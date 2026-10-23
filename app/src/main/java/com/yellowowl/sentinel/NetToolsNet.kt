package com.yellowowl.sentinel

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

/** Network I/O for the Tools tab. Each function returns a user-facing result or a friendly error string. */
object NetToolsNet {
    private val HOST_RE = Regex("""^[A-Za-z0-9._:-]{1,253}$""")

    // ---- ping (via the system binary; raw ICMP needs root) ----
    suspend fun ping(host: String, count: Int = 4): Result<PingResult> = withContext(Dispatchers.IO) {
        if (!HOST_RE.matches(host)) return@withContext Result.failure(IllegalArgumentException("Enter a valid host or IP."))
        try {
            val process = ProcessBuilder(listOf("/system/bin/ping", "-c", count.toString(), "-W", "2", host))
                .redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText()
            if (!process.waitFor(15, TimeUnit.SECONDS)) { process.destroy(); return@withContext Result.failure(IllegalStateException("Ping timed out.")) }
            PingParse.parse(output)?.let { Result.success(it) }
                ?: Result.failure(IllegalStateException(if (output.isBlank()) "No response." else output.lines().firstOrNull { it.isNotBlank() } ?: "Ping failed."))
        } catch (e: Exception) {
            Result.failure(IllegalStateException("Couldn't run ping: ${e.message ?: e.javaClass.simpleName}"))
        }
    }

    // ---- DNS lookup against a resolver ----
    data class DnsAnswer(val type: String, val value: String)

    /** The record types queried when the user picks "ALL". */
    val dnsAllTypes = listOf("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA")

    suspend fun dnsLookup(name: String, recordType: String, resolver: String = "8.8.8.8"): Result<List<DnsAnswer>> =
        withContext(Dispatchers.IO) {
            val clean = name.trim().trimEnd('.')
            if (clean.isBlank()) return@withContext Result.failure(IllegalArgumentException("Enter a domain."))
            if (recordType.equals("ALL", ignoreCase = true)) return@withContext dnsLookupAll(clean, resolver)
            try {
                val answers = queryOne(clean, recordType, resolver)
                if (answers.isEmpty()) Result.failure(IllegalStateException("No ${recordType.uppercase()} records found."))
                else Result.success(answers)
            } catch (e: Exception) {
                Result.failure(IllegalStateException("DNS lookup failed: ${e.message ?: e.javaClass.simpleName}"))
            }
        }

    private suspend fun dnsLookupAll(name: String, resolver: String): Result<List<DnsAnswer>> {
        val all = ArrayList<DnsAnswer>()
        for (type in dnsAllTypes) {
            runCatching { queryOne(name, type, resolver) }.getOrNull()?.let { all.addAll(it) }
        }
        val deduped = all.distinctBy { "${it.type}|${it.value}" }
        return if (deduped.isEmpty()) Result.failure(IllegalStateException("No records found for $name."))
        else Result.success(deduped)
    }

    private fun queryOne(name: String, recordType: String, resolver: String): List<DnsAnswer> =
        DatagramSocket().use { socket ->
            socket.soTimeout = 4000
            val query = MdnsDns.query(name, MdnsDns.typeFor(recordType), recursionDesired = true)
            socket.send(DatagramPacket(query, query.size, InetAddress.getByName(resolver), 53))
            val buffer = ByteArray(4096)
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            val msg = MdnsDns.parse(packet.data.copyOf(packet.length)) ?: return emptyList()
            msg.answers.map { rec ->
                DnsAnswer(MdnsDns.typeName(rec.type), rec.ip ?: rec.target ?: rec.txt.joinToString(" ").ifBlank { "(no data)" })
            }
        }

    // ---- whois (TCP 43, one referral hop) ----
    suspend fun whois(domain: String): Result<String> = withContext(Dispatchers.IO) {
        val clean = domain.trim().lowercase()
        if (!HOST_RE.matches(clean) || !clean.contains('.')) return@withContext Result.failure(IllegalArgumentException("Enter a domain name."))
        try {
            var server = WhoisServers.forDomain(clean)
            var response = queryWhois(server, clean)
            val referral = Regex("""(?:Registrar WHOIS Server|whois):\s*(\S+)""", RegexOption.IGNORE_CASE)
                .find(response)?.groupValues?.get(1)?.trim()?.removePrefix("https://")?.removePrefix("http://")
            if (referral != null && referral != server && HOST_RE.matches(referral)) {
                runCatching { queryWhois(referral, clean) }.getOrNull()?.let { response = it; server = referral }
            }
            Result.success("[$server]\n\n$response")
        } catch (e: Exception) {
            Result.failure(IllegalStateException("WHOIS failed: ${e.message ?: e.javaClass.simpleName}"))
        }
    }

    private fun queryWhois(server: String, domain: String): String =
        Socket().use { socket ->
            socket.connect(InetSocketAddress(server, 43), 6000)
            socket.soTimeout = 6000
            socket.getOutputStream().write("$domain\r\n".toByteArray())
            socket.getOutputStream().flush()
            socket.getInputStream().bufferedReader().readText().take(8000)
        }

    // ---- Wake-on-LAN ----
    suspend fun wakeOnLan(mac: String, broadcastIp: String = "255.255.255.255"): Result<Unit> = withContext(Dispatchers.IO) {
        val packet = Wol.magicPacket(mac) ?: return@withContext Result.failure(IllegalArgumentException("Enter a valid MAC address."))
        try {
            DatagramSocket().use { socket ->
                socket.broadcast = true
                val addr = InetAddress.getByName(broadcastIp)
                for (port in intArrayOf(9, 7)) socket.send(DatagramPacket(packet, packet.size, addr, port))
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(IllegalStateException("Couldn't send the magic packet: ${e.message ?: e.javaClass.simpleName}"))
        }
    }

    // ---- custom port scan of one host ----
    data class OpenPort(val port: Int, val service: String)

    suspend fun scanPorts(host: String, ports: List<Int>, timeoutMillis: Int = 500): Result<List<OpenPort>> =
        withContext(Dispatchers.IO) {
            if (!HOST_RE.matches(host)) return@withContext Result.failure(IllegalArgumentException("Enter a valid host or IP."))
            if (ports.isEmpty()) return@withContext Result.failure(IllegalArgumentException("No ports to scan."))
            try {
                val limiter = Semaphore(64)
                val open = coroutineScope {
                    ports.map { port ->
                        async {
                            limiter.withPermit {
                                val ok = try {
                                    Socket().use { it.connect(InetSocketAddress(host, port), timeoutMillis) }; true
                                } catch (_: Exception) { false }
                                if (ok) OpenPort(port, PortCatalog.serviceName(port)) else null
                            }
                        }
                    }.awaitAll().filterNotNull().sortedBy { it.port }
                }
                Result.success(open)
            } catch (e: Exception) {
                Result.failure(IllegalStateException("Scan failed: ${e.message ?: e.javaClass.simpleName}"))
            }
        }

    // ---- External intel (bring-your-own-key: Shodan + VirusTotal) ----
    suspend fun externalIntel(target: String, shodanKey: String, vtKey: String): Result<List<Finding>> = withContext(Dispatchers.IO) {
        val host = target.trim().lowercase().removePrefix("http://").removePrefix("https://").substringBefore('/').substringBefore(':')
        if (host.isBlank()) return@withContext Result.failure(IllegalArgumentException("Enter a host, IP or domain."))
        if (shodanKey.isBlank() && vtKey.isBlank())
            return@withContext Result.failure(IllegalStateException("Add a Shodan and/or VirusTotal API key in Settings first."))
        val isIp = Ipv4.parse(host) != null
        val out = ArrayList<Finding>()
        val problems = ArrayList<String>()

        if (shodanKey.isNotBlank()) {
            // Shodan is keyed by IP. Resolve a domain to its A record first so it works on hostnames too.
            val ip = if (isIp) host else runCatching { queryOne(host, "A", "8.8.8.8") }.getOrNull()
                ?.firstOrNull { it.type.equals("A", ignoreCase = true) }?.value
            if (ip == null) {
                problems.add("Shodan: couldn't resolve $host to an IP.")
            } else {
                val r = Http.get("https://api.shodan.io/shodan/host/$ip?key=$shodanKey", timeoutMillis = 12000)
                when {
                    r == null -> problems.add("Shodan: no response (timed out or unreachable).")
                    r.code == 200 -> ExternalIntel.parseShodan(r.body)?.let { out.addAll(ExternalIntel.shodanFindings("", target, it)) }
                    r.code == 404 -> out.add(Finding(title = "Shodan: no data for $ip", severity = Severity.INFO, source = FindingSource.NETWORK, scope = "", target = target, details = "Shodan has no record of this IP (not seen by its scanners).", remediation = "No action needed."))
                    r.code == 401 -> problems.add("Shodan: API key rejected (401).")
                    r.code == 429 -> problems.add("Shodan: rate-limited (429) — wait and retry.")
                    else -> problems.add("Shodan: HTTP ${r.code}.")
                }
            }
        }
        if (vtKey.isNotBlank()) {
            val path = if (isIp) "ip_addresses/$host" else "domains/$host"
            val r = Http.get("https://www.virustotal.com/api/v3/$path", timeoutMillis = 12000, extraHeaders = mapOf("x-apikey" to vtKey))
            when {
                r == null -> problems.add("VirusTotal: no response (timed out or unreachable).")
                r.code == 200 -> ExternalIntel.parseVirusTotal(r.body)?.let { out.add(ExternalIntel.vtFinding("", target, it)) }
                r.code == 401 -> problems.add("VirusTotal: API key rejected (401).")
                r.code == 404 -> problems.add("VirusTotal: $host not indexed (404).")
                r.code == 429 -> problems.add("VirusTotal: rate-limited (429) — wait and retry.")
                else -> problems.add("VirusTotal: HTTP ${r.code}.")
            }
        }

        if (out.isNotEmpty()) Result.success(out)
        else if (problems.isNotEmpty()) Result.failure(IllegalStateException(problems.joinToString("\n")))
        else Result.failure(IllegalStateException("No external data returned (the target isn't indexed)."))
    }

    // ---- SMB2 negotiate / signing posture (no auth, no share access) ----
    suspend fun smbInfo(host: String, port: Int = 445): Result<List<Finding>> = withContext(Dispatchers.IO) {
        if (!HOST_RE.matches(host)) return@withContext Result.failure(IllegalArgumentException("Enter a valid host or IP."))
        val target = "$host:$port"
        val out = ArrayList<Finding>()
        var reached = false

        // SMB2/3 negotiate → dialect + signing posture.
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 5000)
                socket.soTimeout = 5000
                val req = SmbScan.negotiateRequest()
                socket.getOutputStream().write(req); socket.getOutputStream().flush()
                val input = socket.getInputStream()
                val nb = readN(input, 4)
                if (nb != null) {
                    reached = true
                    val len = ((nb[1].toInt() and 0xFF) shl 16) or ((nb[2].toInt() and 0xFF) shl 8) or (nb[3].toInt() and 0xFF)
                    if (len in 1..131072) {
                        val body = readN(input, len)
                        if (body != null) SmbScan.parseNegotiateResponse(body)?.let { out.addAll(SmbScan.findings("", target, it)) }
                    }
                }
            }
        } catch (_: Exception) { /* fall through to SMB1 probe */ }

        // SMB1 negotiate → positively detect SMBv1 (a finding in its own right).
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 5000)
                socket.soTimeout = 5000
                val req = SmbScan.smb1NegotiateRequest()
                socket.getOutputStream().write(req); socket.getOutputStream().flush()
                val input = socket.getInputStream()
                val nb = readN(input, 4)
                if (nb != null) {
                    reached = true
                    val len = ((nb[1].toInt() and 0xFF) shl 16) or ((nb[2].toInt() and 0xFF) shl 8) or (nb[3].toInt() and 0xFF)
                    val body = if (len in 1..131072) readN(input, len) else null
                    if (body != null && SmbScan.isSmb1Response(body)) out.add(SmbScan.smbv1Finding("", target))
                }
            }
        } catch (_: Exception) { /* SMB1 likely disabled — good */ }

        when {
            out.isNotEmpty() -> Result.success(out)
            reached -> Result.failure(IllegalStateException("SMB is open but didn't return a readable negotiate response."))
            else -> Result.failure(IllegalStateException("No SMB service responded on $target."))
        }
    }

    // ---- SNMP system info (default community) ----
    private val SNMP_OIDS = linkedMapOf(
        "1.3.6.1.2.1.1.1.0" to "System", "1.3.6.1.2.1.1.5.0" to "Name",
        "1.3.6.1.2.1.1.6.0" to "Location", "1.3.6.1.2.1.1.4.0" to "Contact"
    )

    suspend fun snmpInfo(host: String, community: String = "public"): Result<List<Finding>> = withContext(Dispatchers.IO) {
        if (!HOST_RE.matches(host)) return@withContext Result.failure(IllegalArgumentException("Enter a valid host or IP."))
        val values = LinkedHashMap<String, String>()
        try {
            DatagramSocket().use { socket ->
                socket.soTimeout = 2500
                var reqId = 1
                for ((oid, label) in SNMP_OIDS) {
                    try {
                        val query = Snmp.buildGet(community, oid, reqId++)
                        socket.send(DatagramPacket(query, query.size, InetAddress.getByName(host), 161))
                        val buf = ByteArray(2048)
                        val pkt = DatagramPacket(buf, buf.size)
                        socket.receive(pkt)
                        val resp = Snmp.parse(pkt.data.copyOf(pkt.length)) ?: continue
                        val vb = resp.varbinds.firstOrNull { it.value.isNotEmpty() } ?: continue
                        val text = String(vb.value, Charsets.UTF_8).trim().filter { it >= ' ' }
                        if (text.isNotBlank()) values[label] = text.take(160)
                    } catch (_: Exception) { /* this OID didn't answer; try the next */ }
                }
            }
        } catch (e: Exception) {
            return@withContext Result.failure(IllegalStateException("SNMP query failed: ${e.message ?: e.javaClass.simpleName}"))
        }
        if (values.isEmpty()) return@withContext Result.failure(IllegalStateException("No SNMP response (no SNMP, or a non-default community is set)."))
        val detail = values.entries.joinToString(" · ") { "${it.key}: ${it.value}" }
        Result.success(listOf(
            Finding(
                title = "SNMP readable with community \"$community\"",
                severity = Severity.MEDIUM, source = FindingSource.NETWORK, scope = "", target = "$host:161",
                details = "The device answered SNMP GETs using the default community \"$community\", disclosing: $detail.",
                remediation = "Change the SNMP community from the default, restrict SNMP to management hosts, or disable SNMP/upgrade to SNMPv3 with auth+priv."
            )
        ))
    }

    // ---- SSH algorithm audit (banner + KEXINIT, no auth) ----
    suspend fun sshAudit(host: String, port: Int = 22): Result<List<Finding>> = withContext(Dispatchers.IO) {
        if (!HOST_RE.matches(host)) return@withContext Result.failure(IllegalArgumentException("Enter a valid host or IP."))
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 5000)
                socket.soTimeout = 6000
                val input = socket.getInputStream()
                val output = socket.getOutputStream()

                // Read identification lines until the server's "SSH-..." banner.
                var banner: String? = null
                repeat(4) {
                    val line = readLine(input) ?: return@repeat
                    if (line.startsWith("SSH-")) { banner = line.trim(); return@repeat }
                }
                if (banner == null) return@withContext Result.failure(IllegalStateException("Not an SSH service (no identification banner)."))
                output.write("SSH-2.0-SentinelSecurity\r\n".toByteArray()); output.flush()

                val lenBuf = readN(input, 4) ?: return@withContext Result.success(SshAudit.findings("", "$host:$port", banner, null))
                val packetLen = ((lenBuf[0].toInt() and 0xFF) shl 24) or ((lenBuf[1].toInt() and 0xFF) shl 16) or
                    ((lenBuf[2].toInt() and 0xFF) shl 8) or (lenBuf[3].toInt() and 0xFF)
                if (packetLen !in 1..65536) return@withContext Result.success(SshAudit.findings("", "$host:$port", banner, null))
                val packet = readN(input, packetLen) ?: return@withContext Result.success(SshAudit.findings("", "$host:$port", banner, null))
                val paddingLen = packet[0].toInt() and 0xFF
                val payload = packet.copyOfRange(1, (packetLen - paddingLen).coerceIn(1, packet.size))
                val kex = SshAudit.parseKexInit(payload)
                Result.success(SshAudit.findings("", "$host:$port", banner, kex))
            }
        } catch (e: Exception) {
            Result.failure(IllegalStateException("SSH audit failed: ${e.message ?: e.javaClass.simpleName}"))
        }
    }

    private fun readLine(input: java.io.InputStream): String? {
        val sb = StringBuilder()
        while (sb.length < 512) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) return sb.toString()
            if (b != '\r'.code) sb.append(b.toChar())
        }
        return sb.toString()
    }

    private fun readN(input: java.io.InputStream, n: Int): ByteArray? {
        val buf = ByteArray(n)
        var read = 0
        while (read < n) {
            val r = input.read(buf, read, n - read)
            if (r < 0) return null
            read += r
        }
        return buf
    }

    // ---- DNS/email security posture ----
    private fun dnsQueryRaw(name: String, type: Int, resolver: String): MdnsDns.Message? =
        DatagramSocket().use { socket ->
            socket.soTimeout = 4000
            val query = MdnsDns.query(name, type, recursionDesired = true)
            socket.send(DatagramPacket(query, query.size, InetAddress.getByName(resolver), 53))
            val buffer = ByteArray(4096)
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            MdnsDns.parse(packet.data.copyOf(packet.length))
        }

    suspend fun dnsPosture(domain: String, resolver: String = "8.8.8.8"): Result<List<Finding>> = withContext(Dispatchers.IO) {
        val host = domain.trim().lowercase().removePrefix("http://").removePrefix("https://").substringBefore('/').trimEnd('.')
        if (!HOST_RE.matches(host) || !host.contains('.')) return@withContext Result.failure(IllegalArgumentException("Enter a domain name."))
        try {
            val txtType = MdnsDns.typeFor("TXT")
            val apexTxt = runCatching { dnsQueryRaw(host, txtType, resolver) }.getOrNull()?.answers?.flatMap { it.txt }.orEmpty()
            val allSpf = apexTxt.filter { it.trim().startsWith("v=spf1", ignoreCase = true) }
            val spf = allSpf.firstOrNull()

            val dmarcTxt = runCatching { dnsQueryRaw("_dmarc.$host", txtType, resolver) }.getOrNull()?.answers?.flatMap { it.txt }.orEmpty()
            val dmarc = dmarcTxt.firstOrNull { it.trim().startsWith("v=DMARC1", ignoreCase = true) }

            var dkimFound = false
            for (sel in DnsPosture.dkimSelectors) {
                val txt = runCatching { dnsQueryRaw("$sel._domainkey.$host", txtType, resolver) }.getOrNull()?.answers?.flatMap { it.txt }.orEmpty()
                if (txt.any { it.contains("v=DKIM1", ignoreCase = true) || it.contains("p=", ignoreCase = true) }) { dkimFound = true; break }
            }

            val caa = runCatching { dnsQueryRaw(host, 257, resolver) }.getOrNull()?.answers?.any { it.type == 257 } ?: false
            val dnssec = runCatching { dnsQueryRaw(host, 48, resolver) }.getOrNull()?.answers?.any { it.type == 48 } ?: false
            val hasMx = runCatching { dnsQueryRaw(host, MdnsDns.typeFor("MX"), resolver) }.getOrNull()?.answers?.any { it.target != null } ?: false

            val records = DnsPosture.DnsRecords(host, spf, dmarc, dkimFound, caa, dnssec, hasMx, allSpf)
            Result.success(DnsPosture.findings(host, records))
        } catch (e: Exception) {
            Result.failure(IllegalStateException("DNS posture check failed: ${e.message ?: e.javaClass.simpleName}"))
        }
    }

    // ---- CT-log subdomain discovery (crt.sh, with a Certspotter fallback) ----
    suspend fun subdomains(domain: String): Result<List<String>> = withContext(Dispatchers.IO) {
        val clean = domain.trim().lowercase().removePrefix("http://").removePrefix("https://").substringBefore('/')
        if (!HOST_RE.matches(clean) || !clean.contains('.')) return@withContext Result.failure(IllegalArgumentException("Enter a domain name."))

        // Query both CT sources concurrently and union them — each indexes certificates the other misses.
        // crt.sh is slow (30s+) and returns large bodies, so it gets a long read timeout and a high cap;
        // parsing salvages a truncated/non-JSON body rather than failing.
        val (crt, cs) = coroutineScope {
            val crtD = async {
                Http.get(
                    CertSearch.crtShUrl(clean),
                    timeoutMillis = 15_000, readTimeoutMillis = 45_000,
                    maxBytes = 16 * 1024 * 1024,
                    extraHeaders = mapOf("Accept" to "application/json")
                )
            }
            val csD = async {
                Http.get(
                    CertSearch.certSpotterUrl(clean),
                    timeoutMillis = 15_000, readTimeoutMillis = 30_000,
                    maxBytes = 8 * 1024 * 1024,
                    extraHeaders = mapOf("Accept" to "application/json")
                )
            }
            crtD.await() to csD.await()
        }
        val crtSubs = if (crt != null && crt.code in 200..299) CertSearch.parseSubdomains(crt.body, clean) else emptyList()
        val csSubs = if (cs != null && cs.code in 200..299) CertSearch.parseCertSpotter(cs.body, clean) else emptyList()
        val merged = CertSearch.sortHosts(crtSubs + csSubs)
        if (merged.isNotEmpty()) return@withContext Result.success(resolveAndDescribe(merged))

        // Nothing usable — explain why in a way that points at the real cause.
        val reached = (crt != null && crt.code in 200..299) || (cs != null && cs.code in 200..299)
        val msg = when {
            reached -> "No subdomains found in CT logs for $clean."
            crt?.code == 429 || cs?.code == 429 -> "CT-log lookup was rate-limited. Wait a minute and try again."
            crt != null -> "crt.sh returned HTTP ${crt.code} and the fallback didn't answer. Try again shortly."
            else -> "Couldn't reach the CT logs — crt.sh can be slow or briefly down. Try again in a moment."
        }
        Result.failure(IllegalStateException(msg))
    }

    private const val RESOLVE_CAP = 150   // bound the DNS fan-out for domains with huge CT footprints

    /** Resolves each discovered subdomain (A records) concurrently and formats a line per host. */
    private suspend fun resolveAndDescribe(names: List<String>): List<String> = coroutineScope {
        val toResolve = names.take(RESOLVE_CAP)
        val gate = Semaphore(24)
        val resolved = toResolve.map { name ->
            async {
                gate.withPermit {
                    val ips = runCatching { queryOne(name, "A", "8.8.8.8") }.getOrNull()
                        ?.filter { it.type.equals("A", ignoreCase = true) }?.map { it.value }.orEmpty()
                    CertSearch.describeResolved(name, ips)
                }
            }
        }.awaitAll()
        // Surface the security-relevant hosts first: internal-resolving ones, then the rest in order.
        // Names beyond the cap are listed unresolved so nothing from the CT logs is dropped.
        val (internal, rest) = resolved.partition { it.contains("[INTERNAL]") }
        internal + rest + names.drop(RESOLVE_CAP)
    }

    // ---- public-IP exposure ----
    data class ExposureResult(
        val info: IpExposure.PublicIpInfo,
        val reachable: List<Int>,     // ports that answered from this device (best-effort; see note)
        val probedPorts: List<Int>
    )

    /** Public-IP info service (read-only; returns IP, ISP, ASN, city/country). */
    private const val IP_INFO_URL = "http://ip-api.com/json/?fields=status,message,query,isp,org,as,city,country"

    /** Looks up this connection's public IP and (best-effort) which common inbound ports answer. */
    suspend fun publicExposure(probe: Boolean = true): Result<ExposureResult> = withContext(Dispatchers.IO) {
        val resp = Http.get(IP_INFO_URL, timeoutMillis = 8000, followRedirects = true)
            ?: return@withContext Result.failure(IllegalStateException("Couldn't reach the public-IP service. Check your connection."))
        val info = IpExposure.parseInfo(resp.body)
            ?: return@withContext Result.failure(IllegalStateException("Couldn't determine your public IP."))

        val ports = IpExposure.commonInboundPorts
        val reachable = if (probe && info.kind == IpExposure.IpKind.PUBLIC) {
            val limiter = Semaphore(8)
            coroutineScope {
                ports.map { port ->
                    async {
                        limiter.withPermit {
                            val ok = try {
                                Socket().use { it.connect(InetSocketAddress(info.ip, port), 1500) }; true
                            } catch (_: Exception) { false }
                            if (ok) port else null
                        }
                    }
                }.awaitAll().filterNotNull().sorted()
            }
        } else emptyList()

        Result.success(ExposureResult(info, reachable, if (probe && info.kind == IpExposure.IpKind.PUBLIC) ports else emptyList()))
    }

    /** Parses "22,80,443" or "1-1024" or a mix into a bounded, de-duplicated port list. */
    fun parsePortSpec(spec: String, max: Int = 2048): List<Int> {
        val result = LinkedHashSet<Int>()
        for (part in spec.split(',', ' ').map { it.trim() }.filter { it.isNotEmpty() }) {
            if ('-' in part) {
                val a = part.substringBefore('-').toIntOrNull() ?: continue
                val b = part.substringAfter('-').toIntOrNull() ?: continue
                for (p in a..b) if (p in 1..65535) { result.add(p); if (result.size >= max) return result.toList() }
            } else part.toIntOrNull()?.takeIf { it in 1..65535 }?.let { result.add(it) }
            if (result.size >= max) break
        }
        return result.toList()
    }
}
