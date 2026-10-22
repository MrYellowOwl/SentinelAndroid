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

        if (shodanKey.isNotBlank() && isIp) {
            val r = Http.get("https://api.shodan.io/shodan/host/$host?key=$shodanKey", timeoutMillis = 12000)
            if (r != null && r.code == 200) ExternalIntel.parseShodan(r.body)?.let { out.addAll(ExternalIntel.shodanFindings("", target, it)) }
            else if (r != null && r.code == 404) out.add(Finding(title = "Shodan: no data for $host", severity = Severity.INFO, source = FindingSource.NETWORK, scope = "", target = target, details = "Shodan has no record of this IP (not seen by its scanners).", remediation = "No action needed."))
        }
        if (vtKey.isNotBlank()) {
            val path = if (isIp) "ip_addresses/$host" else "domains/$host"
            val r = Http.get("https://www.virustotal.com/api/v3/$path", timeoutMillis = 12000, extraHeaders = mapOf("x-apikey" to vtKey))
            if (r != null && r.code == 200) ExternalIntel.parseVirusTotal(r.body)?.let { out.add(ExternalIntel.vtFinding("", target, it)) }
        }

        if (out.isEmpty()) Result.failure(IllegalStateException("No external data returned (check the keys, or the target isn't indexed)."))
        else Result.success(out)
    }

    // ---- SMB2 negotiate / signing posture (no auth, no share access) ----
    suspend fun smbInfo(host: String, port: Int = 445): Result<List<Finding>> = withContext(Dispatchers.IO) {
        if (!HOST_RE.matches(host)) return@withContext Result.failure(IllegalArgumentException("Enter a valid host or IP."))
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 5000)
                socket.soTimeout = 5000
                val req = SmbScan.negotiateRequest()
                socket.getOutputStream().write(req); socket.getOutputStream().flush()
                val input = socket.getInputStream()
                val nb = readN(input, 4) ?: return@withContext Result.failure(IllegalStateException("No SMB2 response."))
                val len = ((nb[1].toInt() and 0xFF) shl 16) or ((nb[2].toInt() and 0xFF) shl 8) or (nb[3].toInt() and 0xFF)
                if (len !in 1..131072) return@withContext Result.failure(IllegalStateException("Unexpected SMB response."))
                val body = readN(input, len) ?: return@withContext Result.failure(IllegalStateException("Truncated SMB response."))
                val info = SmbScan.parseNegotiateResponse(body)
                    ?: return@withContext Result.failure(IllegalStateException("Not an SMB2 server (or SMBv1-only)."))
                Result.success(SmbScan.findings("", "$host:$port", info))
            }
        } catch (e: Exception) {
            Result.failure(IllegalStateException("SMB check failed: ${e.message ?: e.javaClass.simpleName}"))
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
            val spf = apexTxt.firstOrNull { it.trim().startsWith("v=spf1", ignoreCase = true) }

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

            val records = DnsPosture.DnsRecords(host, spf, dmarc, dkimFound, caa, dnssec, hasMx)
            Result.success(DnsPosture.findings(host, records))
        } catch (e: Exception) {
            Result.failure(IllegalStateException("DNS posture check failed: ${e.message ?: e.javaClass.simpleName}"))
        }
    }

    // ---- CT-log subdomain discovery (crt.sh) ----
    suspend fun subdomains(domain: String): Result<List<String>> = withContext(Dispatchers.IO) {
        val clean = domain.trim().lowercase().removePrefix("http://").removePrefix("https://").substringBefore('/')
        if (!HOST_RE.matches(clean) || !clean.contains('.')) return@withContext Result.failure(IllegalArgumentException("Enter a domain name."))
        val resp = Http.get(CertSearch.crtShUrl(clean), timeoutMillis = 15000, maxBytes = 4 * 1024 * 1024)
            ?: return@withContext Result.failure(IllegalStateException("Couldn't reach crt.sh. It can be slow — try again."))
        if (resp.code !in 200..299) return@withContext Result.failure(IllegalStateException("crt.sh returned HTTP ${resp.code}."))
        val subs = CertSearch.parseSubdomains(resp.body, clean)
        if (subs.isEmpty()) Result.failure(IllegalStateException("No subdomains found in CT logs for $clean."))
        else Result.success(subs)
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
