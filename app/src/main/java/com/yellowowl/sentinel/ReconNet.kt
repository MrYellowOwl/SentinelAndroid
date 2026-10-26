package com.yellowowl.sentinel

import android.content.Context
import android.net.wifi.WifiManager
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

/**
 * The network reads behind the recon engine: TCP banner grabbing and UDP discovery (SSDP, mDNS, NetBIOS).
 * Parsing lives in [Fingerprint] and [Discovery]; this file only moves bytes.
 */
object ReconNet {
    private const val BANNER_CAP = 2048

    /** Connects to [ip]:[port], elicits a banner if the service reveals one, and identifies it. */
    fun grabBanner(ip: String, port: Int, timeoutMillis: Int): ServiceFingerprint? {
        val kind = Fingerprint.probeFor(port)
        if (kind == ProbeKind.NONE) return null
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ip, port), timeoutMillis)
                socket.soTimeout = timeoutMillis
                val request = Fingerprint.requestBytes(kind)
                if (request.isNotEmpty()) {
                    socket.getOutputStream().write(request)
                    socket.getOutputStream().flush()
                }
                val input = socket.getInputStream()
                val buffer = ByteArrayOutputStream()
                val chunk = ByteArray(512)
                try {
                    while (buffer.size() < BANNER_CAP) {
                        val read = input.read(chunk)
                        if (read <= 0) break
                        buffer.write(chunk, 0, read)
                        // One line / packet is enough for single-line banners; multi-line kinds read to cap/timeout.
                        if (kind !in Fingerprint.multiLineKinds && buffer.toByteArray().contains('\n'.code.toByte())) break
                    }
                } catch (_: SocketTimeoutException) {
                    // Return whatever arrived before the timeout.
                }
                Fingerprint.parse(kind, port, buffer.toByteArray())
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Sends SSDP, mDNS and NetBIOS probes and collects what answers, keyed by responder IP.
     * Reveals (and names) devices that expose no scanned TCP port. Never throws.
     */
    suspend fun discover(context: Context, range: LocalNetworkRange, windowMillis: Int): Map<String, DeviceIdentity> =
        withContext(Dispatchers.IO) {
            val hosts = range.hosts()
            val multicastLock = acquireMulticastLock(context)
            try {
                val maps = coroutineScope {
                    listOf(
                        async { runCatching { ssdp(windowMillis) }.getOrDefault(emptyMap()) },
                        async { runCatching { mdns(windowMillis) }.getOrDefault(emptyMap()) },
                        async { runCatching { netbios(hosts, windowMillis) }.getOrDefault(emptyMap()) },
                        async { runCatching { snmp(hosts, range.gatewayIp, windowMillis) }.getOrDefault(emptyMap()) },
                        async { runCatching { arp() }.getOrDefault(emptyMap()) }
                    ).awaitAll()
                }
                mergeByIp(maps)
            } finally {
                runCatching { multicastLock?.release() }
            }
        }

    /** Best-effort kernel ARP cache read: MAC (+ OUI vendor) per IP. Empty on sandboxed Android. */
    private fun arp(): Map<String, DeviceIdentity> {
        val text = runCatching { java.io.File("/proc/net/arp").readText() }.getOrNull() ?: return emptyMap()
        return ArpTable.parse(text).mapValues { (_, mac) -> DeviceIdentity(mac = mac, vendor = Oui.vendor(mac)) }
    }

    private fun mergeByIp(maps: List<Map<String, DeviceIdentity>>): Map<String, DeviceIdentity> {
        val merged = HashMap<String, DeviceIdentity>()
        for (map in maps) for ((ip, identity) in map) {
            merged[ip] = merged[ip]?.merge(identity) ?: identity
        }
        return merged.filterValues { !it.isEmpty }
    }

    private suspend fun ssdp(windowMillis: Int): Map<String, DeviceIdentity> {
        val raw = collectUdp(windowMillis) { socket ->
            val payload = Ssdp.searchRequest()
            socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName(Ssdp.MULTICAST_HOST), Ssdp.PORT))
        }
        val byIp = HashMap<String, DeviceIdentity>()
        val locationByIp = LinkedHashMap<String, String>()   // one description URL per responder
        for ((ip, data) in raw) {
            val text = String(data, Charsets.US_ASCII)
            val base = runCatching { Ssdp.parseResponse(text) }.getOrNull()
            if (base != null && !base.isEmpty) byIp[ip] = byIp[ip]?.merge(base) ?: base
            if (ip !in locationByIp) Ssdp.locationOf(text)?.let { locationByIp[ip] = it }
        }
        // Fetch each device's description document for its friendlyName / manufacturer / modelName —
        // the fields an M-SEARCH reply alone doesn't carry. These are LAN reads of a page the device
        // itself advertises; nothing is sent beyond the local network.
        val described = coroutineScope {
            locationByIp.entries.map { (ip, url) ->
                async { runCatching { fetchDescription(url) }.getOrNull()?.takeIf { !it.isEmpty }?.let { ip to it } }
            }.awaitAll().filterNotNull()
        }
        for ((ip, desc) in described) {
            // The description's friendlyName/model/vendor are richer, so they win over the header guess.
            byIp[ip] = desc.merge(byIp[ip] ?: DeviceIdentity())
        }
        return byIp.filterValues { !it.isEmpty }
    }

    /** Reads a UPnP device-description document (LAN, http) and extracts its identity. */
    private suspend fun fetchDescription(url: String): DeviceIdentity? {
        val res = Http.get(url, timeoutMillis = 1500, maxBytes = 64 * 1024) ?: return null
        if (res.code !in 200..299 || res.body.isBlank()) return null
        return Ssdp.parseDescription(res.body)
    }

    // The service-type meta-query plus the common types most devices advertise, so one window names far more.
    private val mdnsQueries = listOf(
        "_services._dns-sd._udp.local", "_device-info._tcp.local", "_workstation._tcp.local",
        "_http._tcp.local", "_ipp._tcp.local", "_printer._tcp.local", "_pdl-datastream._tcp.local",
        "_airplay._tcp.local", "_googlecast._tcp.local", "_raop._tcp.local", "_spotify-connect._tcp.local",
        "_smb._tcp.local", "_afpovertcp._tcp.local", "_ssh._tcp.local", "_hap._tcp.local", "_companion-link._tcp.local"
    )

    private suspend fun mdns(windowMillis: Int): Map<String, DeviceIdentity> =
        collectUdp(windowMillis) { socket ->
            val dest = InetAddress.getByName(MdnsDns.MULTICAST_HOST)
            mdnsQueries.forEach { name ->
                val payload = MdnsDns.query(name, MdnsDns.TYPE_PTR, qu = true)
                runCatching { socket.send(DatagramPacket(payload, payload.size, dest, MdnsDns.PORT)) }
            }
        } parseWith { data -> MdnsDns.parse(data)?.let { MdnsDns.identify(it) } }

    private suspend fun netbios(hosts: List<String>, windowMillis: Int): Map<String, DeviceIdentity> =
        collectUdp(windowMillis) { socket ->
            val payload = NetBios.nodeStatusRequest()
            for (host in hosts) {
                runCatching { socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName(host), 137)) }
            }
        } parseWith { data -> NetBios.parseNodeStatus(data) }

    /**
     * SNMPv1 recon with the "public" community: reads sysName/sysDescr from any host that answers, and
     * walks the gateway's ARP table (ipNetToMediaPhysAddress) to recover MAC↔IP for the whole LAN —
     * data Android won't let an app read locally. OUI turns each MAC into a vendor. All reads, no writes.
     */
    private fun snmp(hosts: List<String>, gatewayIp: String?, windowMillis: Int): Map<String, DeviceIdentity> {
        val out = HashMap<String, DeviceIdentity>()
        val community = "public"
        try {
            DatagramSocket().use { socket ->
                socket.soTimeout = 500
                val deadline = System.currentTimeMillis() + windowMillis

                // 1) Walk the gateway's ARP table (sequential GETNEXT).
                if (gatewayIp != null) {
                    var current = Snmp.ARP_PHYS_BASE
                    var reqId = 1000
                    var steps = 0
                    while (steps++ < 512 && System.currentTimeMillis() < deadline) {
                        val resp = snmpRequest(socket, gatewayIp, Snmp.buildGetNext(community, current, reqId++)) ?: break
                        val vb = resp.varbinds.firstOrNull() ?: break
                        if (!Snmp.oidStartsWith(vb.oid, Snmp.ARP_PHYS_BASE)) break
                        val ip = Snmp.ipFromArpOid(vb.oid)
                        val mac = vb.asMac()
                        if (ip != null && mac != null) {
                            out[ip] = (out[ip] ?: DeviceIdentity()).merge(DeviceIdentity(mac = mac, vendor = Oui.vendor(mac)))
                        }
                        if (vb.oid == current) break // no progress; avoid a loop
                        current = vb.oid
                    }
                }

                // 2) Fire sysName/sysDescr GETs at every host, then collect replies for the window.
                var reqId = 5000
                for (host in hosts) {
                    runCatching {
                        val addr = InetAddress.getByName(host)
                        socket.send(Snmp.buildGet(community, Snmp.SYS_NAME, reqId++).let { DatagramPacket(it, it.size, addr, Snmp.PORT) })
                        socket.send(Snmp.buildGet(community, Snmp.SYS_DESCR, reqId++).let { DatagramPacket(it, it.size, addr, Snmp.PORT) })
                    }
                }
                val buffer = ByteArray(2048)
                while (System.currentTimeMillis() < deadline) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    try {
                        socket.receive(packet)
                        val ip = packet.address?.hostAddress ?: continue
                        val resp = Snmp.parse(packet.data.copyOf(packet.length)) ?: continue
                        var identity = DeviceIdentity()
                        for (vb in resp.varbinds) {
                            when {
                                vb.oid == Snmp.SYS_NAME -> vb.asString()?.let { identity = identity.copy(name = it) }
                                Snmp.oidStartsWith(vb.oid, "1.3.6.1.2.1.1.1") -> vb.asString()?.let { identity = identity.copy(model = it.take(80)) }
                            }
                        }
                        if (!identity.isEmpty) out[ip] = (out[ip] ?: DeviceIdentity()).merge(identity)
                    } catch (_: SocketTimeoutException) {
                    } catch (_: Exception) {
                        break
                    }
                }
            }
        } catch (_: Exception) {
        }
        return out
    }

    /** Sends one SNMP request and waits (within soTimeout) for a reply from [ip]. */
    private fun snmpRequest(socket: DatagramSocket, ip: String, request: ByteArray): Snmp.Response? = try {
        val addr = InetAddress.getByName(ip)
        socket.send(DatagramPacket(request, request.size, addr, Snmp.PORT))
        val buffer = ByteArray(2048)
        val packet = DatagramPacket(buffer, buffer.size)
        socket.receive(packet)
        Snmp.parse(packet.data.copyOf(packet.length))
    } catch (_: Exception) {
        null
    }

    /** Opens a UDP socket, runs [send], then reads datagrams until the time window closes. */
    private suspend fun collectUdp(windowMillis: Int, send: (DatagramSocket) -> Unit): List<Pair<String, ByteArray>> {
        val packets = ArrayList<Pair<String, ByteArray>>()
        DatagramSocket().use { socket ->
            socket.soTimeout = 400
            send(socket)
            val deadline = System.currentTimeMillis() + windowMillis
            val buffer = ByteArray(4096)
            while (System.currentTimeMillis() < deadline && currentCoroutineContext().isActive) {
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(packet)
                    val ip = packet.address?.hostAddress ?: continue
                    packets.add(ip to packet.data.copyOf(packet.length))
                } catch (_: SocketTimeoutException) {
                    // keep polling until the deadline
                } catch (_: CancellationException) {
                    throw CancellationException()
                } catch (_: Exception) {
                    break
                }
            }
        }
        return packets
    }

    private infix fun List<Pair<String, ByteArray>>.parseWith(
        parse: (ByteArray) -> DeviceIdentity?
    ): Map<String, DeviceIdentity> {
        val out = HashMap<String, DeviceIdentity>()
        for ((ip, data) in this) {
            val identity = runCatching { parse(data) }.getOrNull() ?: continue
            if (identity.isEmpty) continue
            out[ip] = out[ip]?.merge(identity) ?: identity
        }
        return out
    }

    private fun acquireMulticastLock(context: Context): WifiManager.MulticastLock? = try {
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        wifi?.createMulticastLock("sentinel-recon")?.apply {
            setReferenceCounted(false)
            acquire()
        }
    } catch (_: Exception) {
        null
    }
}
