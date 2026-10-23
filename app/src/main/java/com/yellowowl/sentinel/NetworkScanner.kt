package com.yellowowl.sentinel

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/** Progress within one phase; [overall] maps it onto the whole scan (discovery 0-60%, services 60-97%, names 97-100%). */
data class ScanProgress(
    val phase: String,
    val done: Int,
    val total: Int,
    val phaseStart: Float = 0f,
    val phaseSpan: Float = 1f
) {
    val fraction: Float get() = if (total == 0) 0f else (done.toFloat() / total).coerceIn(0f, 1f)
    val overall: Float get() = (phaseStart + phaseSpan * fraction).coerceIn(0f, 1f)
}

/**
 * Conservative, local-network-only scanner. It never targets public addresses and limits itself
 * to the phone's own /24 slice of the current private Wi-Fi or Ethernet network.
 */
object NetworkScanner {
    private const val DISCOVERY_TIMEOUT_MS = 300
    private const val PORT_TIMEOUT_MS = 400
    private const val BANNER_TIMEOUT_MS = 1200
    private const val RECON_WINDOW_MS = 2500
    const val PHASE_DISCOVERY = "Finding devices"
    const val PHASE_SERVICES = "Checking services"
    const val PHASE_NAMES = "Looking up names"

    fun detectLocalNetwork(context: Context): LocalNetworkRange? {
        val manager = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val network = manager.activeNetwork ?: return null
        val capabilities = manager.getNetworkCapabilities(network) ?: return null
        val isLan = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        if (!isLan) return null

        val link = manager.getLinkProperties(network) ?: return null
        val address = link.linkAddresses.firstOrNull { linkAddress ->
            val inet = linkAddress.address
            inet is Inet4Address && !inet.isLoopbackAddress && Ipv4.isPrivate(Ipv4.fromBytes(inet.address))
        } ?: return null

        val gateway = link.routes
            .firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }
            ?.gateway?.hostAddress

        return Ipv4.scanRange(Ipv4.fromBytes(address.address.address), address.prefixLength, gateway)
    }

    suspend fun scanLocalNetwork(
        range: LocalNetworkRange,
        context: Context? = null,
        profile: ScanProfile = ScanProfile.NORMAL,
        onProgress: (ScanProgress) -> Unit
    ): NetworkScanResult = withContext(Dispatchers.IO) {
        val hosts = range.hosts()
        check(hosts.isNotEmpty() && hosts.size <= 254) { "This network is outside the supported scan size." }
        val ports = PortCatalog.scanPortsFor(profile)
        val start = System.currentTimeMillis()

        // Phase 1: TCP presence sweep and UDP discovery (SSDP/mDNS/NetBIOS) run together.
        val discovered = AtomicInteger(0)
        val hostLimiter = Semaphore(48)
        onProgress(ScanProgress(PHASE_DISCOVERY, 0, hosts.size, 0f, 0.5f))
        val (tcpAlive, identities) = coroutineScope {
            val reconJob = async {
                if (context != null) ReconNet.discover(context, range, RECON_WINDOW_MS) else emptyMap()
            }
            val aliveJob = async {
                hosts.map { ip ->
                    async {
                        hostLimiter.withPermit {
                            val present = isDevicePresent(ip)
                            onProgress(ScanProgress(PHASE_DISCOVERY, discovered.incrementAndGet(), hosts.size, 0f, 0.5f))
                            if (present) ip else null
                        }
                    }
                }.awaitAll().filterNotNull()
            }
            aliveJob.await() to reconJob.await()
        }
        // Hosts that answered UDP discovery but no TCP port still count as present.
        val alive = (tcpAlive + identities.keys).distinct().sortedBy { Ipv4.parse(it) ?: 0L }

        // Phase 2: scan service ports, grabbing a version banner on any open port that reveals one.
        val checked = AtomicInteger(0)
        val totalChecks = alive.size * ports.size
        val portLimiter = Semaphore(64)
        onProgress(ScanProgress(PHASE_SERVICES, 0, totalChecks, 0.5f, 0.45f))
        val withPorts = coroutineScope {
            alive.map { ip ->
                async {
                    val open = ports.map { port ->
                        async {
                            portLimiter.withPermit {
                                val isOpen = probe(ip, port, PORT_TIMEOUT_MS) == ProbeResult.OPEN
                                onProgress(ScanProgress(PHASE_SERVICES, checked.incrementAndGet(), totalChecks, 0.5f, 0.45f))
                                if (!isOpen) null
                                else {
                                    val fp = runCatching { ReconNet.grabBanner(ip, port, BANNER_TIMEOUT_MS) }.getOrNull()
                                    PortFinding(port, PortCatalog.serviceName(port), fp)
                                }
                            }
                        }
                    }.awaitAll().filterNotNull().sortedBy { it.port }
                    ip to open
                }
            }.awaitAll()
        }

        // Phase 3: fill in a name for hosts discovery didn't already name (reverse DNS, best effort).
        onProgress(ScanProgress(PHASE_NAMES, 0, 1, 0.95f, 0.05f))
        val devices = coroutineScope {
            withPorts.map { (ip, open) ->
                async {
                    val identity = enrich(identities[ip], open)
                    DeviceResult(
                        ipAddress = ip,
                        openPorts = open,
                        hostname = if (identity?.name == null) lookupName(ip, range.gatewayIp) else null,
                        identity = identity,
                        isThisDevice = ip == range.phoneIp,
                        isGateway = ip == range.gatewayIp
                    )
                }
            }.awaitAll()
        }.sortedBy { Ipv4.parse(it.ipAddress) ?: 0L }

        NetworkScanResult(
            cidr = range.cidr,
            scannedHosts = hosts.size,
            devices = devices,
            durationMillis = System.currentTimeMillis() - start
        )
    }

    /** Rescans a single host: ports + banners + reverse-DNS name. Keeps the prior discovery identity. */
    suspend fun scanHost(
        range: LocalNetworkRange,
        ip: String,
        priorIdentity: DeviceIdentity?,
        profile: ScanProfile = ScanProfile.NORMAL
    ): DeviceResult = withContext(Dispatchers.IO) {
        val portLimiter = Semaphore(64)
        val open = coroutineScope {
            PortCatalog.scanPortsFor(profile).map { port ->
                async {
                    portLimiter.withPermit {
                        if (probe(ip, port, PORT_TIMEOUT_MS) != ProbeResult.OPEN) null
                        else {
                            val fp = runCatching { ReconNet.grabBanner(ip, port, BANNER_TIMEOUT_MS) }.getOrNull()
                            PortFinding(port, PortCatalog.serviceName(port), fp)
                        }
                    }
                }
            }.awaitAll().filterNotNull().sortedBy { it.port }
        }
        val identity = enrich(priorIdentity, open)
        DeviceResult(
            ipAddress = ip,
            openPorts = open,
            hostname = if (identity?.name == null) lookupName(ip, range.gatewayIp) else null,
            identity = identity,
            isThisDevice = ip == range.phoneIp,
            isGateway = ip == range.gatewayIp
        )
    }

    /** Fills in a device-type guess from vendor + open ports when discovery didn't already classify it. */
    private fun enrich(base: DeviceIdentity?, openPorts: List<PortFinding>): DeviceIdentity? {
        val kind = DeviceClassifier.classify(base?.vendor, openPorts.map { it.port }, base?.kind)
        return when {
            base != null -> if (base.kind == null && kind != null) base.copy(kind = kind) else base
            kind != null -> DeviceIdentity(kind = kind)
            else -> null
        }
    }

    private suspend fun isDevicePresent(ip: String): Boolean {
        for (port in PortCatalog.discoveryPorts) {
            currentCoroutineContext().ensureActive()
            if (probe(ip, port, DISCOVERY_TIMEOUT_MS) != ProbeResult.NO_RESPONSE) return true
        }
        return false
    }

    private fun probe(host: String, port: Int, timeoutMillis: Int): ProbeResult = try {
        Socket().use { it.connect(InetSocketAddress(host, port), timeoutMillis) }
        ProbeResult.OPEN
    } catch (error: Exception) {
        ProbeClassifier.classifyFailure(error)
    }

    /** Reverse DNS can block for seconds and can't be interrupted, so it runs detached and we stop waiting after a timeout. */
    private val lookupScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private suspend fun lookupName(ip: String, resolver: String?): String? {
        val address = Ipv4.parse(ip) ?: return null
        // First ask the router's DNS directly (dnsmasq usually knows its DHCP clients by name);
        // Android's own resolver typically returns the IP unchanged for LAN hosts.
        if (resolver != null) {
            runCatching { NetToolsNet.reverseDns(ip, resolver) }.getOrNull()
                ?.takeIf { it != ip }
                ?.let { return cleanName(it) }
        }
        // Many devices (Apple, smart TVs, IoT) answer reverse mDNS even when the router serves no PTR.
        runCatching { NetToolsNet.reverseMdns(ip) }.getOrNull()
            ?.takeIf { it != ip }
            ?.let { return cleanName(it) }
        val lookup = lookupScope.async {
            runCatching { InetAddress.getByAddress(Ipv4.toBytes(address)).canonicalHostName }.getOrNull()
        }
        return withTimeoutOrNull(1_500) { lookup.await() }
            ?.takeIf { it != ip && it.isNotBlank() }
            ?.let { cleanName(it) }
    }

    /** Trim trailing dot and a noisy local-domain suffix so "nas.lan." shows as "nas". */
    private fun cleanName(raw: String): String {
        val n = raw.trim().trimEnd('.')
        val suffix = listOf(".lan", ".home", ".local", ".localdomain", ".home.arpa").firstOrNull { n.endsWith(it, ignoreCase = true) }
        return (if (suffix != null) n.dropLast(suffix.length) else n).ifBlank { n }
    }
}
