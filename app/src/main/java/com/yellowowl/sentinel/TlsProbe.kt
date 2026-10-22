package com.yellowowl.sentinel

import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Tests which TLS protocol versions a host accepts and the cipher each negotiates, by attempting
 * one handshake per protocol. Certificate validity is checked separately by the audit; here we use
 * a permissive trust manager so a bad cert doesn't mask the protocol/cipher support we're probing.
 */
object TlsProbe {
    private val CANDIDATE_PROTOCOLS = listOf("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1")

    // Inspection-only trust manager: we are enumerating server capabilities, not establishing trust.
    private val permissiveTrust = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    suspend fun probe(host: String, port: Int = 443, timeoutMillis: Int = 4000): TlsInspect.TlsReport =
        withContext(Dispatchers.IO) {
            val supported = LinkedHashMap<String, String>()
            var reachedAny = false
            for (protocol in CANDIDATE_PROTOCOLS) {
                try {
                    val ctx = SSLContext.getInstance("TLS")
                    ctx.init(null, arrayOf(permissiveTrust), null)
                    val socket = ctx.socketFactory.createSocket() as SSLSocket
                    try {
                        socket.connect(InetSocketAddress(host, port), timeoutMillis)
                        socket.soTimeout = timeoutMillis
                        socket.enabledProtocols = arrayOf(protocol)  // may throw if the device lacks this protocol
                        socket.startHandshake()
                        reachedAny = true
                        supported[socket.session.protocol] = socket.session.cipherSuite
                    } finally {
                        runCatching { socket.close() }
                    }
                } catch (_: Exception) {
                    // Protocol not supported by server (or device) — skip it.
                }
            }
            TlsInspect.TlsReport(
                host = host,
                reachable = reachedAny || supported.isNotEmpty(),
                protocols = supported.keys.toList(),
                cipherByProtocol = supported
            )
        }
}
