package com.yellowowl.sentinel

import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetLogicTest {
    @Test
    fun parseAndFormatRoundTrip() {
        val value = Ipv4.parse("192.168.1.42")!!
        assertEquals("192.168.1.42", Ipv4.format(value))
        assertEquals(value, Ipv4.fromBytes(Ipv4.toBytes(value)))
    }

    @Test
    fun parseRejectsInvalidAddresses() {
        listOf("", "1.2.3", "1.2.3.4.5", "256.1.1.1", "a.b.c.d", "1..2.3", "-1.2.3.4").forEach {
            assertNull("expected null for '$it'", Ipv4.parse(it))
        }
    }

    @Test
    fun privateRangesMatchRfc1918Boundaries() {
        assertTrue(Ipv4.isPrivate(Ipv4.parse("10.0.0.1")!!))
        assertTrue(Ipv4.isPrivate(Ipv4.parse("172.16.0.0")!!))
        assertTrue(Ipv4.isPrivate(Ipv4.parse("172.31.255.255")!!))
        assertTrue(Ipv4.isPrivate(Ipv4.parse("192.168.0.10")!!))
        assertFalse(Ipv4.isPrivate(Ipv4.parse("172.15.255.255")!!))
        assertFalse(Ipv4.isPrivate(Ipv4.parse("172.32.0.0")!!))
        assertFalse(Ipv4.isPrivate(Ipv4.parse("8.8.8.8")!!))
        assertFalse(Ipv4.isPrivate(Ipv4.parse("100.64.0.1")!!))
    }

    @Test
    fun reverseDnsNameReversesOctets() {
        assertEquals("5.1.168.192.in-addr.arpa", Ipv4.reverseDnsName("192.168.1.5"))
        assertEquals("1.0.0.10.in-addr.arpa", Ipv4.reverseDnsName("10.0.0.1"))
        assertNull(Ipv4.reverseDnsName("not-an-ip"))
    }

    @Test
    fun slash24RangeCoversAllHosts() {
        val range = Ipv4.scanRange(Ipv4.parse("192.168.1.37")!!, 24, "192.168.1.1")!!
        assertEquals("192.168.1.0/24", range.cidr)
        assertEquals(254, range.hostCount)
        assertEquals("192.168.1.1", range.hosts().first())
        assertEquals("192.168.1.254", range.hosts().last())
        assertEquals("192.168.1.1", range.gatewayIp)
    }

    @Test
    fun largerNetworksAreLimitedToThePhonesSlash24() {
        val range = Ipv4.scanRange(Ipv4.parse("10.5.7.20")!!, 16)!!
        assertEquals("10.5.7.0/24", range.cidr)
        assertEquals(254, range.hosts().size)
    }

    @Test
    fun tinyPublicAndInvalidNetworksAreRejected() {
        assertEquals(2, Ipv4.scanRange(Ipv4.parse("192.168.1.1")!!, 30)!!.hostCount)
        assertNull(Ipv4.scanRange(Ipv4.parse("192.168.1.1")!!, 31))
        assertNull(Ipv4.scanRange(Ipv4.parse("8.8.8.8")!!, 24))
        assertNull(Ipv4.scanRange(Ipv4.parse("192.168.1.1")!!, 0))
    }

    @Test
    fun refusedConnectionMeansDeviceIsPresent() {
        val android = ConnectException("failed to connect to /192.168.1.5 (port 22) after 300ms: isConnected failed: ECONNREFUSED (Connection refused)")
        assertEquals(ProbeResult.REFUSED, ProbeClassifier.classifyFailure(android))
        assertEquals(ProbeResult.REFUSED, ProbeClassifier.classifyFailure(ConnectException("Connection refused")))
    }

    @Test
    fun timeoutsAndUnreachableMeanNoDevice() {
        assertEquals(ProbeResult.NO_RESPONSE, ProbeClassifier.classifyFailure(SocketTimeoutException("timeout")))
        assertEquals(ProbeResult.NO_RESPONSE, ProbeClassifier.classifyFailure(ConnectException("EHOSTUNREACH (No route to host)")))
        assertEquals(ProbeResult.NO_RESPONSE, ProbeClassifier.classifyFailure(NoRouteToHostException("No route to host")))
    }

    @Test
    fun onlyRiskyPortsBecomeFindings() {
        val result = NetworkScanResult(
            cidr = "192.168.1.0/24",
            scannedHosts = 254,
            devices = listOf(
                DeviceResult(
                    ipAddress = "192.168.1.20",
                    hostname = "nas.lan",
                    openPorts = listOf(23, 80, 443, 445).map { PortFinding(it, PortCatalog.serviceName(it)) }
                ),
                DeviceResult("192.168.1.30", openPorts = listOf(PortFinding(80, "HTTP")))
            ),
            durationMillis = 1000
        )
        val findings = NetworkFindings.from(result)
        assertEquals(2, findings.size)
        assertEquals(Severity.HIGH, findings.first { it.target == "192.168.1.20:23" }.severity)
        assertEquals(Severity.MEDIUM, findings.first { it.target == "192.168.1.20:445" }.severity)
        assertTrue(findings.all { it.scope == "192.168.1.0/24" && it.source == FindingSource.NETWORK })
        assertTrue(findings.first().title.contains("nas.lan"))
    }

    @Test
    fun everyScanPortHasAName() {
        PortCatalog.scanPorts.forEach { assertTrue("port $it", PortCatalog.serviceName(it) != "Unknown") }
    }
}
