package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MonitorSpeedWifiTest {
    // ---- scan diff ----
    private fun snap(ip: String, mac: String?, vararg ports: Int) = DeviceSnapshot(ip, mac, null, ports.toList())

    @Test
    fun diffDetectsNewGoneAndPortChanges() {
        val old = listOf(snap("192.168.1.2", "aa:aa:aa:aa:aa:aa", 22, 80), snap("192.168.1.3", "bb:bb:bb:bb:bb:bb", 443))
        val new = listOf(
            snap("192.168.1.2", "aa:aa:aa:aa:aa:aa", 22, 80, 445), // opened 445
            snap("192.168.1.9", "cc:cc:cc:cc:cc:cc", 8080)         // brand new
        )
        val d = ScanDiffer.diff(old, new)
        assertEquals(listOf("cc:cc:cc:cc:cc:cc"), d.newDevices.map { it.key })
        assertEquals(listOf("bb:bb:bb:bb:bb:bb"), d.goneDevices.map { it.key })
        assertEquals(1, d.portChanges.size)
        assertEquals(listOf(445), d.portChanges[0].opened)
        assertFalse(d.isEmpty)
        assertEquals(3, d.changeCount)
    }

    @Test
    fun diffMatchesByMacAcrossIpChange() {
        // same device, new DHCP lease (IP changed) but same MAC -> not "new"
        val old = listOf(snap("192.168.1.50", "de:ad:be:ef:00:01", 22))
        val new = listOf(snap("192.168.1.77", "de:ad:be:ef:00:01", 22))
        assertTrue(ScanDiffer.diff(old, new).isEmpty)
    }

    @Test
    fun diffFallsBackToIpWhenNoMac() {
        val old = listOf(snap("10.0.0.5", null, 80))
        val new = listOf(snap("10.0.0.5", null, 80, 443))
        val d = ScanDiffer.diff(old, new)
        assertEquals(1, d.portChanges.size)
        assertEquals(listOf(443), d.portChanges[0].opened)
    }

    @Test
    fun summaryLinesReadable() {
        val d = ScanDiff(
            newDevices = listOf(snap("192.168.1.9", "cc:cc:cc:cc:cc:cc", 8080)),
            goneDevices = emptyList(),
            portChanges = listOf(PortChange(snap("192.168.1.2", "aa:aa:aa:aa:aa:aa", 445), listOf(445), emptyList()))
        )
        val lines = ScanDiffer.summaryLines(d)
        assertTrue(lines.any { it.startsWith("New device:") })
        assertTrue(lines.any { it.contains("new open port(s) 445") })
    }

    // ---- speed calc ----
    @Test
    fun mbpsCalc() {
        assertEquals(80.0, SpeedCalc.mbps(10_000_000, 1000), 0.001) // 10 MB in 1s = 80 Mbps
        assertEquals(0.0, SpeedCalc.mbps(1000, 0), 0.001)
        assertEquals("150 Mbps", SpeedCalc.format(150.0)) // >=100 drops decimals
        assertEquals("80.0 Mbps", SpeedCalc.format(80.0)) // 10-99 keeps one decimal
        assertEquals("1.25 Mbps", SpeedCalc.format(1.25)) // <10 keeps two
    }

    // ---- wifi helpers ----
    @Test
    fun wifiChannelAndBand() {
        assertEquals(1, WifiInfoUtil.channel(2412))
        assertEquals(6, WifiInfoUtil.channel(2437))
        assertEquals(11, WifiInfoUtil.channel(2462))
        assertEquals(14, WifiInfoUtil.channel(2484))
        assertEquals(36, WifiInfoUtil.channel(5180))
        assertEquals(149, WifiInfoUtil.channel(5745))
        assertEquals("2.4 GHz", WifiInfoUtil.band(2437))
        assertEquals("5 GHz", WifiInfoUtil.band(5180))
        assertEquals("6 GHz", WifiInfoUtil.band(5975))
    }

    @Test
    fun wifiSignalPercent() {
        assertEquals(100, WifiInfoUtil.signalPercent(-45))
        assertEquals(0, WifiInfoUtil.signalPercent(-100))
        assertEquals(50, WifiInfoUtil.signalPercent(-75))
    }

    @Test
    fun wifiSecurityParsing() {
        assertEquals("WPA3", WifiInfoUtil.security("[WPA3-SAE-CCMP][ESS]"))
        assertEquals("WPA2", WifiInfoUtil.security("[WPA2-PSK-CCMP][RSN][ESS]"))
        assertEquals("WEP", WifiInfoUtil.security("[WEP][ESS]"))
        assertEquals("Open", WifiInfoUtil.security("[ESS]"))
        assertTrue(WifiInfoUtil.isWeak("Open"))
        assertTrue(WifiInfoUtil.isWeak("WEP"))
        assertFalse(WifiInfoUtil.isWeak("WPA2"))
    }
}
