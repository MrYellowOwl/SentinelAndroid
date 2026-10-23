package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SavedNetworkTest {
    private fun dev(ip: String, mac: String? = null, gw: Boolean = false, ports: List<Int> = emptyList()) =
        SavedDevice(mac = mac, ip = ip, openPorts = ports, isGateway = gw)

    @Test fun deviceKeyPrefersMacOverIp() {
        assertEquals("mac:aa:bb:cc:dd:ee:ff", NetworkMerge.deviceKey("AA:BB:CC:DD:EE:FF", "192.168.1.5"))
        assertEquals("ip:192.168.1.5", NetworkMerge.deviceKey(null, "192.168.1.5"))
        assertEquals("ip:192.168.1.5", NetworkMerge.deviceKey("", "192.168.1.5"))
    }

    @Test fun firstScanSetsFirstAndLastSeen() {
        val net = NetworkMerge.mergeScan(
            prior = null, id = "net1", label = "Home", ssid = "Home", bssid = "b1",
            cidr = "192.168.1.0/24", gatewayIp = "192.168.1.1", security = "WPA2",
            scanned = listOf(dev("192.168.1.1", "aa:aa:aa:aa:aa:aa", gw = true), dev("192.168.1.5", "bb:bb:bb:bb:bb:bb")),
            now = 1000L
        )
        assertEquals(1000L, net.firstSeen)
        assertEquals(2, net.deviceCount)
        assertEquals(2, net.onlineCount)
        assertTrue(net.devices.all { it.firstSeen == 1000L && it.lastSeen == 1000L && it.online })
        assertTrue(net.devices.first().isGateway)   // gateway sorts first
    }

    @Test fun rescanKeepsFirstSeenAndMarksDepartedOffline() {
        val first = NetworkMerge.mergeScan(
            null, "net1", "Home", "Home", "b1", "192.168.1.0/24", "192.168.1.1", "WPA2",
            listOf(dev("192.168.1.5", "bb:bb:bb:bb:bb:bb"), dev("192.168.1.9", "cc:cc:cc:cc:cc:cc")),
            now = 1000L
        )
        // Second scan: .5 still present (new IP, same MAC), .9 gone, a new .12 appears.
        val second = NetworkMerge.mergeScan(
            first, "net1", "Home", "Home", "b1", "192.168.1.0/24", "192.168.1.1", "WPA2",
            listOf(dev("192.168.1.20", "bb:bb:bb:bb:bb:bb"), dev("192.168.1.12", "dd:dd:dd:dd:dd:dd")),
            now = 5000L
        )
        val byMac = second.devices.associateBy { it.mac }
        // .5→.20 device matched by MAC: firstSeen preserved, lastSeen updated, still online, IP moved.
        val moved = byMac["bb:bb:bb:bb:bb:bb"]!!
        assertEquals(1000L, moved.firstSeen); assertEquals(5000L, moved.lastSeen)
        assertTrue(moved.online); assertEquals("192.168.1.20", moved.ip)
        // Departed device kept but offline.
        val gone = byMac["cc:cc:cc:cc:cc:cc"]!!
        assertFalse(gone.online); assertEquals(1000L, gone.firstSeen)
        // New device.
        val fresh = byMac["dd:dd:dd:dd:dd:dd"]!!
        assertTrue(fresh.online); assertEquals(5000L, fresh.firstSeen)
        assertEquals(1000L, second.firstSeen)   // network firstSeen preserved
        assertEquals(3, second.deviceCount); assertEquals(2, second.onlineCount)
        // Online devices sort before offline ones.
        assertTrue(second.devices.indexOf(moved) < second.devices.indexOf(gone))
    }

    @Test fun dedupesDevicesSharingAnIdentityWithinOneScan() {
        // Same MAC reported on two IPs (ARP quirk) must collapse to one row — two rows with the same
        // device key would crash the list UI on a duplicate key.
        val net = NetworkMerge.mergeScan(
            null, "net1", "Home", "Home", "b1", "192.168.1.0/24", "192.168.1.1", "WPA2",
            listOf(
                dev("192.168.1.5", "bb:bb:bb:bb:bb:bb"),
                dev("192.168.1.6", "bb:bb:bb:bb:bb:bb"),   // same MAC, different IP
                dev("192.168.1.7", null),
                dev("192.168.1.7", null)                    // same IP, no MAC
            ),
            now = 1000L
        )
        val keys = net.devices.map { NetworkMerge.deviceKey(it.mac, it.ip) }
        assertEquals(keys.distinct(), keys)                // every render key is unique
        assertEquals(2, net.deviceCount)                   // one per identity
    }

    @Test fun codecRoundTrips() {
        val net = NetworkMerge.mergeScan(
            null, "net1", "Home", "Home", "bssid-1", "192.168.1.0/24", "192.168.1.1", "WPA2",
            listOf(dev("192.168.1.1", "aa:aa:aa:aa:aa:aa", gw = true, ports = listOf(80, 443)), dev("192.168.1.5")),
            now = 1234L
        )
        val decoded = NetworkCodec.decode(NetworkCodec.encode(listOf(net)))
        assertEquals(1, decoded.size)
        val n = decoded.first()
        assertEquals("net1", n.id); assertEquals("Home", n.ssid); assertEquals("192.168.1.0/24", n.cidr)
        assertEquals(2, n.deviceCount)
        val gw = n.devices.first { it.isGateway }
        assertEquals(listOf(80, 443), gw.openPorts); assertEquals("aa:aa:aa:aa:aa:aa", gw.mac)
        val noMac = n.devices.first { it.mac == null }
        assertEquals("192.168.1.5", noMac.ip); assertNull(noMac.mac)
    }

    @Test fun decodeHealsDuplicateDeviceKeys() {
        // Data written by the pre-fix merge could contain two rows with the same MAC; decode must
        // collapse them so the list UI can't hit a duplicate key.
        val json = """
            {"version":1,"networks":[{"id":"n1","label":"Home","devices":[
                {"mac":"bb:bb:bb:bb:bb:bb","ip":"192.168.1.5","lastSeen":2},
                {"mac":"bb:bb:bb:bb:bb:bb","ip":"192.168.1.6","lastSeen":2},
                {"ip":"192.168.1.9","lastSeen":2}
            ]}]}
        """.trimIndent()
        val net = NetworkCodec.decode(json).single()
        val keys = net.devices.map { NetworkMerge.deviceKey(it.mac, it.ip) }
        assertEquals(keys.distinct(), keys)
        assertEquals(2, net.deviceCount)
    }

    @Test fun decodeJunkIsEmpty() {
        assertTrue(NetworkCodec.decode("not json").isEmpty())
        assertTrue(NetworkCodec.decode("""{"version":1}""").isEmpty())
    }
}
