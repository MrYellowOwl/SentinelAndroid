package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HandoffTest {
    private fun device(ip: String, vararg ports: Int) = DeviceResult(
        ipAddress = ip,
        openPorts = ports.map { PortFinding(it, PortCatalog.serviceName(it)) }
    )

    @Test
    fun fullScanUsesTheOpenPorts() {
        val cmds = Handoff.forDevice(device("192.168.1.10", 22, 80, 445))
        assertTrue(cmds.any { it.command == "nmap -sV -sC -p22,80,445 192.168.1.10" })
    }

    @Test
    fun perServiceCommandsAreGenerated() {
        val cmds = Handoff.forDevice(device("10.0.0.5", 22, 445, 443, 3306)).map { it.command }
        assertTrue(cmds.contains("ssh user@10.0.0.5"))
        assertTrue(cmds.contains("smbclient -L //10.0.0.5 -N"))
        assertTrue(cmds.any { it.startsWith("testssl.sh 10.0.0.5:443") })
        assertTrue(cmds.contains("mysql -h 10.0.0.5 -u root -p"))
    }

    @Test
    fun noPortsFallsBackToTopPortsScan() {
        val cmds = Handoff.forDevice(device("10.0.0.9"))
        assertEquals(1, cmds.size)
        assertTrue(cmds[0].command.contains("--top-ports"))
    }

    @Test
    fun commandsAreDeduped() {
        // two HTTP ports should not produce duplicate identical commands
        val cmds = Handoff.forDevice(device("10.0.0.5", 80, 8080)).map { it.command }
        assertEquals(cmds.size, cmds.distinct().size)
    }

    @Test
    fun webHostCommandsIncludeWpScanOnlyWhenWordPress() {
        val plain = Handoff.forWebHost("example.com", isWordPress = false).map { it.command }
        assertTrue(plain.none { it.contains("wpscan") })
        val wp = Handoff.forWebHost("blog.example.com", isWordPress = true).map { it.command }
        assertTrue(wp.any { it.contains("wpscan --url https://blog.example.com") })
    }
}
