package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpExposureTest {
    @Test fun classifiesAddressKinds() {
        assertEquals(IpExposure.IpKind.PUBLIC, IpExposure.classify("8.8.8.8"))
        assertEquals(IpExposure.IpKind.PRIVATE, IpExposure.classify("192.168.1.5"))
        assertEquals(IpExposure.IpKind.PRIVATE, IpExposure.classify("10.0.0.1"))
        assertEquals(IpExposure.IpKind.PRIVATE, IpExposure.classify("172.16.0.1"))
        assertEquals(IpExposure.IpKind.CGNAT, IpExposure.classify("100.70.0.1"))
        assertEquals(IpExposure.IpKind.LOOPBACK, IpExposure.classify("127.0.0.1"))
        assertEquals(IpExposure.IpKind.LINK_LOCAL, IpExposure.classify("169.254.1.1"))
        assertEquals(IpExposure.IpKind.UNKNOWN, IpExposure.classify("not-an-ip"))
    }

    @Test fun cgnatBoundaryIsCorrect() {
        // 100.64.0.0 – 100.127.255.255 is CGNAT; 100.63.x and 100.128.x are not.
        assertEquals(IpExposure.IpKind.CGNAT, IpExposure.classify("100.64.0.0"))
        assertEquals(IpExposure.IpKind.CGNAT, IpExposure.classify("100.127.255.255"))
        assertEquals(IpExposure.IpKind.PUBLIC, IpExposure.classify("100.63.255.255"))
        assertEquals(IpExposure.IpKind.PUBLIC, IpExposure.classify("100.128.0.0"))
    }

    @Test fun parsesIpApiSuccess() {
        val json = """{"status":"success","query":"203.0.113.9","isp":"Acme ISP",
            "org":"Acme","as":"AS64500 Acme","city":"Austin","country":"United States"}"""
        val info = IpExposure.parseInfo(json)!!
        assertEquals("203.0.113.9", info.ip)
        assertEquals("Acme ISP", info.isp)
        assertEquals("AS64500 Acme", info.asn)
        assertEquals("Austin, United States", info.location)
        assertEquals(IpExposure.IpKind.PUBLIC, info.kind)
    }

    @Test fun parseRejectsFailAndJunk() {
        assertNull(IpExposure.parseInfo("""{"status":"fail","message":"private range"}"""))
        assertNull(IpExposure.parseInfo("nope"))
    }

    @Test fun verdictsDifferByKind() {
        assertTrue(IpExposure.verdict(IpExposure.IpKind.CGNAT).contains("carrier-grade", ignoreCase = true))
        assertTrue(IpExposure.verdict(IpExposure.IpKind.PUBLIC).contains("public", ignoreCase = true))
    }
}
