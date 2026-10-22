package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EolDataTest {
    @Test fun flagsEolPhpBranches() {
        assertNotNull(EolData.eolNote("php", "8.1.6"))
        assertNotNull(EolData.eolNote("php", "7.4.33"))
        assertNotNull(EolData.eolNote("php", "5.6.40"))   // falls back to major "5"
        assertNotNull(EolData.eolNote("php", "8.0.1"))
    }

    @Test fun leavesSupportedPhpAlone() {
        assertNull(EolData.eolNote("php", "8.2.10"))
        assertNull(EolData.eolNote("php", "8.3.0"))
        assertNull(EolData.eolNote("php", "8.4.1"))
    }

    @Test fun handlesApacheAndMysqlBranches() {
        assertNotNull(EolData.eolNote("apache_httpd", "2.2.34"))
        assertNull(EolData.eolNote("apache_httpd", "2.4.58"))
        assertNotNull(EolData.eolNote("mysql", "5.7.41"))
        assertNull(EolData.eolNote("mysql", "8.0.35"))
    }

    @Test fun unknownProductOrNoVersionIsNull() {
        assertNull(EolData.eolNote("nginx", "1.18.0"))
        assertNull(EolData.eolNote("php", null))
    }

    @Test fun findingHasMediumSeverityAndTarget() {
        val f = EolData.finding("192.168.1.0/24", "192.168.1.5:80", ServiceFingerprint("php", "8.1.2"))!!
        assertEquals(Severity.MEDIUM, f.severity)
        assertEquals("192.168.1.5:80", f.target)
        assertTrue(f.title.contains("End-of-life"))
        assertNull(EolData.finding("s", "t", ServiceFingerprint("php", "8.3.0")))
    }
}
