package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WebDeepTest {
    private val origin = "https://sentinel-cors-probe.example"

    @Test fun corsReflectionWithCredentialsIsHigh() {
        val f = WebDeep.corsFinding("s", "h", origin, acao = origin, acac = "true")!!
        assertEquals(Severity.HIGH, f.severity)
        assertTrue(f.title.contains("arbitrary origin"))
    }

    @Test fun corsReflectionWithoutCredentialsIsMedium() {
        val f = WebDeep.corsFinding("s", "h", origin, acao = origin, acac = null)!!
        assertEquals(Severity.MEDIUM, f.severity)
    }

    @Test fun corsWildcardIsInfoAndNoAcaoIsNull() {
        assertEquals(Severity.INFO, WebDeep.corsFinding("s", "h", origin, acao = "*", acac = null)!!.severity)
        assertNull(WebDeep.corsFinding("s", "h", origin, acao = null, acac = null))
    }

    @Test fun securityTxtOnlyFlaggedWhenMissing() {
        assertNull(WebDeep.securityTxtFinding("s", "h", found = true))
        assertEquals(Severity.INFO, WebDeep.securityTxtFinding("s", "h", found = false)!!.severity)
    }

    @Test fun sriFindsExternalScriptsMissingIntegrity() {
        val html = """
            <script src="https://cdn.example.com/a.js"></script>
            <script src="https://cdn.example.com/b.js" integrity="sha384-xyz"></script>
            <script src="/local.js"></script>
            <script src="https://myhost/self.js"></script>
        """.trimIndent()
        val bad = WebDeep.externalScriptsWithoutSri(html, "myhost")
        assertEquals(listOf("https://cdn.example.com/a.js"), bad)   // b has integrity, /local is same-origin, self is same host
    }

    @Test fun exposedPathSeverityFromTable() {
        val git = WebDeep.sensitivePaths.first { it.path == "/.git/config" }
        assertEquals(Severity.HIGH, WebDeep.exposedPathFinding("s", "h", git).severity)
    }

    @Test fun softNotFoundOnlyWhenRandomPathReturns200() {
        assertTrue(WebDeep.looksLikeSoftNotFound(200))
        assertTrue(!WebDeep.looksLikeSoftNotFound(404))
        assertTrue(!WebDeep.looksLikeSoftNotFound(403))
        assertTrue(!WebDeep.looksLikeSoftNotFound(null))
    }

    @Test fun softNotFoundFindingIsInfo() {
        val f = WebDeep.softNotFoundFinding("s", "h")
        assertEquals(Severity.INFO, f.severity)
        assertTrue(f.title.contains("soft-404"))
    }
}
