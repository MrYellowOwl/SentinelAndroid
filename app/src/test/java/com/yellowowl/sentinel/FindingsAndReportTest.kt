package com.yellowowl.sentinel

import java.util.Date
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FindingsAndReportTest {
    private fun finding(title: String, severity: Severity, source: String, scope: String, createdAt: Long) = Finding(
        title = title, severity = severity, source = source, scope = scope, target = scope,
        details = "d", remediation = "r", createdAt = createdAt
    )

    @Test
    fun rescanReplacesOnlyTheSameSourceAndScope() {
        val existing = listOf(
            finding("old lan issue", Severity.HIGH, FindingSource.NETWORK, "192.168.1.0/24", 1),
            finding("other lan", Severity.LOW, FindingSource.NETWORK, "10.0.0.0/24", 2),
            finding("site issue", Severity.MEDIUM, FindingSource.WEB, "example.com", 3)
        )
        val newRun = listOf(finding("new lan issue", Severity.MEDIUM, FindingSource.NETWORK, "192.168.1.0/24", 10))
        val merged = FindingMerge.replaceRun(existing, FindingSource.NETWORK, "192.168.1.0/24", newRun, max = 100)
        val titles = merged.map { it.title }
        assertFalse(titles.contains("old lan issue"))
        assertTrue(titles.containsAll(listOf("new lan issue", "other lan", "site issue")))
    }

    @Test
    fun emptyRescanClearsFixedIssues() {
        val existing = listOf(finding("fixed", Severity.HIGH, FindingSource.WEB, "example.com", 1))
        assertTrue(FindingMerge.replaceRun(existing, FindingSource.WEB, "EXAMPLE.com", emptyList(), 100).isEmpty())
    }

    @Test
    fun historyIsCappedKeepingNewest() {
        val existing = (1..10).map { finding("f$it", Severity.LOW, FindingSource.WEB, "site$it", it.toLong()) }
        val merged = FindingMerge.replaceRun(existing, FindingSource.WEB, "new", emptyList(), max = 3)
        assertEquals(listOf("f10", "f9", "f8"), merged.map { it.title })
    }

    @Test
    fun prioritizedSortsBySeverityThenNewest() {
        val list = listOf(
            finding("low", Severity.LOW, "s", "a", 5),
            finding("high-old", Severity.HIGH, "s", "a", 1),
            finding("info", Severity.INFO, "s", "a", 9),
            finding("high-new", Severity.HIGH, "s", "a", 2)
        )
        assertEquals(listOf("high-new", "high-old", "low", "info"), FindingMerge.prioritized(list).map { it.title })
    }

    @Test
    fun severityParsingIsLenient() {
        assertEquals(Severity.HIGH, Severity.parse("critical"))
        assertEquals(Severity.MEDIUM, Severity.parse(" Medium "))
        assertEquals(Severity.INFO, Severity.parse(null))
        assertEquals(Severity.INFO, Severity.parse("garbage"))
    }

    @Test
    fun reportEscapesContentAndShowsCounts() {
        val html = ReportHtml.build(
            listOf(
                finding("<script>alert('x')</script>", Severity.HIGH, FindingSource.WEB, "example.com", 1),
                finding("Plain", Severity.LOW, FindingSource.WEB, "example.com", 2)
            ),
            Date(0), "1.0.0"
        )
        assertFalse(html.contains("<script>alert"))
        assertTrue(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"))
        assertTrue(html.contains("""<div class="stat high"><b>1</b>"""))
        assertTrue(html.contains("Sentinel 1.0.0"))
        // High-severity row comes before the low one.
        assertTrue(html.indexOf("&lt;script&gt;") < html.indexOf("<b>Plain</b>"))
    }

    @Test
    fun emptyReportIsValid() {
        val html = ReportHtml.build(emptyList(), Date(0), "1.0.0")
        assertTrue(html.contains("No saved findings."))
        assertTrue(html.trimEnd().endsWith("</html>"))
    }
}
