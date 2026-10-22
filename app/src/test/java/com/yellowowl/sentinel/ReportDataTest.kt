package com.yellowowl.sentinel

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

class ReportDataTest {
    private val findings = listOf(
        Finding(id = "1", title = "Telnet exposed", severity = Severity.HIGH, source = FindingSource.NETWORK,
            scope = "192.168.1.0/24", target = "192.168.1.10:23", details = "Telnet is cleartext.",
            remediation = "Disable telnet.", createdAt = 1_700_000_000_000L),
        Finding(id = "2", title = "Missing HSTS", severity = Severity.LOW, source = FindingSource.WEB,
            scope = "example.com", target = "example.com", details = "No HSTS, value has a \"quote\", comma.",
            remediation = "Add header.", createdAt = 1_700_000_000_000L)
    )

    @Test fun csvHasHeaderRowAndAllFindings() {
        val csv = ReportData.toCsv(findings)
        val lines = csv.trim().split("\r\n")
        assertEquals(3, lines.size) // header + 2
        assertTrue(lines[0].startsWith("severity,source,scope,target,title"))
        assertTrue(csv.contains("Telnet exposed"))
    }

    @Test fun csvEscapesQuotesAndCommas() {
        val csv = ReportData.toCsv(findings)
        // The details field with a quote and comma must be wrapped and its quote doubled.
        assertTrue(csv.contains("\"No HSTS, value has a \"\"quote\"\", comma.\""))
    }

    @Test fun csvOrdersBySeverity() {
        val csv = ReportData.toCsv(findings)
        val body = csv.trim().split("\r\n").drop(1)
        assertTrue(body[0].startsWith("High")) // HIGH before LOW
    }

    @Test fun jsonIsValidAndStructured() {
        val json = ReportData.toJson(findings, Date(1_700_000_000_000L), "1.7.0")
        val o = JSONObject(json)
        assertEquals("Sentinel Security", o.getString("tool"))
        assertEquals("1.7.0", o.getString("app_version"))
        assertEquals(2, o.getInt("count"))
        assertEquals(1, o.getJSONObject("counts").getInt("high"))
        val first = o.getJSONArray("findings").getJSONObject(0)
        assertEquals("Telnet exposed", first.getString("title"))
        assertTrue(first.getString("created_at").startsWith("2023-11-14T"))
    }

    @Test fun annotationsAppearInExports() {
        val ann = mapOf(findings[0].key to FindingAnnotation(status = FindingStatus.FIXED, notes = "patched"))
        val csv = ReportData.toCsv(findings, ann)
        assertTrue(csv.contains("patched"))
        val json = ReportData.toJson(findings, Date(0L), "1.7.0", ann)
        assertTrue(json.contains("\"notes\": \"patched\""))
    }
}
