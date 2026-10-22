package com.yellowowl.sentinel

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import org.json.JSONArray
import org.json.JSONObject

/**
 * Machine-readable exports of findings: CSV for spreadsheets, JSON for tooling/pipelines.
 * Pure Kotlin (org.json for correct escaping) so both are unit tested.
 */
object ReportData {
    private fun iso(epochMillis: Long): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
            .apply { timeZone = TimeZone.getTimeZone("UTC") }
            .format(Date(epochMillis))

    private val CSV_COLUMNS = listOf(
        "severity", "source", "scope", "target", "title", "details", "remediation", "status", "notes", "created_at"
    )

    /** RFC-4180-style CSV: quote fields containing comma, quote, CR or LF; double internal quotes. */
    fun toCsv(findings: List<Finding>, annotations: Map<String, FindingAnnotation> = emptyMap()): String {
        val sb = StringBuilder()
        sb.append(CSV_COLUMNS.joinToString(",")).append("\r\n")
        for (f in FindingMerge.prioritized(findings)) {
            val a = annotations[f.key]
            val cells = listOf(
                f.severity.label, f.source, f.scope, f.target, f.title, f.details, f.remediation,
                a?.takeIf { !it.isDefault }?.status?.label.orEmpty(),
                a?.notes.orEmpty(),
                iso(f.createdAt)
            )
            sb.append(cells.joinToString(",") { escapeCsv(it) }).append("\r\n")
        }
        return sb.toString()
    }

    private fun escapeCsv(value: String): String =
        if (value.any { it == ',' || it == '"' || it == '\n' || it == '\r' })
            "\"" + value.replace("\"", "\"\"") + "\""
        else value

    fun toJson(
        findings: List<Finding>,
        generatedAt: Date,
        appVersion: String,
        annotations: Map<String, FindingAnnotation> = emptyMap()
    ): String {
        val ordered = FindingMerge.prioritized(findings)
        val counts = FindingMerge.countBySeverity(findings)
        val countsJson = JSONObject()
        Severity.entries.forEach { countsJson.put(it.name.lowercase(), counts[it] ?: 0) }

        val arr = JSONArray()
        for (f in ordered) {
            val a = annotations[f.key]
            val o = JSONObject()
                .put("id", f.id)
                .put("severity", f.severity.label)
                .put("source", f.source)
                .put("scope", f.scope)
                .put("target", f.target)
                .put("title", f.title)
                .put("details", f.details)
                .put("remediation", f.remediation)
                .put("created_at", iso(f.createdAt))
            if (a != null && !a.isDefault) o.put("status", a.status.label)
            if (!a?.notes.isNullOrBlank()) o.put("notes", a!!.notes)
            arr.put(o)
        }

        return JSONObject()
            .put("tool", "Sentinel Security")
            .put("app_version", appVersion)
            .put("generated_at", iso(generatedAt.time))
            .put("count", ordered.size)
            .put("counts", countsJson)
            .put("findings", arr)
            .toString(2)
    }
}
