package com.yellowowl.sentinel

import java.text.DateFormat
import java.util.Date

/** Builds the shareable HTML report. Pure Kotlin so it can be unit tested. */
object ReportHtml {
    /** Plain-text one-liner used in the report's executive summary (pure, testable). */
    fun execLine(findings: List<Finding>): String {
        val c = FindingMerge.countBySeverity(findings)
        val kev = findings.count { it.title.startsWith("[KEV]") }
        val parts = Severity.entries.filter { (c[it] ?: 0) > 0 }.map { "${c[it]} ${it.label.lowercase()}" }
        val head = if (findings.isEmpty()) "No findings recorded." else "${findings.size} finding(s): ${parts.joinToString(", ")}."
        return head + if (kev > 0) " $kev flagged as actively exploited (CISA KEV) — prioritize these." else ""
    }

    fun build(
        findings: List<Finding>,
        generatedAt: Date,
        appVersion: String,
        annotations: Map<String, FindingAnnotation> = emptyMap(),
        scopeEntries: List<Scope.Entry> = emptyList()
    ): String {
        val dateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
        val counts = FindingMerge.countBySeverity(findings)
        val summary = Severity.entries.joinToString("") { severity ->
            """<div class="stat ${severity.name.lowercase()}"><b>${counts[severity] ?: 0}</b><span>${severity.label}</span></div>"""
        }

        // Framework breakdown for the executive summary.
        val byOwasp = findings.mapNotNull { Compliance.tag(it).owasp }.groupingBy { it }.eachCount()
            .entries.sortedByDescending { it.value }
        val frameworkHtml = if (byOwasp.isEmpty()) "" else
            "<p><b>OWASP coverage:</b> " + byOwasp.joinToString("; ") { "${escape(it.key)} (${it.value})" } + "</p>"
        val outOfScope = Scope.outOfScope(scopeEntries, findings.map { it.target })
        val scopeHtml = when {
            scopeEntries.isEmpty() -> ""
            outOfScope.isEmpty() -> "<p><b>Scope:</b> all findings fall within the defined engagement scope.</p>"
            else -> """<p class="oos"><b>Out of scope:</b> ${outOfScope.joinToString(", ") { escape(it) }} — review authorization before acting on these.</p>"""
        }

        fun row(f: Finding): String {
            val a = annotations[f.key]
            val statusTag = a?.takeIf { !it.isDefault }?.let {
                """<span class="status ${it.status.name.lowercase()}">${escape(it.status.label)}</span>"""
            }.orEmpty()
            val notes = a?.notes?.takeIf { it.isNotBlank() }?.let { "<br><small>Notes: ${escape(it)}</small>" }.orEmpty()
            val tags = Compliance.tag(f).labels.joinToString("") { """<span class="tag">${escape(it)}</span>""" }
            return """<tr><td><span class="sev ${f.severity.name.lowercase()}">${f.severity.label}</span></td>""" +
                """<td><b>${escape(f.title)}</b> $statusTag<br><small>${escape(f.source)} · ${escape(dateFormat.format(Date(f.createdAt)))}</small>$notes${if (tags.isNotEmpty()) "<br>$tags" else ""}</td>""" +
                """<td>${escape(f.target)}</td><td>${escape(f.details)}</td><td>${escape(f.remediation)}</td></tr>"""
        }

        // Group network findings by host IP, then website findings by host, then anything else.
        val groups: List<Pair<String, List<Finding>>> = buildList {
            findings.filter { it.source == FindingSource.NETWORK }
                .groupBy { it.hostIp ?: it.target }
                .toSortedMap(compareBy { Ipv4.parse(it) ?: Long.MAX_VALUE })
                .forEach { (host, list) -> add("Host $host" to list) }
            findings.filter { it.source == FindingSource.WEB }
                .groupBy { it.target }
                .forEach { (host, list) -> add("Website $host" to list) }
            findings.filterNot { it.source == FindingSource.NETWORK || it.source == FindingSource.WEB }
                .takeIf { it.isNotEmpty() }?.let { add("Other" to it) }
        }

        val body = if (findings.isEmpty()) {
            """<table><thead><tr><th>Severity</th><th>Finding</th><th>Target</th><th>Details</th><th>Recommended action</th></tr></thead>""" +
                """<tbody><tr><td colspan="5">No saved findings.</td></tr></tbody></table>"""
        } else {
            groups.joinToString("\n") { (title, list) ->
                val rows = FindingMerge.prioritized(list).joinToString("\n", transform = ::row)
                """<h2>${escape(title)}</h2>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Target</th><th>Details</th><th>Recommended action</th></tr></thead><tbody>
$rows
</tbody></table>"""
            }
        }

        return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Security Report</title>
<style>
body{font:15px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:32px auto;max-width:1100px;padding:0 16px;color:#17212b}
h1{margin:0;color:#0d6b58}p{color:#536171}
.notice{padding:12px 14px;background:#eef7f4;border-left:4px solid #1d9d7b;border-radius:4px}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}
.stat{border:1px solid #d9e1e8;border-radius:10px;padding:10px 16px;min-width:90px}
.stat b{display:block;font-size:24px}.stat span{color:#536171;font-size:13px}
table{border-collapse:collapse;width:100%;margin-top:20px}
th,td{border:1px solid #d9e1e8;padding:9px;text-align:left;vertical-align:top}
th{background:#f1f5f8}td{overflow-wrap:anywhere}small{color:#5d6874}
.sev{display:inline-block;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700}
.high{color:#b3261e}.sev.high{background:#fde7e9}.medium{color:#8a5a00}.sev.medium{background:#fff1d6}
.low{color:#1f5f99}.sev.low{background:#e3f0fc}.info{color:#0d6b58}.sev.info{background:#e3f5ef}
h2{margin:26px 0 0;font-size:16px;color:#0d6b58;border-bottom:2px solid #d9e1e8;padding-bottom:4px}
.status{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px;font-weight:700;background:#eef2f5;color:#536171}
.status.fixed{background:#e3f5ef;color:#0d6b58}.status.false_positive{background:#eef2f5;color:#70797f}.status.verified{background:#fff1d6;color:#8a5a00}
.tag{display:inline-block;margin:3px 4px 0 0;padding:1px 7px;border-radius:5px;font-size:11px;background:#eef2f5;color:#45566b}
.summary{border:1px solid #d9e1e8;border-radius:10px;padding:4px 16px;margin:18px 0}
.oos{color:#b3261e}
@media print{body{margin:0}.notice,.summary{break-inside:avoid}}
</style></head><body>
<h1>Sentinel Security Report</h1>
<p>Generated ${escape(dateFormat.format(generatedAt))} · ${findings.size} finding(s) · Sentinel $appVersion</p>
<div class="stats">$summary</div>
<div class="summary"><h2 style="border:0;margin:10px 0 4px">Executive summary</h2><p>${escape(execLine(findings))}</p>$frameworkHtml$scopeHtml</div>
<div class="notice"><b>Scope note:</b> Findings are automated indicators, not proof of exploitability. Validate them in context and only test systems you own or are authorized to assess.</div>
$body
<p><small>Generated locally on the device by Sentinel Security.</small></p></body></html>"""
    }

    fun escape(value: String): String = value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")
}
