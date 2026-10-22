package com.yellowowl.sentinel

import android.content.Context
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

/** Small device-local persistence. Nothing is uploaded. */
object FindingStore {
    private const val PREFS = "sentinel_local_data"
    private const val KEY_FINDINGS = "findings_json"
    private const val MAX_FINDINGS = 300

    fun load(context: Context): List<Finding> {
        val raw = prefs(context).getString(KEY_FINDINGS, "[]") ?: "[]"
        return try {
            val array = JSONArray(raw)
            buildList {
                for (index in 0 until array.length()) {
                    val item = array.optJSONObject(index) ?: continue
                    add(
                        Finding(
                            // A blank or duplicate id would crash keyed lists, so repair it on load.
                            id = item.optString("id").ifBlank { UUID.randomUUID().toString() },
                            title = item.optString("title"),
                            severity = Severity.parse(item.optString("severity")),
                            source = item.optString("source"),
                            scope = item.optString("scope"),
                            target = item.optString("target"),
                            details = item.optString("details"),
                            remediation = item.optString("remediation"),
                            createdAt = item.optLong("createdAt", System.currentTimeMillis())
                        )
                    )
                }
            }.distinctBy { it.id }.sortedByDescending { it.createdAt }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /** Saves a completed scan, replacing the previous results for the same source and scope. Returns the new list. */
    fun replaceRun(context: Context, source: String, scope: String, run: List<Finding>): List<Finding> {
        val updated = FindingMerge.replaceRun(load(context), source, scope, run, MAX_FINDINGS)
        save(context, updated)
        return updated
    }

    fun remove(context: Context, id: String): List<Finding> {
        val updated = FindingMerge.remove(load(context), id)
        save(context, updated)
        return updated
    }

    /** Replaces one host's findings from a single-host rescan, leaving other hosts untouched. */
    fun replaceHost(context: Context, source: String, scope: String, hostIp: String, run: List<Finding>): List<Finding> {
        val updated = FindingMerge.replaceHost(load(context), source, scope, hostIp, run, MAX_FINDINGS)
        save(context, updated)
        return updated
    }

    fun clear(context: Context) {
        prefs(context).edit().remove(KEY_FINDINGS).apply()
    }

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun save(context: Context, findings: List<Finding>) {
        val array = JSONArray()
        findings.forEach { finding ->
            array.put(
                JSONObject().apply {
                    put("id", finding.id)
                    put("title", finding.title)
                    put("severity", finding.severity.name)
                    put("source", finding.source)
                    put("scope", finding.scope)
                    put("target", finding.target)
                    put("details", finding.details)
                    put("remediation", finding.remediation)
                    put("createdAt", finding.createdAt)
                }
            )
        }
        prefs(context).edit().putString(KEY_FINDINGS, array.toString()).apply()
    }
}
