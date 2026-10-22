package com.yellowowl.sentinel

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** Persists the network-monitoring state and the device baseline used for change detection. */
object MonitorStore {
    private const val PREFS = "sentinel_monitor"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_CIDR = "cidr"
    private const val KEY_BASELINE = "baseline_json"
    private const val KEY_BASELINE_CIDR = "baseline_cidr"

    fun isEnabled(context: Context): Boolean = prefs(context).getBoolean(KEY_ENABLED, false)
    fun monitoredCidr(context: Context): String? = prefs(context).getString(KEY_CIDR, null)?.takeIf { it.isNotBlank() }

    fun setEnabled(context: Context, enabled: Boolean, cidr: String?) {
        prefs(context).edit().putBoolean(KEY_ENABLED, enabled).putString(KEY_CIDR, if (enabled) cidr else null).apply()
    }

    fun saveBaseline(context: Context, cidr: String, snapshots: List<DeviceSnapshot>) {
        val array = JSONArray()
        snapshots.forEach { s ->
            array.put(JSONObject().apply {
                put("ip", s.ip); put("mac", s.mac ?: ""); put("name", s.name ?: "")
                put("ports", JSONArray().also { pa -> s.ports.forEach { pa.put(it) } })
            })
        }
        prefs(context).edit().putString(KEY_BASELINE, array.toString()).putString(KEY_BASELINE_CIDR, cidr).apply()
    }

    fun loadBaseline(context: Context, cidr: String): List<DeviceSnapshot>? {
        if (prefs(context).getString(KEY_BASELINE_CIDR, null) != cidr) return null
        val raw = prefs(context).getString(KEY_BASELINE, null) ?: return null
        return try {
            val array = JSONArray(raw)
            buildList {
                for (i in 0 until array.length()) {
                    val o = array.optJSONObject(i) ?: continue
                    val portsArr = o.optJSONArray("ports")
                    val ports = buildList { if (portsArr != null) for (j in 0 until portsArr.length()) add(portsArr.optInt(j)) }
                    add(DeviceSnapshot(o.optString("ip"), o.optString("mac").ifBlank { null }, o.optString("name").ifBlank { null }, ports))
                }
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
