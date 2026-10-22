package com.yellowowl.sentinel

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject

/** Persists user-assigned device nicknames (device key -> name). */
object NicknameStore {
    private const val PREFS = "sentinel_nicknames"
    private const val KEY = "names"

    private val _names = MutableStateFlow<Map<String, String>>(emptyMap())
    val names: StateFlow<Map<String, String>> = _names.asStateFlow()

    @Volatile private var loaded = false

    fun init(context: Context) {
        if (loaded) return
        synchronized(this) {
            if (loaded) return
            _names.value = read(context)
            loaded = true
        }
    }

    /** Current names, loading from disk if a background component hasn't yet. */
    fun current(context: Context): Map<String, String> {
        init(context)
        return _names.value
    }

    fun set(context: Context, key: String, name: String) {
        init(context)
        val updated = _names.value.toMutableMap()
        if (name.isBlank()) updated.remove(key) else updated[key] = name.trim()
        _names.value = updated
        val obj = JSONObject()
        updated.forEach { (k, v) -> obj.put(k, v) }
        runCatching { prefs(context).edit().putString(KEY, obj.toString()).apply() }
    }

    private fun read(context: Context): Map<String, String> = runCatching {
        val raw = prefs(context).getString(KEY, null) ?: return@runCatching emptyMap<String, String>()
        val obj = JSONObject(raw)
        buildMap { obj.keys().forEach { k -> put(k, obj.optString(k)) } }
    }.getOrDefault(emptyMap())

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
