package com.yellowowl.sentinel

import android.content.Context
import org.json.JSONObject

/** Device-local triage annotations (status + notes), keyed by [Finding.key] so they survive rescans. */
object AnnotationStore {
    private const val PREFS = "sentinel_annotations"
    private const val KEY = "annotations_json"

    fun load(context: Context): Map<String, FindingAnnotation> {
        val raw = prefs(context).getString(KEY, "{}") ?: "{}"
        return try {
            val root = JSONObject(raw)
            buildMap {
                for (key in root.keys()) {
                    val obj = root.optJSONObject(key) ?: continue
                    put(
                        key,
                        FindingAnnotation(
                            status = FindingStatus.parse(obj.optString("status")),
                            notes = obj.optString("notes"),
                            updatedAt = obj.optLong("updatedAt", System.currentTimeMillis())
                        )
                    )
                }
            }
        } catch (_: Exception) {
            emptyMap()
        }
    }

    fun put(context: Context, key: String, annotation: FindingAnnotation): Map<String, FindingAnnotation> {
        val updated = load(context).toMutableMap()
        if (annotation.isDefault) updated.remove(key) else updated[key] = annotation
        save(context, updated)
        return updated
    }

    private fun save(context: Context, annotations: Map<String, FindingAnnotation>) {
        val root = JSONObject()
        annotations.forEach { (key, a) ->
            root.put(key, JSONObject().apply {
                put("status", a.status.name)
                put("notes", a.notes)
                put("updatedAt", a.updatedAt)
            })
        }
        prefs(context).edit().putString(KEY, root.toString()).apply()
    }

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
