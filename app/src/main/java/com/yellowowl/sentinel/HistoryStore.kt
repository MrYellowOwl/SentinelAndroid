package com.yellowowl.sentinel

import android.content.Context
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Persists the last [ScanHistoryCodec.MAX_ENTRIES] scans to a JSON file for the History screen. */
object HistoryStore {
    private const val FILE = "scan_history.json"

    private val _entries = MutableStateFlow<List<HistoryEntry>>(emptyList())
    val entries: StateFlow<List<HistoryEntry>> = _entries.asStateFlow()

    @Volatile private var loaded = false

    fun init(context: Context) {
        if (loaded) return
        synchronized(this) {
            if (loaded) return
            _entries.value = runCatching { file(context).takeIf { it.isFile }?.readText()?.let { ScanHistoryCodec.parse(it) } }
                .getOrNull().orEmpty()
            loaded = true
        }
    }

    fun record(context: Context, entry: HistoryEntry) {
        init(context)
        val updated = (listOf(entry) + _entries.value).take(ScanHistoryCodec.MAX_ENTRIES)
        _entries.value = updated
        runCatching { file(context).writeText(ScanHistoryCodec.toJson(updated)) }
    }

    fun recordNetwork(context: Context, cidr: String, devices: List<DeviceResult>, findings: List<Finding>) {
        val snapshots = Nicknames.applyNames(ScanDiffer.snapshot(devices), NicknameStore.current(context))
        record(context, ScanHistoryCodec.entryFromFindings(
            at = System.currentTimeMillis(),
            type = FindingSource.NETWORK,
            label = cidr,
            findings = findings,
            devices = snapshots
        ))
    }

    fun recordWeb(context: Context, host: String, findings: List<Finding>) {
        record(context, ScanHistoryCodec.entryFromFindings(
            at = System.currentTimeMillis(),
            type = FindingSource.WEB,
            label = host,
            findings = findings
        ))
    }

    fun clear(context: Context) {
        _entries.value = emptyList()
        runCatching { file(context).delete() }
    }

    private fun file(context: Context) = File(context.applicationContext.filesDir, FILE)
}
