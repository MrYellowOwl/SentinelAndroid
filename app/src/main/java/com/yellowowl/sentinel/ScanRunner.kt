package com.yellowowl.sentinel

import android.content.Context
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext

data class ScanState(
    val scanning: Boolean = false,
    val progress: ScanProgress? = null,
    val lastResult: NetworkScanResult? = null,
    val message: String? = null,
    val isError: Boolean = false,
    val rescanningIp: String? = null
)

enum class ScanRequestResult { QUEUED, ALREADY_RUNNING, NO_NETWORK, NOT_AUTHORIZED }

/**
 * Single scan engine for every trigger (phone UI, notification action, watch).
 * Scans execute inside [ScanWorker] so Android keeps the app alive even if it's in the background.
 */
object ScanRunner {
    private const val NO_NETWORK_MESSAGE = "Connect the phone to a private Wi-Fi or Ethernet network first."

    private val _state = MutableStateFlow(ScanState())
    val state: StateFlow<ScanState> = _state.asStateFlow()

    @Volatile private var lastPublishedStep = ""

    /** Validates the network and queues a scan. Safe to call from the main thread. */
    fun request(context: Context): ScanRequestResult {
        val app = context.applicationContext
        if (_state.value.scanning) return ScanRequestResult.ALREADY_RUNNING
        val range = NetworkScanner.detectLocalNetwork(app)
        if (range == null) {
            fail(app, NO_NETWORK_MESSAGE)
            return ScanRequestResult.NO_NETWORK
        }
        if (!SentinelSettings.isAuthorized(app, range.cidr)) {
            fail(app, notAuthorizedMessage(range.cidr))
            return ScanRequestResult.NOT_AUTHORIZED
        }
        _state.update { it.copy(scanning = true, progress = null, message = "Starting scan…", isError = false) }
        WatchSync.publish(app)
        ScanWorker.enqueue(app)
        return ScanRequestResult.QUEUED
    }

    fun cancel(context: Context) {
        val app = context.applicationContext
        ScanWorker.cancel(app)
        // The worker may not have started yet, so reset state here as well.
        _state.update { it.copy(scanning = false, progress = null, message = "Scan cancelled.", isError = false) }
        WatchSync.publish(app)
    }

    /** Runs the scan to completion. Called by [ScanWorker]. */
    suspend fun runNow(context: Context) {
        val app = context.applicationContext
        val range = withContext(Dispatchers.IO) { NetworkScanner.detectLocalNetwork(app) }
        if (range == null) {
            fail(app, NO_NETWORK_MESSAGE)
            return
        }
        if (!SentinelSettings.isAuthorized(app, range.cidr)) {
            fail(app, notAuthorizedMessage(range.cidr))
            return
        }

        lastPublishedStep = ""
        _state.value = ScanState(scanning = true)
        WatchSync.publish(app)
        try {
            val profile = SentinelSettings.scanProfile(app)
            val scanned = NetworkScanner.scanLocalNetwork(range, app, profile) { progress -> onProgress(app, progress) }
            // Opt-in only: fill maker/model gaps from online sources. A no-op (and no network) when disabled.
            val result = DeviceCloud.enrich(scanned, SentinelSettings.cloudLookupEnabled(app), SentinelSettings.fingerbankKey(app))
            // Open-port risks plus any CVEs that match the fingerprinted service versions.
            val cveFindings = result.devices.flatMap { VulnStore.matcher().findingsFor(result.cidr, it) }
            val run = NetworkFindings.from(result) + cveFindings
            SentinelRepo.replaceRun(FindingSource.NETWORK, result.cidr, run)
            SentinelSettings.saveLastScan(app, SentinelSettings.LastScan(result.cidr, System.currentTimeMillis(), result.devices.size))
            HistoryStore.recordNetwork(app, result.cidr, result.devices, run)
            // Persist this scan into the per-network memory (independent of Findings).
            NetworkStore.recordScan(app, range, result)
            // Keep the monitoring baseline fresh so background checks diff against the latest manual scan.
            if (MonitorStore.isEnabled(app) && MonitorStore.monitoredCidr(app) == result.cidr) {
                MonitorStore.saveBaseline(app, result.cidr, ScanDiffer.snapshot(result.devices))
            }
            val seconds = "%.1f".format(result.durationMillis / 1000.0)
            _state.value = ScanState(
                scanning = false,
                lastResult = result,
                message = "Found ${result.devices.size} device(s) in $seconds s · ${run.size} issue(s) saved to Findings."
            )
            Notifier.networkScanComplete(app, result, run)
        } catch (cancelled: CancellationException) {
            _state.update { it.copy(scanning = false, progress = null, message = "Scan cancelled.", isError = false) }
            throw cancelled
        } catch (error: Exception) {
            _state.update { it.copy(scanning = false, progress = null, message = error.message ?: "The scan couldn't complete.", isError = true) }
        } finally {
            WatchSync.publish(app)
        }
    }

    /** Rescans just one host and updates its findings in place. For the walkthrough "re-scan" action. */
    suspend fun rescanHost(context: Context, ip: String) {
        val app = context.applicationContext
        val range = withContext(Dispatchers.IO) { NetworkScanner.detectLocalNetwork(app) }
        if (range == null || !SentinelSettings.isAuthorized(app, range.cidr)) {
            _state.update { it.copy(message = "Can't rescan: reconnect and confirm authorization on the Network tab.", isError = true) }
            return
        }
        _state.update { it.copy(rescanningIp = ip) }
        try {
            val prior = _state.value.lastResult?.devices?.firstOrNull { it.ipAddress == ip }?.identity
            val device = NetworkScanner.scanHost(range, ip, prior, SentinelSettings.scanProfile(app))
            val run = NetworkFindings.from(NetworkScanResult(range.cidr, 1, listOf(device), 0)) +
                VulnStore.matcher().findingsFor(range.cidr, device)
            SentinelRepo.replaceHost(FindingSource.NETWORK, range.cidr, ip, run)
            // Reflect the fresh device in the last result so the walkthrough list updates.
            _state.update { state ->
                val last = state.lastResult ?: return@update state.copy(rescanningIp = null)
                val devices = last.devices.map { if (it.ipAddress == ip) device else it }
                state.copy(lastResult = last.copy(devices = devices), rescanningIp = null)
            }
        } catch (cancelled: CancellationException) {
            _state.update { it.copy(rescanningIp = null) }
            throw cancelled
        } catch (error: Exception) {
            _state.update { it.copy(rescanningIp = null, message = error.message ?: "Rescan failed.", isError = true) }
        }
    }

    private fun onProgress(app: Context, progress: ScanProgress) {
        _state.update { if (it.scanning) it.copy(progress = progress, message = null) else it }
        // Update the watch at most once per 10% step.
        val step = "${progress.phase}:${(progress.overall * 10).toInt()}"
        if (step != lastPublishedStep) {
            lastPublishedStep = step
            WatchSync.publish(app)
        }
    }

    private fun fail(app: Context, message: String) {
        _state.update { it.copy(scanning = false, progress = null, message = message, isError = true) }
        WatchSync.publish(app)
    }

    private fun notAuthorizedMessage(cidr: String) =
        "Open Sentinel on your phone and confirm you're authorized to scan $cidr."
}
