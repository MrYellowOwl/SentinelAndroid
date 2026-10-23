package com.yellowowl.sentinel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class NetworkUiState(
    val range: LocalNetworkRange? = null,
    val checked: Boolean = false,
    val authorized: Boolean = false,
    val scanning: Boolean = false,
    val progress: ScanProgress? = null,
    val devices: List<DeviceResult> = emptyList(),
    val lastResult: NetworkScanResult? = null,
    val message: String? = null,
    val isError: Boolean = false,
    val rescanningIp: String? = null
)

data class WebUiState(
    val url: String = "",
    val busy: Boolean = false,
    val wpChecks: Boolean = false,
    val result: WebsiteAuditResult? = null,
    val wpDetected: Boolean? = null,
    val error: String? = null
)

private data class NetworkInfo(
    val range: LocalNetworkRange? = null,
    val checked: Boolean = false,
    val authorized: Boolean = false
)

/** Screen state. Scans themselves run in [ScanRunner]/[ScanWorker], so they outlive this ViewModel. */
class SentinelViewModel(application: Application) : AndroidViewModel(application) {
    private val app get() = getApplication<Application>()

    val findings: StateFlow<List<Finding>> = SentinelRepo.findings
    val annotations: StateFlow<Map<String, FindingAnnotation>> = SentinelRepo.annotations

    private val info = MutableStateFlow(NetworkInfo())

    val network: StateFlow<NetworkUiState> = combine(info, ScanRunner.state) { net, scan ->
        NetworkUiState(
            range = net.range,
            checked = net.checked,
            authorized = net.authorized,
            scanning = scan.scanning,
            progress = scan.progress,
            devices = scan.lastResult?.devices.orEmpty(),
            lastResult = scan.lastResult,
            message = scan.message,
            isError = scan.isError,
            rescanningIp = scan.rescanningIp
        )
    }.stateIn(viewModelScope, SharingStarted.Eagerly, NetworkUiState())

    private val _alertsEnabled = MutableStateFlow(SentinelSettings.alertsEnabled(application))
    val alertsEnabled: StateFlow<Boolean> = _alertsEnabled.asStateFlow()

    private val _scanProfile = MutableStateFlow(SentinelSettings.scanProfile(application))
    val scanProfile: StateFlow<ScanProfile> = _scanProfile.asStateFlow()

    fun setScanProfile(profile: ScanProfile) {
        SentinelSettings.setScanProfile(app, profile)
        _scanProfile.value = profile
    }

    private val _monitoring = MutableStateFlow(MonitorStore.isEnabled(application))
    val monitoring: StateFlow<Boolean> = _monitoring.asStateFlow()

    /** Returns false if monitoring couldn't be enabled (no authorized network yet). */
    fun setMonitoring(enabled: Boolean): Boolean {
        if (!enabled) {
            Monitor.disable(app)
            _monitoring.value = false
            return true
        }
        val range = network.value.range ?: return false
        if (!SentinelSettings.isAuthorized(app, range.cidr)) return false
        val baseline = network.value.devices.takeIf { it.isNotEmpty() }?.let { ScanDiffer.snapshot(it) }
        Monitor.enable(app, range.cidr, baseline)
        _monitoring.value = true
        return true
    }

    private val _web = MutableStateFlow(WebUiState())
    val web: StateFlow<WebUiState> = _web.asStateFlow()

    val vulnDb: StateFlow<VulnDbStatus> = VulnStore.status

    fun updateVulnDb() {
        if (VulnStore.status.value.updating) return
        viewModelScope.launch { VulnStore.update(app) }
    }

    // ---- Engagement scope ----
    private val _scopeText = MutableStateFlow(SentinelSettings.scopeText(application))
    val scopeText: StateFlow<String> = _scopeText.asStateFlow()
    fun setScopeText(text: String) {
        SentinelSettings.setScopeText(app, text)
        _scopeText.value = text
    }

    // ---- External intel API keys (bring-your-own) ----
    private val _shodanKey = MutableStateFlow(SentinelSettings.shodanKey(application))
    val shodanKey: StateFlow<String> = _shodanKey.asStateFlow()
    fun setShodanKey(key: String) { SentinelSettings.setShodanKey(app, key); _shodanKey.value = key }
    private val _vtKey = MutableStateFlow(SentinelSettings.virusTotalKey(application))
    val vtKey: StateFlow<String> = _vtKey.asStateFlow()
    fun setVtKey(key: String) { SentinelSettings.setVirusTotalKey(app, key); _vtKey.value = key }

    // ---- Device nicknames ----
    val nicknames: StateFlow<Map<String, String>> = NicknameStore.names
    fun setNickname(device: DeviceResult, name: String) = NicknameStore.set(app, Nicknames.keyFor(device), name)

    // ---- Scan history ----
    val history: StateFlow<List<HistoryEntry>> = HistoryStore.entries
    fun clearHistory() = HistoryStore.clear(app)

    // ---- Saved networks (per-network scan memory; independent of Findings) ----
    val savedNetworks: StateFlow<List<SavedNetwork>> = NetworkStore.networks
    fun forgetNetwork(id: String) = NetworkStore.remove(app, id)

    // ---- Scheduled scans ----
    private val _scanSchedule = MutableStateFlow(SentinelSettings.scanSchedule(application))
    val scanSchedule: StateFlow<ScanSchedule> = _scanSchedule.asStateFlow()
    fun setScanSchedule(schedule: ScanSchedule) {
        Scheduler.apply(app, schedule)
        _scanSchedule.value = schedule
    }

    // ---- Theme ----
    private val _themeLight = MutableStateFlow(SentinelSettings.themeLight(application))
    val themeLight: StateFlow<Boolean> = _themeLight.asStateFlow()

    fun setThemeLight(light: Boolean) {
        SentinelSettings.setThemeLight(app, light)
        applyTheme(light)
        _themeLight.value = light
    }

    // ---- Exploit-feed source URL ----
    private val _feedUrl = MutableStateFlow(SentinelSettings.feedUrl(application))
    val feedUrl: StateFlow<String> = _feedUrl.asStateFlow()

    fun setFeedUrl(url: String) {
        SentinelSettings.setFeedUrl(app, url)
        _feedUrl.value = SentinelSettings.feedUrl(app)
    }

    fun resetFeedUrl() {
        SentinelSettings.setFeedUrl(app, VulnFeed.DEFAULT_FEED_URL)
        _feedUrl.value = VulnFeed.DEFAULT_FEED_URL
    }

    // ---- In-app app updates (GitHub Releases) ----
    private val _appUpdate = MutableStateFlow(AppUpdateStatus(currentVersion = currentVersionName()))
    val appUpdate: StateFlow<AppUpdateStatus> = _appUpdate.asStateFlow()

    fun checkForUpdate() {
        if (_appUpdate.value.checking || _appUpdate.value.installing) return
        _appUpdate.update { it.copy(checking = true, message = null, isError = false) }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { Http.get(AppUpdateLogic.latestReleaseApiUrl(), maxBytes = 256 * 1024) }
            if (result == null || result.code !in 200..299) {
                _appUpdate.update { it.copy(checking = false, message = "Couldn't reach the update server.", isError = true) }
                return@launch
            }
            val release = AppUpdateLogic.parse(result.body)
            if (release == null) {
                _appUpdate.update { it.copy(checking = false, message = "No published release found yet.", isError = true) }
                return@launch
            }
            val newer = AppUpdateLogic.isNewer(release.versionName, _appUpdate.value.currentVersion)
            _appUpdate.update {
                it.copy(
                    checking = false,
                    available = newer,
                    latestVersion = release.versionName,
                    notes = release.notes,
                    apkUrl = release.apkUrl,
                    pageUrl = release.pageUrl,
                    message = if (newer) "Update available: v${release.versionName}" else "You're on the latest version.",
                    isError = false
                )
            }
        }
    }

    /** Downloads + installs the APK; [onFallback] opens the release page only as a last resort. */
    fun installUpdate(onFallback: (String) -> Unit) {
        val status = _appUpdate.value
        val apk = status.apkUrl
        if (status.installing) return
        if (apk == null) {
            _appUpdate.update { it.copy(message = "This release has no APK attached yet — opening the release page.", isError = true) }
            onFallback(status.pageUrl)
            return
        }
        _appUpdate.update { it.copy(installing = true) }
        viewModelScope.launch {
            val result = AppInstaller.downloadAndInstall(app, apk)
            val message = when (result) {
                AppInstaller.Result.LAUNCHED -> "Downloaded — follow the installer prompt to finish."
                AppInstaller.Result.NEEDS_PERMISSION -> "Allow Sentinel to install apps in the screen that opened, then tap Download & install again."
                AppInstaller.Result.FAILED -> "Couldn't download the update — opening the release page so you can install it manually."
            }
            _appUpdate.update { it.copy(installing = false, message = message, isError = result == AppInstaller.Result.FAILED) }
            if (result == AppInstaller.Result.FAILED) onFallback(status.pageUrl)
        }
    }

    private fun currentVersionName(): String = runCatching {
        @Suppress("DEPRECATION")
        app.packageManager.getPackageInfo(app.packageName, 0).versionName ?: "0"
    }.getOrDefault("0")

    fun refreshNetwork() {
        viewModelScope.launch {
            val range = withContext(Dispatchers.IO) { NetworkScanner.detectLocalNetwork(app) }
            info.value = NetworkInfo(
                range = range,
                checked = true,
                authorized = range != null && SentinelSettings.isAuthorized(app, range.cidr)
            )
        }
    }

    /** Authorization is remembered per network (CIDR), which also allows watch-triggered scans there. */
    fun setAuthorized(authorized: Boolean) {
        val cidr = info.value.range?.cidr ?: return
        SentinelSettings.setAuthorized(app, cidr, authorized)
        info.update { it.copy(authorized = authorized) }
    }

    fun startScan() {
        val result = ScanRunner.request(app)
        if (result == ScanRequestResult.NO_NETWORK || result == ScanRequestResult.NOT_AUTHORIZED) refreshNetwork()
    }

    fun cancelScan() = ScanRunner.cancel(app)

    fun setAlertsEnabled(enabled: Boolean) {
        SentinelSettings.setAlertsEnabled(app, enabled)
        _alertsEnabled.value = enabled
    }

    fun setUrl(value: String) {
        _web.update { it.copy(url = value, error = null) }
    }

    fun setWpChecks(enabled: Boolean) {
        _web.update { it.copy(wpChecks = enabled) }
    }

    fun runAudit() {
        val state = _web.value
        if (state.busy || state.url.isBlank()) return
        _web.update { it.copy(busy = true, error = null, result = null, wpDetected = null) }
        viewModelScope.launch {
            try {
                val result = WebsiteAuditor.audit(state.url)
                val scope = result.findings.firstOrNull()?.scope ?: WebChecks.scopeFor(WebChecks.normalizeUrl(state.url))
                var findings = result.findings
                var wpDetected: Boolean? = null
                if (state.wpChecks) {
                    val wp = WpAudit.audit(scope, scope, VulnStore.matcher())
                    wpDetected = wp.isWordPress
                    if (wp.findings.isNotEmpty()) findings = FindingMerge.prioritized(findings + wp.findings)
                }
                SentinelRepo.replaceRun(FindingSource.WEB, scope, findings)
                HistoryStore.recordWeb(app, scope, findings)
                _web.update { it.copy(busy = false, result = result.copy(findings = findings), wpDetected = wpDetected) }
                Notifier.websiteAuditComplete(app, scope, findings)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                _web.update { it.copy(busy = false, error = WebChecks.friendlyError(error)) }
            }
        }
    }

    fun dismissFinding(id: String) {
        viewModelScope.launch { SentinelRepo.remove(id) }
    }

    fun setFindingStatus(finding: Finding, status: FindingStatus) {
        val current = annotations.value[finding.key] ?: FindingAnnotation()
        SentinelRepo.setAnnotation(finding.key, current.copy(status = status, updatedAt = System.currentTimeMillis()))
    }

    fun setFindingNotes(finding: Finding, notes: String) {
        val current = annotations.value[finding.key] ?: FindingAnnotation()
        SentinelRepo.setAnnotation(finding.key, current.copy(notes = notes, updatedAt = System.currentTimeMillis()))
    }

    fun rescanHost(ip: String) {
        viewModelScope.launch { ScanRunner.rescanHost(app, ip) }
    }

    fun clearFindings() {
        viewModelScope.launch { SentinelRepo.clear() }
    }
}
