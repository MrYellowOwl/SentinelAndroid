@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.yellowowl.sentinel

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applyTheme(SentinelSettings.themeLight(this))
        enableEdgeToEdge()
        setContent {
            SentinelTheme {
                SentinelApp()
            }
        }
    }
}

internal enum class AppScreen(val label: String, val icon: ImageVector) {
    Dashboard("Home", Icons.Filled.Dashboard),
    Network("Network", Icons.Filled.Router),
    Website("Web", Icons.Filled.Language),
    Tools("Tools", Icons.Filled.Build),
    Findings("Findings", Icons.Filled.Assessment)
}

@Composable
private fun SentinelApp(vm: SentinelViewModel = viewModel()) {
    val context = LocalContext.current
    val findings by vm.findings.collectAsState()
    val network by vm.network.collectAsState()
    val web by vm.web.collectAsState()
    val alertsEnabled by vm.alertsEnabled.collectAsState()
    val vulnDb by vm.vulnDb.collectAsState()
    val annotations by vm.annotations.collectAsState()
    val scanProfile by vm.scanProfile.collectAsState()
    val monitoring by vm.monitoring.collectAsState()
    val themeLight by vm.themeLight.collectAsState()
    val feedUrl by vm.feedUrl.collectAsState()
    val appUpdate by vm.appUpdate.collectAsState()
    val scanSchedule by vm.scanSchedule.collectAsState()
    val history by vm.history.collectAsState()
    val savedNetworks by vm.savedNetworks.collectAsState()
    val nicknames by vm.nicknames.collectAsState()
    val scopeText by vm.scopeText.collectAsState()
    val shodanKey by vm.shodanKey.collectAsState()
    val vtKey by vm.vtKey.collectAsState()
    val cloudLookup by vm.cloudLookup.collectAsState()
    val fingerbankKey by vm.fingerbankKey.collectAsState()
    val pagespeedKey by vm.pagespeedKey.collectAsState()
    val webSecurityMode by vm.webSecurityMode.collectAsState()
    val webProjects by vm.webProjects.collectAsState()
    var screen by rememberSaveable { mutableStateOf(AppScreen.Dashboard) }
    var findingsFilter by rememberSaveable { mutableStateOf<Severity?>(null) }
    var hostDetailIp by rememberSaveable { mutableStateOf<String?>(null) }
    var showSettings by rememberSaveable { mutableStateOf(false) }
    var showHistory by rememberSaveable { mutableStateOf(false) }
    var savedReportHtml by rememberSaveable { mutableStateOf<String?>(null) }

    val copyText: (String) -> Unit = { text ->
        runCatching {
            val clip = context.getSystemService(ClipboardManager::class.java)
            clip?.setPrimaryClip(ClipData.newPlainText("Sentinel", text))
        }
        Toast.makeText(context, "Copied: $text", Toast.LENGTH_SHORT).show()
    }
    val openUrl: (String) -> Unit = { url ->
        val opened = runCatching {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }.isSuccess
        if (!opened) Toast.makeText(context, "No app can open that link.", Toast.LENGTH_SHORT).show()
    }

    val exportReport: (ReportExporter.Format) -> Unit = { format ->
        when {
            findings.isEmpty() -> Toast.makeText(context, "Nothing to export yet. Run a scan first.", Toast.LENGTH_SHORT).show()
            !ReportExporter.share(context, findings, format) ->
                Toast.makeText(context, "No app is available to share the ${format.label}.", Toast.LENGTH_SHORT).show()
        }
    }

    val notificationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        vm.setAlertsEnabled(granted)
        if (!granted) {
            Toast.makeText(context, "Notifications are blocked. Allow them in Android Settings to get alerts.", Toast.LENGTH_LONG).show()
        }
    }
    val onAlertsChange: (Boolean) -> Unit = { enable ->
        val needsPermission = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        when {
            !enable -> vm.setAlertsEnabled(false)
            needsPermission -> notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            else -> vm.setAlertsEnabled(true)
        }
    }

    BackHandler(enabled = savedReportHtml != null || showHistory || showSettings || hostDetailIp != null || screen != AppScreen.Dashboard) {
        when {
            savedReportHtml != null -> savedReportHtml = null
            showHistory -> showHistory = false
            showSettings -> showSettings = false
            hostDetailIp != null -> hostDetailIp = null
            else -> screen = AppScreen.Dashboard
        }
    }

    Scaffold(
        containerColor = Bg,
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Filled.Shield, contentDescription = null, tint = Accent, modifier = Modifier.size(24.dp))
                        Text("SENTINEL", fontWeight = FontWeight.Black, letterSpacing = 2.sp, fontSize = 19.sp)
                    }
                },
                actions = {
                    IconButton(onClick = { exportReport(ReportExporter.Format.HTML) }, enabled = findings.isNotEmpty()) {
                        Icon(Icons.Filled.Share, contentDescription = "Share report", tint = if (findings.isNotEmpty()) TextMuted else Border)
                    }
                    IconButton(onClick = { showSettings = true; vm.checkForUpdate() }) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings", tint = TextMuted)
                    }
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(containerColor = Bg, titleContentColor = TextMain)
            )
        },
        bottomBar = {
            NavigationBar(containerColor = SurfaceColor) {
                AppScreen.entries.forEach { item ->
                    NavigationBarItem(
                        selected = screen == item,
                        onClick = { screen = item },
                        icon = {
                            val busy = (item == AppScreen.Network && network.scanning) || (item == AppScreen.Website && web.busy)
                            if (busy) {
                                BadgedBox(badge = { Badge(containerColor = Accent) }) { Icon(item.icon, contentDescription = item.label) }
                            } else {
                                Icon(item.icon, contentDescription = item.label)
                            }
                        },
                        label = { Text(item.label, fontSize = 12.sp) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = Accent,
                            selectedTextColor = Accent,
                            indicatorColor = NavIndicator,
                            unselectedIconColor = TextMuted,
                            unselectedTextColor = TextMuted
                        )
                    )
                }
            }
        }
    ) { padding ->
        val modifier = Modifier.padding(padding).consumeWindowInsets(padding)
        savedReportHtml?.let { html ->
            SavedReportScreen(modifier = modifier, html = html, onBack = { savedReportHtml = null })
            return@Scaffold
        }
        if (showHistory) {
            HistoryScreen(
                modifier = modifier,
                entries = history,
                onClear = vm::clearHistory,
                onBack = { showHistory = false }
            )
            return@Scaffold
        }
        if (showSettings) {
            SettingsScreen(
                modifier = modifier,
                themeLight = themeLight,
                onThemeChange = vm::setThemeLight,
                vulnDb = vulnDb,
                onUpdateDb = vm::updateVulnDb,
                feedUrl = feedUrl,
                onFeedUrl = vm::setFeedUrl,
                onResetFeed = vm::resetFeedUrl,
                appUpdate = appUpdate,
                onCheckUpdate = vm::checkForUpdate,
                onInstallUpdate = { vm.installUpdate(onFallback = openUrl) },
                scanSchedule = scanSchedule,
                onScheduleChange = vm::setScanSchedule,
                scopeText = scopeText,
                onScopeChange = vm::setScopeText,
                shodanKey = shodanKey,
                onShodanChange = vm::setShodanKey,
                vtKey = vtKey,
                onVtChange = vm::setVtKey,
                cloudLookup = cloudLookup,
                onCloudLookupChange = vm::setCloudLookup,
                fingerbankKey = fingerbankKey,
                onFingerbankChange = vm::setFingerbankKey,
                pagespeedKey = pagespeedKey,
                onPagespeedChange = vm::setPagespeedKey,
                webSecurityMode = webSecurityMode,
                onWebModeChange = vm::setWebSecurityMode,
                historyCount = history.size,
                onOpenHistory = { showHistory = true },
                onBack = { showSettings = false },
                onCopy = copyText,
                onOpenUrl = openUrl
            )
            return@Scaffold
        }
        val detailDevice = hostDetailIp?.let { ip -> network.devices.firstOrNull { it.ipAddress == ip } }
        if (hostDetailIp != null && detailDevice != null) {
            val detailSaved = run {
                val mac = detailDevice.mac?.trim()?.lowercase()?.takeIf { it.isNotBlank() }
                savedNetworks.flatMap { it.devices }.firstOrNull { sd ->
                    (mac != null && sd.mac?.trim()?.lowercase() == mac) || sd.ip == detailDevice.ipAddress
                }
            }
            HostDetailScreen(
                modifier = modifier,
                device = detailDevice,
                findings = findings.filter { it.hostIp == detailDevice.ipAddress },
                annotations = annotations,
                rescanning = network.rescanningIp == detailDevice.ipAddress,
                nickname = nicknames[Nicknames.keyFor(detailDevice)],
                onSetNickname = { vm.setNickname(detailDevice, it) },
                saved = detailSaved,
                shodanKey = shodanKey,
                vtKey = vtKey,
                onBack = { hostDetailIp = null },
                onRescan = { vm.rescanHost(detailDevice.ipAddress) },
                onStatus = vm::setFindingStatus,
                onNotes = vm::setFindingNotes,
                onCopy = copyText,
                onOpenUrl = openUrl
            )
            return@Scaffold
        }
        when (screen) {
            AppScreen.Dashboard -> DashboardScreen(
                modifier = modifier,
                findings = findings,
                alertsEnabled = alertsEnabled,
                onAlertsChange = onAlertsChange,
                onOpen = { screen = it },
                onOpenFindings = { filter ->
                    findingsFilter = filter
                    screen = AppScreen.Findings
                }
            )
            AppScreen.Network -> NetworkScreen(
                modifier = modifier,
                state = network,
                onAppear = vm::refreshNetwork,
                onAuthorize = vm::setAuthorized,
                onStart = vm::startScan,
                onCancel = vm::cancelScan,
                profile = scanProfile,
                onSetProfile = vm::setScanProfile,
                monitoring = monitoring,
                nicknames = nicknames,
                savedNetworks = savedNetworks,
                onForgetNetwork = vm::forgetNetwork,
                onMonitorChange = { enable ->
                    if (!vm.setMonitoring(enable) && enable) {
                        Toast.makeText(context, "Scan and confirm authorization first, then enable monitoring.", Toast.LENGTH_LONG).show()
                    } else if (enable) {
                        Toast.makeText(context, "Monitoring on. Turn on alerts (Home) to get change notifications.", Toast.LENGTH_LONG).show()
                    }
                },
                onOpenHost = { hostDetailIp = it },
                onViewFindings = {
                    findingsFilter = null
                    screen = AppScreen.Findings
                }
            )
            AppScreen.Website -> WebsiteAuditScreen(
                modifier = modifier,
                state = web,
                securityMode = webSecurityMode,
                onUrlChange = vm::setUrl,
                onWpChecksChange = vm::setWpChecks,
                onRun = vm::runAudit,
                onShareSite = { fmt -> web.siteProfile?.let { if (!ReportExporter.shareSite(context, it, fmt)) Toast.makeText(context, "No app available to share the report.", Toast.LENGTH_SHORT).show() } },
                onPrintSite = { web.siteProfile?.let { ReportExporter.printSitePdf(context, it) } },
                onOpenUrl = openUrl,
                onCopy = copyText,
                projects = webProjects,
                onSaveClient = {
                    if (vm.saveCurrentIntake()) Toast.makeText(context, "Saved to client projects.", Toast.LENGTH_SHORT).show()
                    else Toast.makeText(context, "Run an audit first, then save.", Toast.LENGTH_SHORT).show()
                },
                onViewSaved = { savedReportHtml = it },
                onRerun = vm::rerunIntake,
                onDeleteProject = vm::removeWebProject
            )
            AppScreen.Tools -> ToolsScreen(
                modifier = modifier,
                onCopy = copyText,
                shodanKey = shodanKey,
                vtKey = vtKey
            )
            AppScreen.Findings -> FindingsScreen(
                modifier = modifier,
                findings = findings,
                filter = findingsFilter,
                vulnDb = vulnDb,
                onUpdateDb = vm::updateVulnDb,
                onFilter = { findingsFilter = it },
                onExport = exportReport,
                onPrintPdf = {
                    if (findings.isEmpty()) Toast.makeText(context, "Nothing to export yet. Run a scan first.", Toast.LENGTH_SHORT).show()
                    else ReportExporter.printPdf(context, findings)
                },
                onClear = vm::clearFindings,
                onDismiss = vm::dismissFinding
            )
        }
    }
}
