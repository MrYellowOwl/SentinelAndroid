@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.yellowowl.sentinel

import android.text.format.DateUtils
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.Print
import androidx.compose.material.icons.filled.Tv
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Laptop
import androidx.compose.material.icons.filled.Build
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.font.FontFamily
import kotlinx.coroutines.launch
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import androidx.compose.ui.platform.LocalContext
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.rememberLauncherForActivityResult
import android.Manifest

// ---------------------------------------------------------------- Dashboard

@Composable
internal fun DashboardScreen(
    modifier: Modifier,
    findings: List<Finding>,
    alertsEnabled: Boolean,
    onAlertsChange: (Boolean) -> Unit,
    onOpen: (AppScreen) -> Unit,
    onOpenFindings: (Severity?) -> Unit
) {
    val counts = FindingMerge.countBySeverity(findings)
    val high = counts[Severity.HIGH] ?: 0
    val medium = counts[Severity.MEDIUM] ?: 0
    val low = counts[Severity.LOW] ?: 0
    val priorities = FindingMerge.prioritized(findings).filter { it.severity != Severity.INFO }.take(3)

    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Eyebrow("SECURITY OVERVIEW")
        Text("Your security,\nat a glance.", fontSize = 30.sp, lineHeight = 34.sp, fontWeight = FontWeight.Bold, color = TextMain)

        val (postureIcon, postureColor, postureTitle, postureText) = when {
            findings.isEmpty() -> Quad(Icons.Filled.Lock, Accent, "No scans yet", "Scan your Wi-Fi network or audit a website to see your security picture.")
            high > 0 -> Quad(Icons.Filled.WarningAmber, HighColor, "$high high-severity issue(s)", "Fix these first. Each finding includes a recommended action.")
            medium > 0 -> Quad(Icons.Filled.WarningAmber, MediumColor, "$medium issue(s) worth reviewing", "No high-severity issues. Review the medium findings when you can.")
            else -> Quad(Icons.Filled.CheckCircle, Accent, "No high or medium issues", "Nice. Re-run your scans after changes to your network or website.")
        }
        SurfaceCard(border = BorderStroke(1.dp, postureColor.copy(alpha = 0.45f))) {
            Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(48.dp).background(postureColor.copy(alpha = 0.15f), CircleShape), contentAlignment = Alignment.Center) {
                    Icon(postureIcon, contentDescription = null, tint = postureColor, modifier = Modifier.size(26.dp))
                }
                Spacer(Modifier.width(13.dp))
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(postureTitle, fontWeight = FontWeight.Bold, color = TextMain, fontSize = 16.sp)
                    Text(postureText, fontSize = 13.sp, color = TextMuted, lineHeight = 18.sp)
                }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
            StatCard("High", high, HighColor, Modifier.weight(1f)) { onOpenFindings(Severity.HIGH) }
            StatCard("Medium", medium, MediumColor, Modifier.weight(1f)) { onOpenFindings(Severity.MEDIUM) }
            StatCard("Low", low, LowColor, Modifier.weight(1f)) { onOpenFindings(Severity.LOW) }
        }

        if (priorities.isNotEmpty()) {
            SectionHeader("TOP PRIORITIES", "Start here")
            priorities.forEach { finding ->
                SurfaceCard(onClick = { onOpenFindings(null) }) {
                    Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                        SeverityBadge(finding.severity)
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(finding.title, color = TextMain, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            Text(finding.target, color = TextMuted, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                        Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null, tint = TextMuted)
                    }
                }
            }
        }

        SectionHeader("TOOLS", "Run a check")
        NavToolCard(
            title = "Network scan",
            subtitle = "Find devices on your Wi-Fi and spot risky open services.",
            icon = Icons.Filled.Router,
            onClick = { onOpen(AppScreen.Network) }
        )
        NavToolCard(
            title = "Website audit",
            subtitle = "Check HTTPS, certificate expiry, security headers and cookies.",
            icon = Icons.Filled.Language,
            onClick = { onOpen(AppScreen.Website) }
        )
        NavToolCard(
            title = "Findings & reports",
            subtitle = "Review issues by priority and share an HTML report.",
            icon = Icons.Filled.Assessment,
            onClick = { onOpenFindings(null) }
        )

        SurfaceCard {
            Row(
                Modifier
                    .fillMaxWidth()
                    .toggleable(value = alertsEnabled, role = Role.Switch, onValueChange = onAlertsChange)
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Filled.NotificationsActive, contentDescription = null, tint = Accent, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text("Alerts on phone & watch", color = TextMain, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Text(
                        "Notify me when a network scan finishes or finds high-severity issues. Paired Galaxy and Wear OS watches show these too.",
                        color = TextMuted, fontSize = 12.sp, lineHeight = 17.sp
                    )
                }
                Spacer(Modifier.width(8.dp))
                Switch(
                    checked = alertsEnabled,
                    onCheckedChange = null,
                    colors = SwitchDefaults.colors(checkedThumbColor = OnAccent, checkedTrackColor = Accent)
                )
            }
        }

        SurfaceCard {
            Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Lock, contentDescription = null, tint = Accent, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(10.dp))
                Text(
                    "Private by design: results stay on this phone. No accounts, no tracking, nothing uploaded unless you share a report.",
                    fontSize = 12.sp, color = TextMuted, lineHeight = 17.sp
                )
            }
        }
        Text(
            "Sentinel ${BuildConfig.VERSION_NAME} · Automated checks are indicators, not proof of exploitability. Only test systems you own or are authorized to assess.",
            color = TextMuted, fontSize = 11.sp, lineHeight = 16.sp
        )
        Spacer(Modifier.height(4.dp))
    }
}

private data class Quad(val icon: ImageVector, val color: Color, val title: String, val text: String)

@Composable
private fun StatCard(title: String, value: Int, tint: Color, modifier: Modifier, onClick: () -> Unit) {
    SurfaceCard(modifier = modifier, onClick = onClick) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(value.toString(), fontSize = 26.sp, fontWeight = FontWeight.Bold, color = if (value > 0) tint else TextMain)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(8.dp).background(tint, CircleShape))
                Spacer(Modifier.width(6.dp))
                Text(title, fontSize = 12.sp, color = TextMuted)
            }
        }
    }
}

@Composable
private fun NavToolCard(title: String, subtitle: String, icon: ImageVector, onClick: () -> Unit) {
    SurfaceCard(onClick = onClick) {
        Row(Modifier.fillMaxWidth().padding(15.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(46.dp).background(SurfaceRaised, RoundedCornerShape(14.dp)), contentAlignment = Alignment.Center) {
                Icon(icon, contentDescription = null, tint = Accent, modifier = Modifier.size(24.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(title, color = TextMain, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                Text(subtitle, color = TextMuted, fontSize = 13.sp, lineHeight = 18.sp)
            }
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null, tint = TextMuted)
        }
    }
}

// ---------------------------------------------------------------- Network

@Composable
internal fun NetworkScreen(
    modifier: Modifier,
    state: NetworkUiState,
    onAppear: () -> Unit,
    onAuthorize: (Boolean) -> Unit,
    onStart: () -> Unit,
    onCancel: () -> Unit,
    profile: ScanProfile,
    onSetProfile: (ScanProfile) -> Unit,
    monitoring: Boolean,
    onMonitorChange: (Boolean) -> Unit,
    nicknames: Map<String, String>,
    savedNetworks: List<SavedNetwork> = emptyList(),
    onForgetNetwork: (String) -> Unit = {},
    onOpenHost: (String) -> Unit,
    onViewFindings: () -> Unit
) {
    LaunchedEffect(Unit) { onAppear() }
    val range = state.range

    // The saved network that matches what we're connected to now (best-effort by subnet/gateway).
    val currentId = remember(savedNetworks, range) {
        savedNetworks.firstOrNull { it.cidr != null && it.cidr == range?.cidr }?.id
            ?: savedNetworks.firstOrNull()?.id
    }
    var selectedId by rememberSaveable(currentId) { mutableStateOf(currentId) }
    val selected = savedNetworks.firstOrNull { it.id == selectedId } ?: savedNetworks.firstOrNull { it.id == currentId }
    val isCurrent = selected == null || selected.id == currentId
    var forgetTarget by rememberSaveable { mutableStateOf<String?>(null) }
    var onlineOnly by rememberSaveable { mutableStateOf(false) }
    var sortOrdinal by rememberSaveable { mutableStateOf(0) }   // Int is always Bundle-savable
    val sortMode = DeviceSort.entries.getOrElse(sortOrdinal) { DeviceSort.IP }

    forgetTarget?.let { id ->
        val net = savedNetworks.firstOrNull { it.id == id }
        AlertDialog(
            onDismissRequest = { forgetTarget = null },
            title = { Text("Forget this network?") },
            text = { Text("Removes the saved device list for \"${net?.label ?: "this network"}\". Findings are not affected. You can rescan to rebuild it.") },
            confirmButton = { TextButton(onClick = { forgetTarget = null; onForgetNetwork(id) }) { Text("Forget", color = HighColor) } },
            dismissButton = { TextButton(onClick = { forgetTarget = null }) { Text("Cancel") } },
            containerColor = SurfaceColor
        )
    }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { ScreenHeading("Network scan", "Finds devices on your current Wi-Fi and checks common services.") }
        item {
            SurfaceCard {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Eyebrow("CURRENT NETWORK")
                            Text(
                                range?.cidr ?: if (state.checked) "No Wi-Fi network found" else "Checking…",
                                color = TextMain, fontSize = 20.sp, fontWeight = FontWeight.Bold
                            )
                        }
                        IconButton(onClick = onAppear, enabled = !state.scanning) {
                            Icon(Icons.Filled.Refresh, contentDescription = "Re-detect network", tint = TextMuted)
                        }
                    }
                    if (range != null) {
                        Text(
                            buildString {
                                append("Your phone is ${range.phoneIp}")
                                range.gatewayIp?.let { append(", router is $it") }
                                append(".\nSentinel looks at the ${range.hostCount} addresses on this network.")
                            },
                            color = TextMuted, fontSize = 13.sp, lineHeight = 19.sp
                        )
                    } else if (state.checked) {
                        Row(verticalAlignment = Alignment.Top) {
                            Icon(Icons.Filled.WifiOff, contentDescription = null, tint = TextMuted, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(
                                "Connect to a private Wi-Fi or Ethernet network, then tap refresh. Mobile data and public addresses can't be scanned.",
                                color = TextMuted, fontSize = 13.sp, lineHeight = 18.sp
                            )
                        }
                    }
                    HorizontalDivider(color = Border)
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .toggleable(
                                value = state.authorized,
                                enabled = range != null && !state.scanning,
                                role = Role.Checkbox,
                                onValueChange = onAuthorize
                            ),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(
                            checked = state.authorized,
                            onCheckedChange = null,
                            enabled = range != null && !state.scanning,
                            colors = CheckboxDefaults.colors(checkedColor = Accent, checkmarkColor = OnAccent)
                        )
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text("I own this network or have permission to scan it.", color = TextMain, fontSize = 13.sp, lineHeight = 18.sp)
                            Text("Remembered for this network. Also allows scans started from your watch.", color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                        }
                    }
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("SCAN DEPTH", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.2.sp)
                        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            ScanProfile.entries.forEach { p ->
                                FilterChip(
                                    selected = profile == p,
                                    onClick = { if (!state.scanning) onSetProfile(p) },
                                    enabled = !state.scanning,
                                    label = { Text("${p.label} · ${p.blurb}", fontSize = 11.sp) },
                                    colors = FilterChipDefaults.filterChipColors(
                                        containerColor = SurfaceRaised, labelColor = TextMuted,
                                        selectedContainerColor = Accent.copy(alpha = 0.18f), selectedLabelColor = Accent
                                    ),
                                    border = FilterChipDefaults.filterChipBorder(enabled = true, selected = profile == p, borderColor = Border, selectedBorderColor = Accent.copy(alpha = 0.6f))
                                )
                            }
                        }
                    }
                    if (state.scanning) {
                        OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth(), border = BorderStroke(1.dp, Border)) {
                            Icon(Icons.Filled.Stop, contentDescription = null, tint = TextMain)
                            Spacer(Modifier.width(8.dp))
                            Text("Cancel scan", color = TextMain, fontWeight = FontWeight.Bold)
                        }
                        val progress = state.progress
                        Text(
                            progress?.let { "${it.phase}… ${(it.overall * 100).toInt()}%" } ?: (state.message ?: "Starting…"),
                            color = TextMuted, fontSize = 13.sp
                        )
                        if (progress != null) {
                            LinearProgressIndicator(
                                progress = { progress.overall },
                                modifier = Modifier.fillMaxWidth(),
                                color = Accent,
                                trackColor = SurfaceRaised
                            )
                        } else {
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = Accent, trackColor = SurfaceRaised)
                        }
                        Text("The scan keeps running if you switch tabs or leave the app.", color = TextMuted, fontSize = 12.sp)
                    } else {
                        PrimaryButton(
                            text = "Start scan",
                            icon = Icons.Filled.PlayArrow,
                            enabled = range != null && state.authorized,
                            onClick = onStart
                        )
                        if (range != null && !state.authorized) {
                            Text("Tick the box above to enable scanning.", color = TextMuted, fontSize = 12.sp)
                        }
                    }
                    if (!state.scanning) {
                        state.message?.let {
                            Text(it, color = if (state.isError) HighColor else Accent, fontSize = 13.sp, lineHeight = 18.sp)
                        }
                    }
                    if (state.lastResult != null && !state.scanning) {
                        TextButton(onClick = onViewFindings, contentPadding = PaddingValues(0.dp)) {
                            Text("View issues in Findings", color = Accent)
                            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null, tint = Accent)
                        }
                    }
                    HorizontalDivider(color = Border)
                    Row(
                        Modifier.fillMaxWidth().toggleable(value = monitoring, enabled = state.authorized || monitoring, role = Role.Switch, onValueChange = onMonitorChange),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text("Monitor this network", color = TextMain, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                            Text(
                                if (monitoring) "Rescanning every ~30 min · alerts on new devices and port changes." else "Background rescans that alert when a new device joins or a port opens.",
                                color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp
                            )
                        }
                        Spacer(Modifier.width(8.dp))
                        Switch(checked = monitoring, onCheckedChange = null, enabled = state.authorized || monitoring, colors = SwitchDefaults.colors(checkedThumbColor = OnAccent, checkedTrackColor = Accent))
                    }
                }
            }
        }
        // Saved-networks switcher: pick any network you've scanned before (survives restarts).
        if (savedNetworks.size > 1) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Eyebrow("SAVED NETWORKS · ${savedNetworks.size}")
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        savedNetworks.forEach { net ->
                            FilterChip(
                                selected = net.id == selected?.id,
                                onClick = { selectedId = net.id },
                                label = { Text("${net.label} · ${net.onlineCount}/${net.deviceCount}", fontSize = 11.sp) },
                                colors = FilterChipDefaults.filterChipColors(
                                    containerColor = SurfaceRaised, labelColor = TextMuted,
                                    selectedContainerColor = Accent.copy(alpha = 0.18f), selectedLabelColor = Accent
                                ),
                                border = FilterChipDefaults.filterChipBorder(enabled = true, selected = net.id == selected?.id, borderColor = Border, selectedBorderColor = Accent.copy(alpha = 0.6f))
                            )
                        }
                    }
                }
            }
        }

        if (selected != null) {
            item {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Eyebrow("DEVICES · ${selected.onlineCount} online / ${selected.deviceCount} known")
                        Text(
                            buildString {
                                append(if (isCurrent) "This network" else selected.label)
                                append(" · last scan ")
                                append(DateUtils.getRelativeTimeSpanString(selected.lastSeen))
                            },
                            color = TextMuted, fontSize = 12.sp
                        )
                    }
                    TextButton(onClick = { forgetTarget = selected.id }) {
                        Icon(Icons.Filled.DeleteOutline, contentDescription = null, tint = TextMuted, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp)); Text("Forget", color = TextMuted, fontSize = 13.sp)
                    }
                }
            }
            // Sort + filter controls.
            item {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    DeviceSort.entries.forEach { mode ->
                        SmallToggleChip(mode.label, sortMode == mode) { sortOrdinal = mode.ordinal }
                    }
                    SmallToggleChip("Online only", onlineOnly) { onlineOnly = !onlineOnly }
                }
            }
            // One card holding the whole list, Fing-style flat rows with hairline dividers.
            item {
                val shown = selected.devices
                    .filter { !onlineOnly || it.online }
                    .sortedWith(
                        when (sortMode) {
                            DeviceSort.IP -> compareByDescending<SavedDevice> { it.isGateway }.thenBy { Ipv4.parse(it.ip) ?: Long.MAX_VALUE }
                            DeviceSort.NAME -> compareBy { it.displayName.lowercase() }
                            DeviceSort.STATUS -> compareByDescending<SavedDevice> { it.online }.thenByDescending { it.isGateway }.thenBy { Ipv4.parse(it.ip) ?: Long.MAX_VALUE }
                        }
                    )
                SurfaceCard {
                    Column(Modifier.fillMaxWidth()) {
                        if (shown.isEmpty()) {
                            Text("No devices match this filter.", color = TextMuted, fontSize = 13.sp, modifier = Modifier.padding(16.dp))
                        }
                        shown.forEachIndexed { i, d ->
                            if (i > 0) HorizontalDivider(color = Border, modifier = Modifier.padding(start = 58.dp))
                            val liveIp = if (isCurrent && state.devices.any { it.ipAddress == d.ip }) d.ip else null
                            DeviceRow(d, nicknames, onClick = liveIp?.let { ip -> { onOpenHost(ip) } })
                        }
                    }
                }
            }
        } else {
            item {
                Column {
                    Eyebrow("DEVICES · ${state.devices.size}")
                    if (state.devices.isEmpty() && !state.scanning) {
                        Text(
                            if (state.lastResult == null) "Devices will appear here after a scan. Some devices ignore all connection attempts and may not be listed."
                            else "No devices answered. Some devices ignore all connection attempts.",
                            color = TextMuted, fontSize = 13.sp, lineHeight = 18.sp, modifier = Modifier.padding(top = 6.dp)
                        )
                    }
                }
            }
            items(state.devices, key = { it.ipAddress }) { device -> DeviceCard(device, nicknames) { onOpenHost(device.ipAddress) } }
        }
    }
}

@Composable
private fun DeviceCard(device: DeviceResult, nicknames: Map<String, String>, onClick: () -> Unit) {
    val name = Nicknames.displayName(device, nicknames)
    SurfaceCard(onClick = onClick) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                val icon = when {
                    device.isThisDevice -> Icons.Filled.PhoneAndroid
                    device.isGateway -> Icons.Filled.Router
                    else -> Icons.Filled.Devices
                }
                Icon(icon, contentDescription = null, tint = Accent, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(name, color = TextMain, fontWeight = FontWeight.Bold, fontSize = 16.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    val sub = listOfNotNull(
                        device.ipAddress.takeIf { it != name },
                        device.vendor,
                        device.kind,
                        device.mac
                    )
                    if (sub.isNotEmpty()) Text(sub.joinToString(" · "), color = TextMuted, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                when {
                    device.isThisDevice -> Tag("This phone")
                    device.isGateway -> Tag("Router")
                }
            }
            if (device.openPorts.isEmpty()) {
                Text("Found via discovery; none of the checked ports are open.", color = TextMuted, fontSize = 13.sp)
            } else {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    device.openPorts.forEach { port ->
                        val tint = PortCatalog.riskFor(port.port)?.severity?.color() ?: TextMuted
                        Box(Modifier.background(SurfaceRaised, RoundedCornerShape(8.dp)).padding(horizontal = 8.dp, vertical = 5.dp)) {
                            Text("${port.service} · ${port.port}", color = tint, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
                val versions = device.openPorts.mapNotNull { it.fingerprint?.let { fp -> "${it.service}: ${fp.display}" } }
                if (versions.isNotEmpty()) {
                    Text(versions.joinToString(" · "), color = TextMuted, fontSize = 11.sp, lineHeight = 15.sp)
                }
            }
        }
    }
}

/** How the device list is ordered. */
private enum class DeviceSort(val label: String) { IP("IP"), NAME("Name"), STATUS("Status") }

/** Picks a device-type icon from the inferred kind (falls back to a generic device). */
private fun deviceIcon(d: SavedDevice): ImageVector {
    if (d.isGateway) return Icons.Filled.Router
    val k = d.kind?.lowercase() ?: return Icons.Filled.Devices
    return when {
        "router" in k || "network gear" in k || "gateway" in k -> Icons.Filled.Router
        "printer" in k -> Icons.Filled.Print
        "camera" in k -> Icons.Filled.Videocam
        "tv" in k || "media" in k -> Icons.Filled.Tv
        "nas" in k || "file share" in k -> Icons.Filled.Storage
        "windows" in k || "pc" in k -> Icons.Filled.Computer
        "server" in k || "web host" in k -> Icons.Filled.Public
        "phone" in k || "consumer" in k -> Icons.Filled.PhoneAndroid
        "smart home" in k -> Icons.Filled.Home
        "raspberry" in k || "iot" in k || "esp" in k -> Icons.Filled.Memory
        "apple" in k || "laptop" in k -> Icons.Filled.Laptop
        else -> Icons.Filled.Devices
    }
}

/** A small selectable chip used for the sort/filter controls. */
@Composable
private fun SmallToggleChip(label: String, selected: Boolean, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, fontSize = 11.sp) },
        colors = FilterChipDefaults.filterChipColors(
            containerColor = SurfaceRaised, labelColor = TextMuted,
            selectedContainerColor = Accent.copy(alpha = 0.18f), selectedLabelColor = Accent
        ),
        border = FilterChipDefaults.filterChipBorder(enabled = true, selected = selected, borderColor = Border, selectedBorderColor = Accent.copy(alpha = 0.6f))
    )
}

/** One flat, Fing-style device row (no card of its own; the list shares one card with dividers). */
@Composable
private fun DeviceRow(d: SavedDevice, nicknames: Map<String, String>, onClick: (() -> Unit)?) {
    fun clean(s: String?) = s?.takeIf { it.isNotBlank() && !it.equals("null", ignoreCase = true) }
    val name = clean(nicknames[Nicknames.keyFor(d.mac, d.ip)]) ?: d.displayName
    val dotColor = if (d.online) Accent else TextMuted
    val rowModifier = Modifier
        .fillMaxWidth()
        .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
        .padding(horizontal = 14.dp, vertical = 12.dp)
    Row(rowModifier, verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(34.dp), contentAlignment = Alignment.Center) {
            Icon(deviceIcon(d), contentDescription = null, tint = if (d.online) Accent else TextMuted, modifier = Modifier.size(24.dp))
            Box(Modifier.align(Alignment.BottomEnd).size(9.dp).background(dotColor, CircleShape))
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(name, color = if (d.online) TextMain else TextMuted, fontWeight = FontWeight.Bold, fontSize = 15.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val meta = listOfNotNull(d.ip.takeIf { it != name }, clean(d.kind)).joinToString(" · ")
            if (meta.isNotEmpty()) Text(meta, color = TextMuted, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (d.openPorts.isNotEmpty()) {
                val sev = d.openPorts.mapNotNull { PortCatalog.riskFor(it)?.severity }.maxByOrNull { it.rank }
                Text(
                    "${d.openPorts.size} open port${if (d.openPorts.size == 1) "" else "s"}",
                    color = sev?.color() ?: TextMuted, fontSize = 11.sp
                )
            }
        }
        Spacer(Modifier.width(8.dp))
        // Right side, Fing-style: maker over model, then status. The green dot already signals "online",
        // so we only spell out a time when the device is offline — keeps the row easy to read.
        Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(2.dp)) {
            clean(d.vendor)?.let { Text(it, color = TextMain, fontWeight = FontWeight.SemiBold, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
            clean(d.model)?.let { Text(it, color = TextMuted, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
            if (!d.online) Text(
                "Seen ${DateUtils.getRelativeTimeSpanString(d.lastSeen)}",
                color = TextMuted, fontSize = 11.sp, maxLines = 1
            )
        }
    }
}

// ---------------------------------------------------------------- Website

@Composable
internal fun WebsiteAuditScreen(
    modifier: Modifier,
    state: WebUiState,
    securityMode: Boolean,
    onUrlChange: (String) -> Unit,
    onWpChecksChange: (Boolean) -> Unit,
    onRun: () -> Unit,
    onShareSite: (ReportExporter.Format) -> Unit = {},
    onPrintSite: () -> Unit = {},
    onOpenUrl: (String) -> Unit = {},
    onCopy: (String) -> Unit = {}
) {
    val focusManager = LocalFocusManager.current
    val run = {
        focusManager.clearFocus()
        onRun()
    }
    Column(
        modifier = modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        if (securityMode) ScreenHeading("Website security", "Checks HTTPS, the TLS certificate, security headers and cookies.")
        else ScreenHeading("Website intake", "A full developer snapshot: hosting, DNS, registrar, cert, stack, integrations and SEO — exportable.")
        SurfaceCard {
            Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = state.url,
                    onValueChange = onUrlChange,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    enabled = !state.busy,
                    label = { Text("Website address") },
                    placeholder = { Text("yourdomain.com") },
                    leadingIcon = { Icon(Icons.Filled.Language, contentDescription = null) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Go, autoCorrectEnabled = false),
                    keyboardActions = KeyboardActions(onGo = { run() })
                )
                Text(
                    if (securityMode) "Only audit sites you own or are authorized to test. Sentinel sends a few ordinary page requests; it never submits forms or attacks the site."
                    else "Pulls public info (DNS, WHOIS, the cert, one homepage fetch). Read-only — nothing is submitted or attacked. Switch to security mode in Settings.",
                    color = TextMuted, fontSize = 12.sp, lineHeight = 17.sp
                )
                if (securityMode) Row(
                    Modifier.fillMaxWidth().toggleable(value = state.wpChecks, enabled = !state.busy, role = Role.Switch, onValueChange = onWpChecksChange),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("Include WordPress checks", color = TextMain, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                        Text("Version, user enumeration, XML-RPC, plugin/theme CVEs, exposed files.", color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                    }
                    Spacer(Modifier.width(8.dp))
                    Switch(checked = state.wpChecks, onCheckedChange = null, enabled = !state.busy, colors = SwitchDefaults.colors(checkedThumbColor = OnAccent, checkedTrackColor = Accent))
                }
                PrimaryButton(
                    text = if (state.busy) (if (securityMode) "Auditing…" else "Building report…") else (if (securityMode) "Run audit" else "Build intake report"),
                    icon = Icons.Filled.PlayArrow,
                    enabled = !state.busy && state.url.isNotBlank(),
                    busy = state.busy,
                    onClick = run
                )
                state.error?.let { Text(it, color = HighColor, fontSize = 13.sp, lineHeight = 18.sp) }
            }
        }

        state.result?.let { result ->
            val counts = FindingMerge.countBySeverity(result.findings)
            SurfaceCard {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Eyebrow("RESULT")
                    Text(result.finalUrl, color = TextMain, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    result.statusCode?.let { Text("HTTP $it", color = TextMuted, fontSize = 12.sp) }
                    if (result.redirectChain.size > 1) {
                        Text("Redirects: " + result.redirectChain.joinToString(" → "), color = TextMuted, fontSize = 12.sp, lineHeight = 17.sp)
                    }
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 4.dp)) {
                        Severity.entries.forEach { severity ->
                            val count = counts[severity] ?: 0
                            if (count > 0) Text("$count ${severity.label}", color = severity.color(), fontSize = 13.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                    state.wpDetected?.let {
                        Text(
                            if (it) "WordPress detected — WordPress checks included." else "WordPress checks ran; this site didn't look like WordPress.",
                            color = if (it) Accent else TextMuted, fontSize = 12.sp
                        )
                    }
                    Text("Saved to Findings. Re-running replaces the previous results for this site.", color = TextMuted, fontSize = 12.sp)
                }
            }
            result.findings.forEach { FindingCard(it) }
        }

        state.siteProfile?.let { p ->
            SiteProfileReport(p, onShareSite = onShareSite, onPrintSite = onPrintSite, onOpenUrl = onOpenUrl, onCopy = onCopy)
        }

        if (securityMode) Text(
            "This is a baseline configuration check, not a full penetration test. Missing headers are recommendations, not proof that the site can be hacked.",
            color = TextMuted, fontSize = 12.sp, lineHeight = 17.sp
        )
    }
}

// ---------------------------------------------------------------- Web developer intake report

@Composable
private fun SiteProfileReport(
    p: SiteProfile,
    onShareSite: (ReportExporter.Format) -> Unit,
    onPrintSite: () -> Unit,
    onOpenUrl: (String) -> Unit,
    onCopy: (String) -> Unit
) {
    // Scores.
    if (p.seoScore != null || p.aiScore != null) {
        SurfaceCard {
            Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Eyebrow("SCORECARD · ${p.domain}")
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    p.seoScore?.let { ScorePill("SEO", it, p.seoGrade, Modifier.weight(1f)) }
                    p.aiScore?.let { ScorePill("AI", it, p.aiGrade, Modifier.weight(1f)) }
                    p.a11yScore?.let { ScorePill("A11y", it, p.a11yGrade, Modifier.weight(1f)) }
                }
                if (p.seoChecks.isNotEmpty()) ScoreBlock("SEO", p.seoCategories, p.seoChecks)
                if (p.aiChecks.isNotEmpty()) ScoreBlock("AI Visibility", p.aiCategories, p.aiChecks)
                if (p.a11yChecks.isNotEmpty()) ScoreBlock("Accessibility", p.a11yCategories, p.a11yChecks)
                if (p.aiCrawlersBlocked.isNotEmpty()) Text("Blocks AI crawlers: ${p.aiCrawlersBlocked.joinToString(", ")}", color = HighColor, fontSize = 12.sp, lineHeight = 16.sp)
            }
        }
    }

    // Attention flags.
    if (p.attentionFlags.isNotEmpty()) {
        SurfaceCard {
            Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Filled.WarningAmber, null, tint = HighColor, modifier = Modifier.size(18.dp))
                    Text("NEEDS ATTENTION · ${p.attentionFlags.size}", color = HighColor, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                }
                p.attentionFlags.forEach { Text("• $it", color = TextMain, fontSize = 13.sp, lineHeight = 18.sp) }
            }
        }
    }

    // Export row.
    SurfaceCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Eyebrow("EXPORT")
            Text("Share the full report, or tap any value below to copy it.", color = TextMuted, fontSize = 12.sp)
            Button(onClick = { onShareSite(ReportExporter.Format.HTML) }, modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = OnAccent)) {
                Icon(Icons.Filled.Share, null, modifier = Modifier.size(18.dp)); Spacer(Modifier.width(8.dp)); Text("Share report", fontWeight = FontWeight.Bold, maxLines = 1)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(onClick = onPrintSite, border = BorderStroke(1.dp, Border), modifier = Modifier.weight(1f)) { Text("PDF", color = Accent, maxLines = 1) }
                OutlinedButton(onClick = { onShareSite(ReportExporter.Format.CSV) }, border = BorderStroke(1.dp, Border), modifier = Modifier.weight(1f)) { Text("CSV", color = Accent, maxLines = 1) }
                OutlinedButton(onClick = { onShareSite(ReportExporter.Format.JSON) }, border = BorderStroke(1.dp, Border), modifier = Modifier.weight(1f)) { Text("JSON", color = Accent, maxLines = 1) }
            }
        }
    }

    val ms = { x: Long? -> x?.let { java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US).format(java.util.Date(it)) } }

    GroupLabel("SNAPSHOT")
    WebInfoCard("OVERVIEW", listOf(
        "Domain" to p.domain,
        "Canonical" to p.canonicalUrl,
        "Prefers" to (if (p.usesWww) "www" else "apex (no www)"),
        "Forces HTTPS" to (if (p.httpsRedirect) "Yes" else "No"),
        "Final URL" to p.finalUrl,
        "HTTP status" to p.statusCode?.toString(),
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("HOSTING & NETWORK", listOf(
        "IP" to p.ip, "Hosting" to p.hostingProvider, "Location" to p.hostingLocation,
        "ASN / org" to p.asn, "CDN" to p.cdn, "Server" to p.serverHeader, "X-Powered-By" to p.poweredBy,
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("PERFORMANCE", listOf(
        "Response time" to p.responseMs?.let { "$it ms" },
        "HTML size" to p.htmlBytes?.let { "${it / 1024} KB" },
        "Scripts" to p.scriptCount?.toString(),
        "Stylesheets" to p.stylesheetCount?.toString(),
        "Render-blocking (head scripts)" to p.scriptsInHead?.toString(),
        "CDN" to p.cdn,
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)

    GroupLabel("DOMAIN, DNS & SECURITY")
    WebInfoCard("DOMAIN & REGISTRAR", listOf(
        "Registrar" to p.registrar, "Created" to p.domainCreated, "Updated" to p.domainUpdated, "Expires" to p.domainExpiry,
        "DNS host" to p.dnsHost, "Name servers" to p.nameServers.joinToString(", ").ifBlank { null },
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("CERTIFICATE", listOf(
        "Issuer" to p.certIssuer, "Subject" to p.certSubject,
        "Valid from" to ms(p.certValidFrom), "Expires" to ms(p.certValidTo),
        "Signature" to p.certSigAlg, "SANs" to p.certSans.joinToString(", ").ifBlank { null },
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("EMAIL", listOf(
        "Provider" to p.emailProvider, "SPF" to (if (p.spf) "Yes" else "No"),
        "DMARC" to (if (p.dmarc) "Yes" else "No"), "DKIM" to (if (p.dkimHint) "Detected" else "Not detected"),
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("DNS SECURITY", listOf(
        "DNSSEC" to (if (p.dnssec) "Enabled" else "Not enabled"),
        "CAA record" to (if (p.caa) "Present" else "None"),
        "SSL grade" to p.sslGrade,
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("SECURITY HEADERS", p.securityHeaders.map { it.key to (if (it.value) "Present" else "Missing") }, onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("EMAIL", listOf(
        "Provider" to p.emailProvider, "SPF" to (if (p.spf) "Yes" else "No"),
        "DMARC" to (if (p.dmarc) "Yes" else "No"), "DKIM" to (if (p.dkimHint) "Detected" else "Not detected"),
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)

    GroupLabel("PLATFORM & STACK")
    WebInfoCard("PLATFORM & STACK", listOf(
        "CMS / platform" to p.cms, "Admin login" to p.cmsAdminPath, "Framework" to p.framework,
        "Page builder" to p.pageBuilder, "Fonts" to p.fonts.joinToString(", ").ifBlank { null },
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("STACK VERSIONS", p.versions.map { it.key to it.value }, onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("THIRD-PARTY INTEGRATIONS", p.integrations.map { it.category to it.name }, onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("IDS TO MIGRATE", p.analyticsIds.map { it.kind to it.value }, onCopy = onCopy, onOpenUrl = onOpenUrl)

    GroupLabel("CONTENT & SEO")
    WebInfoCard("SEO & META", listOf(
        "Title" to p.title, "Description" to p.description, "Canonical" to p.canonicalLink,
        "Viewport" to p.viewport, "Schema" to p.schemaTypes.joinToString(", ").ifBlank { null },
        "Copyright" to p.copyrightYear,
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("STRUCTURE", listOf(
        "robots.txt" to (if (p.robotsFound) "Found" else "Not found"),
        "Pages (sitemap)" to p.pageCount?.toString(),
        "Sitemaps" to p.sitemapUrls.joinToString("\n").ifBlank { null },
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("BUSINESS", listOf(
        "Name" to p.businessName, "Phone" to p.businessPhone, "Address" to p.businessAddress,
    ), onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("CONTACTS ON PAGE", (p.contactEmails.map { "Email" to it } + p.contactPhones.map { "Phone" to it }), onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("KEY PAGES", emptyList(), linkRows = p.keyPages, onCopy = onCopy, onOpenUrl = onOpenUrl)

    GroupLabel("MARKETING & PRESENCE")
    WebInfoCard("SOCIAL", emptyList(), linkRows = p.socialLinks, onCopy = onCopy, onOpenUrl = onOpenUrl)
    WebInfoCard("ONLINE PRESENCE (SEARCH)", emptyList(), linkRows = p.presenceSearches, onCopy = onCopy, onOpenUrl = onOpenUrl)

    GroupLabel("RAW DATA")
    WebInfoCard("DNS RECORDS", p.dns.map { it.type to it.value }, onCopy = onCopy, onOpenUrl = onOpenUrl)
    if (p.notes.isNotEmpty()) WebInfoCard("NOTES", p.notes.map { "⚠" to it }, onCopy = onCopy, onOpenUrl = onOpenUrl)
}

@Composable
private fun GroupLabel(text: String) {
    Text(text, color = TextMuted, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.5.sp, modifier = Modifier.padding(top = 8.dp, start = 2.dp))
}

@Composable
private fun WebInfoCard(
    title: String,
    rows: List<Pair<String, String?>>,
    linkRows: List<SiteLink> = emptyList(),
    onCopy: (String) -> Unit,
    onOpenUrl: (String) -> Unit
) {
    val shown = rows.filter { !it.second.isNullOrBlank() }
    if (shown.isEmpty() && linkRows.isEmpty()) return
    SurfaceCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Eyebrow(title)
            Spacer(Modifier.height(4.dp))
            shown.forEach { (label, value) ->
                Row(
                    Modifier.fillMaxWidth().clickable { onCopy(value.orEmpty()) }.padding(vertical = 3.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(label, color = TextMuted, fontSize = 13.sp, modifier = Modifier.width(120.dp))
                    Text(value.orEmpty(), color = TextMain, fontSize = 13.sp, lineHeight = 18.sp, modifier = Modifier.weight(1f))
                }
            }
            linkRows.forEach { link ->
                Row(
                    Modifier.fillMaxWidth().clickable { onOpenUrl(link.url) }.padding(vertical = 3.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(link.label, color = TextMuted, fontSize = 13.sp, modifier = Modifier.width(120.dp))
                    Text(link.url, color = Accent, fontSize = 13.sp, lineHeight = 18.sp, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                }
            }
        }
    }
}

@Composable
private fun ScorePill(label: String, score: Int, grade: String?, modifier: Modifier = Modifier) {
    val color = when { score >= 80 -> Accent; score >= 55 -> MediumColor; else -> HighColor }
    Column(
        modifier.background(SurfaceRaised, RoundedCornerShape(12.dp)).padding(vertical = 12.dp, horizontal = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(1.dp)
    ) {
        Text("$score", color = color, fontSize = 30.sp, fontWeight = FontWeight.Bold)
        grade?.let { Text("Grade $it", color = color, fontSize = 12.sp, fontWeight = FontWeight.SemiBold) }
        Text(label, color = TextMuted, fontSize = 11.sp, maxLines = 1)
    }
}

private fun barColor(frac: Float): Color = when { frac >= 0.8f -> Accent; frac >= 0.6f -> MediumColor; else -> HighColor }

@Composable
private fun ScoreBlock(title: String, categories: List<ScoreCategory>, checks: List<ScoreCheck>) {
    var expanded by remember { mutableStateOf(false) }
    val passed = checks.count { it.status == CheckStatus.PASS }
    Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
        categories.forEach { cat ->
            val frac = if (cat.possible == 0) 0f else cat.earned.toFloat() / cat.possible
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("${title.take(3)} · ${cat.name}", color = TextMuted, fontSize = 11.sp, modifier = Modifier.width(132.dp), maxLines = 1, overflow = TextOverflow.Ellipsis)
                LinearProgressIndicator(progress = { frac }, modifier = Modifier.weight(1f).height(6.dp).clip(RoundedCornerShape(3.dp)), color = barColor(frac), trackColor = SurfaceRaised)
                Text("${cat.earned}/${cat.possible}", color = TextMuted, fontSize = 11.sp)
            }
        }
        Row(
            Modifier.fillMaxWidth().clickable { expanded = !expanded }.padding(top = 2.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("$title checks · $passed/${checks.size} pass", color = Accent, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            Icon(if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore, contentDescription = null, tint = Accent, modifier = Modifier.size(18.dp))
        }
        if (expanded) checks.forEach { c ->
            val color = when (c.status) { CheckStatus.PASS -> Accent; CheckStatus.WARN -> MediumColor; CheckStatus.FAIL -> HighColor }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(start = 4.dp)) {
                Box(Modifier.size(8.dp).background(color, CircleShape))
                Text(c.label, color = if (c.status == CheckStatus.PASS) TextMain else TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
            }
        }
    }
}

// ---------------------------------------------------------------- Findings

@Composable
internal fun FindingsScreen(
    modifier: Modifier,
    findings: List<Finding>,
    filter: Severity?,
    vulnDb: VulnDbStatus,
    onUpdateDb: () -> Unit,
    onFilter: (Severity?) -> Unit,
    onExport: (ReportExporter.Format) -> Unit,
    onPrintPdf: () -> Unit,
    onClear: () -> Unit,
    onDismiss: (String) -> Unit
) {
    var confirmClear by rememberSaveable { mutableStateOf(false) }
    val counts = FindingMerge.countBySeverity(findings)
    val visible = remember(findings, filter) {
        FindingMerge.prioritized(findings).filter { filter == null || it.severity == filter }
    }
    // Accordion expansion per severity; the highest non-empty group starts open, the rest collapsed.
    val expandedSev = remember { mutableStateMapOf<Severity, Boolean>() }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("Clear all findings?") },
            text = { Text("This deletes all ${findings.size} saved findings from this phone. It can't be undone.") },
            confirmButton = {
                TextButton(onClick = { confirmClear = false; onClear() }) { Text("Clear all", color = HighColor) }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) { Text("Cancel") }
            },
            containerColor = SurfaceColor
        )
    }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                ScreenHeading("Findings", "Highest priority first. Each scan replaces its previous results.")
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Button(
                        onClick = { onExport(ReportExporter.Format.HTML) },
                        enabled = findings.isNotEmpty(),
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = OnAccent)
                    ) {
                        Icon(Icons.Filled.Share, null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Share report", fontWeight = FontWeight.Bold)
                    }
                    TextButton(onClick = { confirmClear = true }, enabled = findings.isNotEmpty()) {
                        Icon(Icons.Filled.DeleteOutline, null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Clear")
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    OutlinedButton(onClick = onPrintPdf, enabled = findings.isNotEmpty(), border = BorderStroke(1.dp, Border), modifier = Modifier.weight(1f)) {
                        Text("PDF", color = Accent, fontSize = 13.sp)
                    }
                    OutlinedButton(onClick = { onExport(ReportExporter.Format.CSV) }, enabled = findings.isNotEmpty(), border = BorderStroke(1.dp, Border), modifier = Modifier.weight(1f)) {
                        Text("CSV", color = Accent, fontSize = 13.sp)
                    }
                    OutlinedButton(onClick = { onExport(ReportExporter.Format.JSON) }, enabled = findings.isNotEmpty(), border = BorderStroke(1.dp, Border), modifier = Modifier.weight(1f)) {
                        Text("JSON", color = Accent, fontSize = 13.sp)
                    }
                }
            }
        }
        item { VulnDbCard(vulnDb, onUpdateDb) }
        item {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SeverityChip("All · ${findings.size}", filter == null, Accent) { onFilter(null) }
                Severity.entries.forEach { severity ->
                    SeverityChip("${severity.label} · ${counts[severity] ?: 0}", filter == severity, severity.color()) {
                        onFilter(if (filter == severity) null else severity)
                    }
                }
            }
        }
        if (visible.isEmpty()) {
            item {
                SurfaceCard {
                    Column(Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = Accent, modifier = Modifier.size(34.dp))
                        Text(if (findings.isEmpty()) "Nothing saved yet" else "No ${filter?.label?.lowercase()} findings", color = TextMain, fontWeight = FontWeight.Bold)
                        Text(
                            if (findings.isEmpty()) "Run a network scan or website audit to build your first report." else "Choose another filter to see the rest.",
                            color = TextMuted, fontSize = 13.sp
                        )
                    }
                }
            }
        } else {
            // Grouped into collapsible accordion sections by severity (highest first).
            val groups = Severity.entries.mapNotNull { sev ->
                visible.filter { it.severity == sev }.takeIf { it.isNotEmpty() }?.let { sev to it }
            }
            groups.forEachIndexed { index, (sev, group) ->
                val isOpen = expandedSev[sev] ?: (index == 0)
                item(key = "sev-${sev.name}") {
                    SeveritySectionHeader(sev, group.size, isOpen) { expandedSev[sev] = !isOpen }
                }
                if (isOpen) {
                    items(group, key = { it.id }) { finding -> FindingCard(finding, onDismiss = { onDismiss(finding.id) }) }
                }
            }
        }
    }
}

/** Collapsible accordion header for a severity group on the Findings screen. */
@Composable
private fun SeveritySectionHeader(severity: Severity, count: Int, expanded: Boolean, onToggle: () -> Unit) {
    val color = severity.color()
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle)
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(10.dp).background(color, CircleShape))
        Spacer(Modifier.width(10.dp))
        Text(severity.label, color = color, fontWeight = FontWeight.Bold, fontSize = 15.sp, modifier = Modifier.weight(1f))
        Text("$count", color = TextMuted, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.width(6.dp))
        Icon(
            if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
            contentDescription = if (expanded) "Collapse" else "Expand",
            tint = TextMuted, modifier = Modifier.size(22.dp)
        )
    }
}

@Composable
private fun VulnDbCard(status: VulnDbStatus, onUpdate: () -> Unit) {
    SurfaceCard {
        Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Shield, contentDescription = null, tint = Accent, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text("Vulnerability database", color = TextMain, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                val line = if (status.count == 0) "No entries yet — tap Update."
                else "${status.count} CVEs · ${status.updated} · ${status.source.substringAfterLast('/').ifBlank { status.source }}"
                Text(line, color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
                status.message?.let { Text(it, color = if (status.isError) HighColor else Accent, fontSize = 11.sp, lineHeight = 15.sp) }
            }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = onUpdate, enabled = !status.updating, border = BorderStroke(1.dp, Border)) {
                if (status.updating) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Accent)
                } else {
                    Icon(Icons.Filled.Refresh, contentDescription = null, tint = Accent, modifier = Modifier.size(16.dp))
                }
                Spacer(Modifier.width(6.dp))
                Text(if (status.updating) "Updating" else "Update", color = Accent)
            }
        }
    }
}

@Composable
private fun SeverityChip(label: String, selected: Boolean, color: Color, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, fontSize = 13.sp) },
        colors = FilterChipDefaults.filterChipColors(
            containerColor = SurfaceColor,
            labelColor = TextMuted,
            selectedContainerColor = color.copy(alpha = 0.18f),
            selectedLabelColor = color
        ),
        border = FilterChipDefaults.filterChipBorder(
            enabled = true,
            selected = selected,
            borderColor = Border,
            selectedBorderColor = color.copy(alpha = 0.6f)
        )
    )
}

// ---------------------------------------------------------------- Shared components

@Composable
internal fun FindingCard(finding: Finding, onDismiss: (() -> Unit)? = null) {
    SurfaceCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SeverityBadge(finding.severity)
                Spacer(Modifier.width(8.dp))
                Text(
                    "${finding.source} · ${DateUtils.getRelativeTimeSpanString(finding.createdAt)}",
                    color = TextMuted, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
            Text(finding.title, color = TextMain, fontWeight = FontWeight.Bold, fontSize = 15.sp, lineHeight = 20.sp)
            Text(finding.target, color = Accent, fontSize = 12.sp)
            val compliance = remember(finding.key) { Compliance.tag(finding).labels }
            if (compliance.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    compliance.forEach { label ->
                        Box(Modifier.background(SurfaceRaised, RoundedCornerShape(5.dp)).padding(horizontal = 7.dp, vertical = 2.dp)) {
                            Text(label, color = TextMuted, fontSize = 10.sp, fontWeight = FontWeight.Medium)
                        }
                    }
                }
            }
            Text(finding.details, color = TextMuted, fontSize = 13.sp, lineHeight = 18.sp)
            HorizontalDivider(color = Border)
            Text("WHAT TO DO", color = TextMain, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.8.sp)
            Text(finding.remediation, color = TextMuted, fontSize = 13.sp, lineHeight = 18.sp)
            if (onDismiss != null) {
                TextButton(onClick = onDismiss, modifier = Modifier.align(Alignment.End)) {
                    Text("Dismiss", color = TextMuted, fontSize = 13.sp)
                }
            }
        }
    }
}

@Composable
private fun SeverityBadge(severity: Severity) {
    val color = severity.color()
    Box(Modifier.background(color.copy(alpha = 0.15f), RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 4.dp)) {
        Text(severity.label.uppercase(), color = color, fontSize = 11.sp, fontWeight = FontWeight.Black, letterSpacing = 0.6.sp)
    }
}

@Composable
private fun Tag(text: String) {
    Box(Modifier.background(Accent.copy(alpha = 0.14f), RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 3.dp)) {
        Text(text, color = Accent, fontSize = 11.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun PrimaryButton(
    text: String,
    icon: ImageVector,
    enabled: Boolean,
    onClick: () -> Unit,
    busy: Boolean = false
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().height(50.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = OnAccent)
    ) {
        if (busy) CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = OnAccent)
        else Icon(icon, contentDescription = null)
        Spacer(Modifier.width(8.dp))
        Text(text, fontWeight = FontWeight.Bold, fontSize = 15.sp)
    }
}

@Composable
private fun SurfaceCard(
    modifier: Modifier = Modifier,
    border: BorderStroke = BorderStroke(1.dp, Border),
    onClick: (() -> Unit)? = null,
    content: @Composable () -> Unit
) {
    val colors = CardDefaults.cardColors(containerColor = SurfaceColor)
    val shape = RoundedCornerShape(16.dp)
    if (onClick != null) {
        Card(onClick = onClick, modifier = modifier, colors = colors, shape = shape, border = border) { content() }
    } else {
        Card(modifier = modifier, colors = colors, shape = shape, border = border) { content() }
    }
}

@Composable
private fun Eyebrow(text: String) {
    Text(text, color = Accent, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.3.sp)
}

@Composable
private fun SectionHeader(eyebrow: String, title: String) {
    Column(verticalArrangement = Arrangement.spacedBy(3.dp), modifier = Modifier.padding(top = 4.dp)) {
        Eyebrow(eyebrow)
        Text(title, color = TextMain, fontWeight = FontWeight.SemiBold, fontSize = 17.sp)
    }
}

@Composable
private fun ScreenHeading(title: String, subtitle: String) {
    Column(verticalArrangement = Arrangement.spacedBy(5.dp), modifier = Modifier.padding(bottom = 8.dp)) {
        Text(title, color = TextMain, fontSize = 25.sp, fontWeight = FontWeight.Bold, lineHeight = 29.sp)
        Text(subtitle, color = TextMuted, fontSize = 13.sp, lineHeight = 18.sp)
    }
}

// ---------------------------------------------------------------- Host walkthrough

private val URL_REGEX = Regex("""https?://\S+""")

@Composable
internal fun HostDetailScreen(
    modifier: Modifier,
    device: DeviceResult,
    findings: List<Finding>,
    annotations: Map<String, FindingAnnotation>,
    rescanning: Boolean,
    nickname: String?,
    onSetNickname: (String) -> Unit,
    saved: SavedDevice? = null,
    shodanKey: String = "",
    vtKey: String = "",
    onBack: () -> Unit,
    onRescan: () -> Unit,
    onStatus: (Finding, FindingStatus) -> Unit,
    onNotes: (Finding, String) -> Unit,
    onCopy: (String) -> Unit,
    onOpenUrl: (String) -> Unit
) {
    val ordered = remember(findings) { FindingMerge.prioritized(findings) }
    val openCount = ordered.count { annotations[it.key]?.status.let { s -> s != FindingStatus.FIXED && s != FindingStatus.FALSE_POSITIVE } }
    val expandedSev = remember { mutableStateMapOf<Severity, Boolean>() }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onBack, contentPadding = PaddingValues(0.dp)) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = Accent, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Devices", color = Accent)
                }
                val shownName = nickname?.takeIf { it.isNotBlank() } ?: device.displayName
                Text(shownName, color = TextMain, fontSize = 24.sp, fontWeight = FontWeight.Bold, lineHeight = 28.sp)
                val sub = listOfNotNull(device.ipAddress.takeIf { it != shownName }, device.vendor, device.model, device.kind)
                if (sub.isNotEmpty()) Text(sub.joinToString(" · "), color = TextMuted, fontSize = 13.sp)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { onCopy(device.ipAddress) }, border = BorderStroke(1.dp, Border)) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = null, tint = TextMain, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp)); Text("Copy IP", color = TextMain)
                    }
                    OutlinedButton(onClick = onRescan, enabled = !rescanning, border = BorderStroke(1.dp, Border)) {
                        if (rescanning) CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Accent)
                        else Icon(Icons.Filled.Refresh, contentDescription = null, tint = TextMain, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp)); Text(if (rescanning) "Rescanning" else "Rescan host", color = TextMain)
                    }
                }
                var nameDraft by rememberSaveable(nickname) { mutableStateOf(nickname ?: "") }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ToolField(nameDraft, { nameDraft = it }, "Nickname (e.g. Dad's laptop)", enabled = true, modifier = Modifier.weight(1f), onGo = { onSetNickname(nameDraft) })
                    OutlinedButton(onClick = { onSetNickname(nameDraft) }, enabled = nameDraft != (nickname ?: ""), border = BorderStroke(1.dp, Border)) {
                        Text("Save", color = Accent)
                    }
                }
            }
        }
        item {
            SurfaceCard {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Eyebrow("OVERVIEW")
                    Spacer(Modifier.height(4.dp))
                    DetailRow("IP address", device.ipAddress)
                    val mac = device.mac
                    if (mac != null) {
                        DetailRow("MAC", mac + if (Oui.isLocallyAdministered(mac)) "  (randomized)" else "")
                    } else {
                        DetailRow("MAC", "Not recovered (Android hides it unless the router shares it)", valueColor = TextMuted)
                    }
                    device.vendor?.takeIf { it.isNotBlank() }?.let { DetailRow("Manufacturer", it) }
                    device.model?.takeIf { it.isNotBlank() }?.let { DetailRow("Model", it) }
                    device.kind?.takeIf { it.isNotBlank() }?.let { DetailRow("Type", it) }
                    device.identity?.name?.takeIf { it.isNotBlank() && it != device.displayName }?.let { DetailRow("Hostname", it) }
                    val role = listOfNotNull(
                        if (device.isGateway) "Gateway / router" else null,
                        if (device.isThisDevice) "This phone" else null
                    ).joinToString(" · ")
                    if (role.isNotEmpty()) DetailRow("Role", role, valueColor = Accent)
                    saved?.let { s ->
                        if (s.firstSeen > 0) DetailRow("First seen", DateUtils.getRelativeTimeSpanString(s.firstSeen).toString())
                        if (s.lastSeen > 0) DetailRow("Last seen", if (device.isThisDevice || s.online) "Now (online)" else DateUtils.getRelativeTimeSpanString(s.lastSeen).toString())
                    }
                }
            }
        }
        if (device.openPorts.isNotEmpty()) {
            item {
                SurfaceCard {
                    Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Eyebrow("OPEN PORTS · ${device.openPorts.size}")
                        device.openPorts.forEach { port ->
                            val risk = PortCatalog.riskFor(port.port)
                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.weight(1f)) {
                                        risk?.severity?.let { Box(Modifier.size(8.dp).background(it.color(), CircleShape)) }
                                        Text("${port.port}  ${port.service}", color = TextMain, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    }
                                    port.fingerprint?.let { Text(it.display, color = Accent, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                                }
                                risk?.why?.let { Text(it, color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp) }
                            }
                        }
                    }
                }
            }
        }
        item {
            val commands = remember(device) { Handoff.forDevice(device) }
            SurfaceCard {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Eyebrow("LAPTOP COMMANDS")
                    Text("Copy-ready for your rig. Sentinel doesn't run these.", color = TextMuted, fontSize = 12.sp)
                    commands.forEach { cmd ->
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(cmd.label, color = TextMuted, fontSize = 11.sp)
                                Text(cmd.command, color = Accent, fontSize = 12.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, lineHeight = 16.sp)
                            }
                            IconButton(onClick = { onCopy(cmd.command) }, modifier = Modifier.size(36.dp)) {
                                Icon(Icons.Filled.ContentCopy, contentDescription = "Copy command", tint = TextMuted, modifier = Modifier.size(16.dp))
                            }
                        }
                    }
                }
            }
        }
        if (device.isGateway) {
            item { InternetExposureCard(shodanKey = shodanKey, vtKey = vtKey, onCopy = onCopy, onOpenUrl = onOpenUrl) }
        }
        item { Eyebrow("ISSUES · $openCount open / ${ordered.size} total") }
        if (ordered.isEmpty()) {
            item {
                SurfaceCard {
                    Column(Modifier.fillMaxWidth().padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = Accent, modifier = Modifier.size(30.dp))
                        Text("No issues flagged on this host.", color = TextMain, fontWeight = FontWeight.Bold)
                    }
                }
            }
        } else {
            // Grouped into collapsible accordion sections by severity (highest first).
            val groups = Severity.entries.mapNotNull { sev ->
                ordered.filter { it.severity == sev }.takeIf { it.isNotEmpty() }?.let { sev to it }
            }
            groups.forEachIndexed { index, (sev, group) ->
                val isOpen = expandedSev[sev] ?: (index == 0)
                item(key = "dsev-${sev.name}") {
                    SeveritySectionHeader(sev, group.size, isOpen) { expandedSev[sev] = !isOpen }
                }
                if (isOpen) {
                    items(group, key = { it.key }) { finding ->
                        WalkthroughFindingCard(
                            finding = finding,
                            annotation = annotations[finding.key],
                            onStatus = { onStatus(finding, it) },
                            onNotes = { onNotes(finding, it) },
                            onOpenUrl = onOpenUrl,
                            onCopy = onCopy
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String, valueColor: Color = TextMain) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(label, color = TextMuted, fontSize = 13.sp, modifier = Modifier.width(104.dp))
        Text(value, color = valueColor, fontSize = 13.sp, lineHeight = 18.sp, modifier = Modifier.weight(1f))
    }
}

/**
 * Shown on the gateway: the network's internet-facing edge. Keyless, it reports the public IP, ISP/ASN
 * and which inbound ports answer from outside; with a Shodan/VirusTotal key it adds third-party intel on
 * that public IP. LAN hosts share one public IP behind NAT, so this edge view lives on the router.
 */
@Composable
private fun InternetExposureCard(shodanKey: String, vtKey: String, onCopy: (String) -> Unit, onOpenUrl: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var ran by remember { mutableStateOf(false) }
    var exposure by remember { mutableStateOf<NetToolsNet.ExposureResult?>(null) }
    var intel by remember { mutableStateOf<List<Finding>>(emptyList()) }
    var err by remember { mutableStateOf<String?>(null) }
    val hasKeys = shodanKey.isNotBlank() || vtKey.isNotBlank()
    SurfaceCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Eyebrow("INTERNET EXPOSURE")
            Text(
                "What the outside world can see at this network's public edge. Your LAN devices aren't reachable from the internet unless a port answers here.",
                color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp
            )
            if (!ran) {
                RunButton(if (busy) "Checking…" else "Check internet exposure", !busy) {
                    busy = true; err = null; ran = true
                    scope.launch {
                        NetToolsNet.publicExposure().onSuccess { r ->
                            exposure = r
                            if (hasKeys && r.info.kind == IpExposure.IpKind.PUBLIC) {
                                NetToolsNet.externalIntel(r.info.ip, shodanKey, vtKey).onSuccess { intel = it }
                            }
                        }.onFailure { err = it.message ?: "Couldn't check exposure." }
                        busy = false
                    }
                }
                if (!hasKeys) Text(
                    "Add a Shodan or VirusTotal key in Settings for deeper intel on the public IP.",
                    color = TextMuted, fontSize = 11.sp, lineHeight = 15.sp
                )
            }
            if (busy) Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Accent)
                Text("Looking up the public IP…", color = TextMuted, fontSize = 13.sp)
            }
            exposure?.let { r ->
                val info = r.info
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(info.ip, color = Accent, fontSize = 16.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                    Tag(info.kind.label)
                }
                listOfNotNull(info.isp, info.asn, info.location).takeIf { it.isNotEmpty() }?.let {
                    Text(it.joinToString(" · "), color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                }
                if (info.kind == IpExposure.IpKind.PUBLIC) {
                    if (r.reachable.isEmpty()) Text("No common inbound ports answered from outside — good.", color = Accent, fontSize = 13.sp)
                    else Text("Reachable inbound: ${r.reachable.joinToString(", ")}", color = HighColor, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                }
                TextButton(onClick = { onCopy(info.ip) }, contentPadding = PaddingValues(0.dp)) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = null, tint = Accent, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp)); Text("Copy public IP", color = Accent, fontSize = 13.sp)
                }
            }
            if (intel.isNotEmpty()) {
                HorizontalDivider(color = Border)
                Text("THIRD-PARTY INTEL", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.2.sp)
                intel.forEach { f ->
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            SeverityBadge(f.severity)
                            Text(f.title, color = TextMain, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
                        }
                        if (f.details.isNotBlank()) Text(f.details, color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                    }
                }
            }
            err?.let { Text(it, color = HighColor, fontSize = 13.sp) }
        }
    }
}

@Composable
private fun WalkthroughFindingCard(
    finding: Finding,
    annotation: FindingAnnotation?,
    onStatus: (FindingStatus) -> Unit,
    onNotes: (String) -> Unit,
    onOpenUrl: (String) -> Unit,
    onCopy: (String) -> Unit
) {
    val status = annotation?.status ?: FindingStatus.NEW
    val resolved = status == FindingStatus.FIXED || status == FindingStatus.FALSE_POSITIVE
    val reference = remember(finding) { URL_REGEX.find("${finding.remediation} ${finding.details}")?.value?.trimEnd('.', ')') }
    var notes by rememberSaveable(finding.key) { mutableStateOf(annotation?.notes ?: "") }

    SurfaceCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SeverityBadge(finding.severity)
                Spacer(Modifier.width(8.dp))
                Text(finding.target, color = TextMuted, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Text(
                finding.title,
                color = if (resolved) TextMuted else TextMain,
                fontWeight = FontWeight.Bold, fontSize = 15.sp, lineHeight = 20.sp
            )
            Text(finding.details, color = TextMuted, fontSize = 13.sp, lineHeight = 18.sp)
            Text(finding.remediation.replace(reference.orEmpty(), "").trim().ifBlank { finding.remediation }, color = TextMuted, fontSize = 13.sp, lineHeight = 18.sp)

            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                FindingStatus.entries.forEach { s ->
                    val tint = when (s) {
                        FindingStatus.FIXED -> Accent
                        FindingStatus.FALSE_POSITIVE -> TextMuted
                        FindingStatus.VERIFIED -> MediumColor
                        FindingStatus.NEW -> LowColor
                    }
                    FilterChip(
                        selected = status == s,
                        onClick = { onStatus(s) },
                        label = { Text(s.label, fontSize = 12.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            containerColor = SurfaceRaised, labelColor = TextMuted,
                            selectedContainerColor = tint.copy(alpha = 0.18f), selectedLabelColor = tint
                        ),
                        border = FilterChipDefaults.filterChipBorder(enabled = true, selected = status == s, borderColor = Border, selectedBorderColor = tint.copy(alpha = 0.6f))
                    )
                }
            }

            OutlinedTextField(
                value = notes,
                onValueChange = { notes = it; onNotes(it) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Notes") },
                placeholder = { Text("Evidence, payload used, follow-up…") },
                minLines = 1
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (reference != null) {
                    TextButton(onClick = { onOpenUrl(reference) }, contentPadding = PaddingValues(horizontal = 6.dp)) {
                        Icon(Icons.Filled.OpenInNew, contentDescription = null, tint = Accent, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp)); Text("Reference", color = Accent, fontSize = 13.sp)
                    }
                }
                TextButton(onClick = { onCopy("${finding.title} — ${finding.target}") }, contentPadding = PaddingValues(horizontal = 6.dp)) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = null, tint = TextMuted, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp)); Text("Copy", color = TextMuted, fontSize = 13.sp)
                }
            }
        }
    }
}

// ---------------------------------------------------------------- Tools tab (PortDroid-style utilities)

@Composable
internal fun ToolsScreen(modifier: Modifier, onCopy: (String) -> Unit, shodanKey: String = "", vtKey: String = "") {
    Column(
        modifier = modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        ScreenHeading("Network tools", "Grouped utilities for quick checks in the field. Tap a category to expand it.")

        ToolSection("REACHABILITY & DISCOVERY", "Ping, port scan, Wi-Fi, speed test", icon = Icons.Filled.Router, startExpanded = true) {
            PingTool(onCopy)
            PortScanTool(onCopy)
            WifiScanTool()
            SpeedTestTool()
        }
        ToolSection("DNS & DOMAIN", "Lookups, email posture, subdomains, WHOIS", icon = Icons.Filled.Language) {
            DnsTool(onCopy)
            HostFindingsTool("DNS / EMAIL POSTURE", "Checks SPF, DMARC, DKIM, CAA and DNSSEC for a domain — email-security and spoofing-resistance.", "example.com", "Check posture", icon = Icons.Filled.Shield) { NetToolsNet.dnsPosture(it) }
            SubdomainTool(onCopy)
            WhoisTool(onCopy)
        }
        ToolSection("SERVICE ASSESSMENT", "SSH, SMB and SNMP — read-only, no login", icon = Icons.Filled.Shield) {
            HostFindingsTool("SSH AUDIT", "Reads the SSH banner and advertised algorithms (KEX, host-key, cipher, MAC) and flags weak/legacy ones. No login.", "192.168.1.1", "Audit SSH", icon = Icons.Filled.Lock) { NetToolsNet.sshAudit(it) }
            HostFindingsTool("SMB SIGNING", "SMB2 negotiate: reads the dialect and whether message signing is required (relay risk). No auth, no share access.", "192.168.1.1", "Check SMB", icon = Icons.Filled.Storage) { NetToolsNet.smbInfo(it) }
            HostFindingsTool("SNMP INFO", "Queries SNMP with the default \"public\" community; a reply is itself a misconfiguration and discloses system info.", "192.168.1.1", "Query SNMP", icon = Icons.Filled.Router) { NetToolsNet.snmpInfo(it) }
        }
        ToolSection("EXPOSURE & INTEL", "Public-IP exposure and third-party intel", icon = Icons.Filled.Public) {
            ExposureTool(onCopy)
            HostFindingsTool("EXTERNAL INTEL", "Passive context from Shodan (IPs) and VirusTotal (IPs/domains). Bring your own API keys in Settings.", "example.com or 1.2.3.4", "Look up", icon = Icons.Filled.Public) { NetToolsNet.externalIntel(it, shodanKey, vtKey) }
        }
        ToolSection("UTILITIES", "Subnet calculator, MAC vendor, Wake-on-LAN", icon = Icons.Filled.Build) {
            SubnetTool(onCopy)
            MacVendorTool(onCopy)
            WolTool()
        }

        Text(
            "Traceroute (hop-by-hop) and SYN/OS-fingerprint scans need raw sockets and aren't possible on an unrooted phone.",
            color = TextMuted, fontSize = 11.sp, lineHeight = 16.sp
        )
        Spacer(Modifier.height(4.dp))
    }
}

/** A collapsible category of tools: a tappable header card that reveals its tools when expanded. */
@Composable
private fun ToolSection(
    title: String,
    subtitle: String,
    icon: ImageVector = Icons.Filled.Build,
    startExpanded: Boolean = false,
    content: @Composable ColumnScope.() -> Unit
) {
    var expanded by rememberSaveable(title) { mutableStateOf(startExpanded) }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SurfaceCard(onClick = { expanded = !expanded }) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(icon, contentDescription = null, tint = Accent, modifier = Modifier.size(22.dp))
                Spacer(Modifier.width(12.dp))
                Column(verticalArrangement = Arrangement.spacedBy(3.dp), modifier = Modifier.weight(1f)) {
                    Eyebrow(title)
                    Text(subtitle, color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                }
                Icon(
                    if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = if (expanded) "Collapse" else "Expand",
                    tint = TextMuted
                )
            }
        }
        if (expanded) content()
    }
}

@Composable
private fun ToolCard(title: String, description: String, icon: ImageVector = Icons.Filled.Build, content: @Composable ColumnScope.() -> Unit) {
    SurfaceCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(icon, contentDescription = null, tint = Accent, modifier = Modifier.size(18.dp))
                Eyebrow(title)
            }
            Text(description, color = TextMuted, fontSize = 12.sp, lineHeight = 15.sp)
            content()
        }
    }
}

@Composable
private fun ToolOutput(busy: Boolean, output: String?, isError: Boolean, onCopy: ((String) -> Unit)?, mono: Boolean = false, scrollable: Boolean = false) {
    if (busy) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Accent)
            Text("Running…", color = TextMuted, fontSize = 13.sp)
        }
    } else output?.let { text ->
        Row(verticalAlignment = Alignment.Top) {
            val base = Modifier.weight(1f)
            val mod = if (scrollable) base.heightIn(max = 260.dp).verticalScroll(rememberScrollState()) else base
            Text(
                text,
                modifier = mod,
                color = if (isError) HighColor else TextMain,
                fontSize = if (mono) 11.sp else 13.sp,
                lineHeight = if (mono) 15.sp else 18.sp,
                fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default
            )
            if (!isError && onCopy != null) {
                IconButton(onClick = { onCopy(text) }, modifier = Modifier.size(32.dp)) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "Copy", tint = TextMuted, modifier = Modifier.size(15.dp))
                }
            }
        }
    }
}

@Composable
private fun ToolField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    placeholder: String? = null,
    keyboard: KeyboardType = KeyboardType.Text,
    onGo: (() -> Unit)? = null
) {
    val focus = LocalFocusManager.current
    OutlinedTextField(
        value = value, onValueChange = onChange, label = { Text(label) },
        placeholder = placeholder?.let { { Text(it, color = TextMuted) } },
        singleLine = true, enabled = enabled, modifier = modifier.fillMaxWidth(),
        keyboardOptions = KeyboardOptions(keyboardType = keyboard, imeAction = if (onGo != null) ImeAction.Go else ImeAction.Default, autoCorrectEnabled = false),
        keyboardActions = KeyboardActions(onGo = { focus.clearFocus(); onGo?.invoke() })
    )
}

@Composable
private fun RunButton(text: String, enabled: Boolean, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = enabled, colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = OnAccent)) {
        Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(16.dp)); Spacer(Modifier.width(6.dp)); Text(text, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun PingTool(onCopy: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var host by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<String?>(null) }
    var err by remember { mutableStateOf(false) }
    val run = {
        if (!busy && host.isNotBlank()) {
            busy = true; out = null
            scope.launch {
                NetToolsNet.ping(host.trim())
                    .onSuccess { r ->
                        out = "${if (r.reachable) "Reachable" else "No reply"} · ${r.received}/${r.transmitted} received · ${r.lossPercent}% loss" + (r.avgMs?.let { " · avg %.1f ms".format(it) } ?: "")
                        err = !r.reachable
                    }
                    .onFailure { out = it.message; err = true }
                busy = false
            }
        }
    }
    ToolCard("PING", "Reachability and round-trip time (uses the system ping).", Icons.Filled.Router) {
        ToolField(host, { host = it }, "Host or IP", !busy, placeholder = "example.com or 192.168.1.1", keyboard = KeyboardType.Uri, onGo = run)
        RunButton("Ping", !busy && host.isNotBlank(), run)
        ToolOutput(busy, out, err, onCopy)
    }
}

@Composable
private fun DnsTool(onCopy: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var domain by rememberSaveable { mutableStateOf("") }
    var type by rememberSaveable { mutableStateOf("A") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<String?>(null) }
    var err by remember { mutableStateOf(false) }
    val run = {
        if (!busy && domain.isNotBlank()) {
            busy = true; out = null
            scope.launch {
                NetToolsNet.dnsLookup(domain.trim(), type)
                    .onSuccess { answers -> out = answers.joinToString("\n") { "${it.type.padEnd(6)} ${it.value}" }; err = false }
                    .onFailure { out = it.message; err = true }
                busy = false
            }
        }
    }
    ToolCard("DNS LOOKUP", "Query a public resolver (8.8.8.8) for DNS records. ALL queries every common type.", Icons.Filled.Language) {
        ToolField(domain, { domain = it }, "Domain", !busy, placeholder = "example.com", keyboard = KeyboardType.Uri, onGo = run)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf("ALL", "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA").forEach { t ->
                FilterChip(
                    selected = type == t, onClick = { type = t }, enabled = !busy,
                    label = { Text(t, fontSize = 12.sp) },
                    colors = FilterChipDefaults.filterChipColors(containerColor = SurfaceRaised, labelColor = TextMuted, selectedContainerColor = Accent.copy(alpha = 0.18f), selectedLabelColor = Accent),
                    border = FilterChipDefaults.filterChipBorder(enabled = true, selected = type == t, borderColor = Border, selectedBorderColor = Accent.copy(alpha = 0.6f))
                )
            }
        }
        RunButton("Look up", !busy && domain.isNotBlank(), run)
        ToolOutput(busy, out, err, onCopy, mono = true)
    }
}

@Composable
private fun PortScanTool(onCopy: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var host by rememberSaveable { mutableStateOf("") }
    var ports by rememberSaveable { mutableStateOf("1-1024") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<String?>(null) }
    var err by remember { mutableStateOf(false) }
    val run = {
        if (!busy && host.isNotBlank()) {
            busy = true; out = null
            scope.launch {
                val list = NetToolsNet.parsePortSpec(ports)
                NetToolsNet.scanPorts(host.trim(), list)
                    .onSuccess { open -> out = if (open.isEmpty()) "No open ports in that range." else open.joinToString("\n") { "${it.port.toString().padEnd(6)} ${it.service}" }; err = open.isEmpty() }
                    .onFailure { out = it.message; err = true }
                busy = false
            }
        }
    }
    ToolCard("PORT SCAN", "TCP connect scan of one host. Ranges like 1-1024 or lists like 22,80,443.", Icons.Filled.Computer) {
        ToolField(host, { host = it }, "Host or IP", !busy, placeholder = "192.168.1.1", keyboard = KeyboardType.Uri)
        ToolField(ports, { ports = it }, "Ports", !busy, placeholder = "1-1024 or 22,80,443", onGo = run)
        RunButton("Scan", !busy && host.isNotBlank(), run)
        ToolOutput(busy, out, err, onCopy, mono = true, scrollable = true)
    }
}

@Composable
private fun WhoisTool(onCopy: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var domain by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<String?>(null) }
    var err by remember { mutableStateOf(false) }
    val run = {
        if (!busy && domain.isNotBlank()) {
            busy = true; out = null
            scope.launch {
                NetToolsNet.whois(domain.trim())
                    .onSuccess { out = it; err = false }.onFailure { out = it.message; err = true }
                busy = false
            }
        }
    }
    ToolCard("WHOIS", "Domain registration details (TCP port 43).", Icons.Filled.Assessment) {
        ToolField(domain, { domain = it }, "Domain", !busy, placeholder = "example.com", keyboard = KeyboardType.Uri, onGo = run)
        RunButton("Look up", !busy && domain.isNotBlank(), run)
        ToolOutput(busy, out, err, onCopy, mono = true, scrollable = true)
    }
}

@Composable
private fun SubdomainTool(onCopy: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var domain by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<String?>(null) }
    var count by remember { mutableStateOf(0) }
    var err by remember { mutableStateOf(false) }
    val run = {
        if (!busy && domain.isNotBlank()) {
            busy = true; out = null; count = 0
            scope.launch {
                NetToolsNet.subdomains(domain.trim())
                    .onSuccess { out = it.joinToString("\n"); count = it.size; err = false }
                    .onFailure { out = it.message; err = true }
                busy = false
            }
        }
    }
    ToolCard("SUBDOMAIN FINDER", "Passive subdomain discovery from CT logs (crt.sh + Certspotter). Read-only — never touches the target.", Icons.Filled.Language) {
        ToolField(domain, { domain = it }, "Domain", !busy, placeholder = "example.com", keyboard = KeyboardType.Uri, onGo = run)
        RunButton(if (busy) "Searching…" else "Find subdomains", !busy && domain.isNotBlank(), run)
        if (!busy && !err && count > 0) Text("$count subdomain(s) found", color = Accent, fontSize = 12.sp, fontWeight = FontWeight.Bold)
        ToolOutput(busy, out, err, onCopy, mono = true, scrollable = true)
    }
}

@Composable
private fun HostFindingsTool(
    eyebrow: String,
    description: String,
    placeholder: String,
    actionLabel: String,
    icon: ImageVector = Icons.Filled.Language,
    runner: suspend (String) -> Result<List<Finding>>
) {
    val scope = rememberCoroutineScope()
    var input by rememberSaveable(eyebrow) { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var findings by remember { mutableStateOf<List<Finding>?>(null) }
    var err by remember { mutableStateOf<String?>(null) }
    val run = {
        if (!busy && input.isNotBlank()) {
            busy = true; findings = null; err = null
            scope.launch {
                runner(input.trim())
                    .onSuccess { findings = it }
                    .onFailure { err = it.message }
                busy = false
            }
        }
    }
    ToolCard(eyebrow, description, icon) {
        ToolField(input, { input = it }, "Host or domain", !busy, placeholder = placeholder, keyboard = KeyboardType.Uri, onGo = run)
        RunButton(if (busy) "Working…" else actionLabel, !busy && input.isNotBlank(), run)
        if (busy) Text("Running…", color = TextMuted, fontSize = 13.sp)
        err?.let { Text(it, color = HighColor, fontSize = 13.sp, lineHeight = 18.sp) }
        findings?.forEach { f ->
            Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(Modifier.padding(top = 5.dp).size(8.dp).background(f.severity.color(), CircleShape))
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                    Text(f.title, color = TextMain, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, lineHeight = 17.sp)
                    Text(f.details, color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                }
            }
        }
    }
}

@Composable
private fun SubnetTool(onCopy: (String) -> Unit) {
    var ip by rememberSaveable { mutableStateOf("") }
    var prefix by rememberSaveable { mutableStateOf("24") }
    var out by remember { mutableStateOf<String?>(null) }
    var err by remember { mutableStateOf(false) }
    ToolCard("SUBNET CALCULATOR", "Network, broadcast, host range and mask for an IP/prefix.", Icons.Filled.Computer) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(ip, { ip = it }, label = { Text("IP") }, placeholder = { Text("192.168.1.10", color = TextMuted) }, singleLine = true, modifier = Modifier.weight(2f), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false))
            OutlinedTextField(prefix, { prefix = it }, label = { Text("/") }, placeholder = { Text("24", color = TextMuted) }, singleLine = true, modifier = Modifier.weight(1f), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
        }
        RunButton("Calculate", ip.isNotBlank()) {
            val p = prefix.trim().removePrefix("/").toIntOrNull()
            val info = p?.let { Subnet.calc(ip.trim(), it) }
            if (info == null) { out = "Enter a valid IP and prefix (0–32)."; err = true }
            else {
                out = "CIDR       ${info.cidr}\nNetmask    ${info.netmask}\nWildcard   ${info.wildcard}\nNetwork    ${info.network}\nBroadcast  ${info.broadcast}\nFirst host ${info.firstHost}\nLast host  ${info.lastHost}\nUsable     ${info.usableHosts}"
                err = false
            }
        }
        ToolOutput(false, out, err, onCopy, mono = true)
    }
}

@Composable
private fun MacVendorTool(onCopy: (String) -> Unit) {
    var mac by rememberSaveable { mutableStateOf("") }
    var out by remember { mutableStateOf<String?>(null) }
    var err by remember { mutableStateOf(false) }
    ToolCard("MAC VENDOR", "Identify a manufacturer from a MAC address (OUI prefix).", Icons.Filled.Memory) {
        ToolField(mac, { mac = it }, "MAC address", true, placeholder = "aa:bb:cc:dd:ee:ff")
        RunButton("Look up", mac.isNotBlank()) {
            val norm = Oui.normalize(mac)
            if (norm == null) { out = "That isn't a valid MAC address."; err = true }
            else { val v = Oui.vendor(norm); out = "$norm\n${v ?: "Unknown vendor"}"; err = false }
        }
        ToolOutput(false, out, err, onCopy, mono = true)
    }
}

@Composable
private fun WolTool() {
    val scope = rememberCoroutineScope()
    var mac by rememberSaveable { mutableStateOf("") }
    var bcast by rememberSaveable { mutableStateOf("255.255.255.255") }
    var busy by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<String?>(null) }
    var err by remember { mutableStateOf(false) }
    ToolCard("WAKE-ON-LAN", "Send a magic packet to power on a device by MAC.", Icons.Filled.Devices) {
        ToolField(mac, { mac = it }, "Target MAC", !busy, placeholder = "aa:bb:cc:dd:ee:ff")
        ToolField(bcast, { bcast = it }, "Broadcast address", !busy, keyboard = KeyboardType.Uri)
        RunButton("Send", !busy && mac.isNotBlank()) {
            busy = true; out = null
            scope.launch {
                NetToolsNet.wakeOnLan(mac.trim(), bcast.trim())
                    .onSuccess { out = "Magic packet sent to $mac."; err = false }
                    .onFailure { out = it.message; err = true }
                busy = false
            }
        }
        ToolOutput(busy, out, err, null)
    }
}

@Composable
private fun SpeedTestTool() {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf<String?>(null) }
    var out by remember { mutableStateOf<String?>(null) }
    var err by remember { mutableStateOf(false) }
    ToolCard("INTERNET SPEED", "Measures your phone's download speed and latency (via Cloudflare).", Icons.Filled.Public) {
        RunButton(if (busy) "Testing…" else "Run speed test", !busy) {
            busy = true; out = null; progress = "Starting…"
            scope.launch {
                SpeedTest.run(onProgress = { bytes, ms -> if (ms > 0) progress = "${bytes / 1_000_000} MB · ${SpeedCalc.format(SpeedCalc.mbps(bytes, ms))}" })
                    .onSuccess {
                        out = "Download  ${SpeedCalc.format(it.downloadMbps)}\nLatency   ${if (it.latencyMs >= 0) "${it.latencyMs} ms" else "n/a"}\nData      ${it.bytes / 1_000_000} MB in ${"%.1f".format(it.millis / 1000.0)} s"
                        err = false
                    }
                    .onFailure { out = it.message; err = true }
                busy = false; progress = null
            }
        }
        if (busy) Text(progress ?: "Running…", color = TextMuted, fontSize = 13.sp)
        ToolOutput(false, out, err, null, mono = true)
    }
}

@Composable
private fun ExposureTool(onCopy: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<NetToolsNet.ExposureResult?>(null) }
    var err by remember { mutableStateOf<String?>(null) }
    ToolCard("PUBLIC IP & EXPOSURE", "Your internet-facing IP and ISP/ASN, and which inbound ports answer from outside.", Icons.Filled.Public) {
        RunButton(if (busy) "Checking…" else "Check my exposure", !busy) {
            busy = true; result = null; err = null
            scope.launch {
                NetToolsNet.publicExposure()
                    .onSuccess { result = it }
                    .onFailure { err = it.message }
                busy = false
            }
        }
        if (busy) Text("Looking up your public IP…", color = TextMuted, fontSize = 13.sp)
        err?.let { Text(it, color = HighColor, fontSize = 13.sp, lineHeight = 18.sp) }
        result?.let { r ->
            val info = r.info
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(info.ip, color = Accent, fontSize = 16.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                    Tag(info.kind.label)
                }
                listOfNotNull(info.isp, info.asn, info.location).takeIf { it.isNotEmpty() }?.let {
                    Text(it.joinToString(" · "), color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                }
                Text(IpExposure.verdict(info.kind), color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                if (info.kind == IpExposure.IpKind.PUBLIC) {
                    HorizontalDivider(color = Border)
                    if (r.reachable.isEmpty()) {
                        Text("No common inbound ports answered — good. (Best-effort from this device; a check from an outside network is more definitive.)",
                            color = LowColor, fontSize = 12.sp, lineHeight = 16.sp)
                    } else {
                        Text("Reachable inbound: ${r.reachable.joinToString(", ")}", color = HighColor, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                        Text("These ports accepted a connection. If you didn't intend to expose them, close the port-forward or firewall them.",
                            color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                    }
                }
                TextButton(onClick = { onCopy(info.ip) }, contentPadding = PaddingValues(0.dp)) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = null, tint = TextMuted, modifier = Modifier.size(15.dp))
                    Spacer(Modifier.width(6.dp)); Text("Copy IP", color = TextMuted, fontSize = 13.sp)
                }
            }
        }
    }
}

@Composable
private fun WifiScanTool() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var aps by remember { mutableStateOf<List<WifiAp>?>(null) }
    var busy by remember { mutableStateOf(false) }
    var note by remember { mutableStateOf<String?>(null) }
    var hasPerm by remember { mutableStateOf(WifiScanNet.hasPermission(context)) }

    val permLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        hasPerm = granted
        if (!granted) note = "Location permission is required by Android to list Wi-Fi networks."
    }

    ToolCard("NEARBY WI-FI", "Lists access points in range with channel, signal and security.", Icons.Filled.Router) {
        if (!hasPerm) {
            Text("Android requires location permission to read Wi-Fi scans. Nothing about your location leaves the phone.", color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
            RunButton("Grant permission", true) { permLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION) }
        } else {
            RunButton(if (busy) "Scanning…" else "Scan Wi-Fi", !busy) {
                busy = true; note = null
                scope.launch {
                    val results = withContext(Dispatchers.IO) { WifiScanNet.scan(context) }
                    aps = results
                    if (results.isEmpty()) note = "No results. Make sure Wi-Fi and location are on; Android throttles repeat scans."
                    busy = false
                }
            }
        }
        note?.let { Text(it, color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp) }
        aps?.forEach { ap ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(ap.ssid, color = TextMain, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text("ch ${ap.channel} · ${ap.band} · ${ap.security}${ap.vendor?.let { " · $it" } ?: ""}", color = TextMuted, fontSize = 11.sp)
                }
                Text(
                    "${ap.signalPercent}%",
                    color = if (WifiInfoUtil.isWeak(ap.security)) MediumColor else Accent,
                    fontSize = 13.sp, fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

// ---------------------------------------------------------------- Settings

@Composable
internal fun SettingsScreen(
    modifier: Modifier,
    themeLight: Boolean,
    onThemeChange: (Boolean) -> Unit,
    vulnDb: VulnDbStatus,
    onUpdateDb: () -> Unit,
    feedUrl: String,
    onFeedUrl: (String) -> Unit,
    onResetFeed: () -> Unit,
    appUpdate: AppUpdateStatus,
    onCheckUpdate: () -> Unit,
    onInstallUpdate: () -> Unit,
    scanSchedule: ScanSchedule,
    onScheduleChange: (ScanSchedule) -> Unit,
    scopeText: String,
    onScopeChange: (String) -> Unit,
    shodanKey: String,
    onShodanChange: (String) -> Unit,
    vtKey: String,
    onVtChange: (String) -> Unit,
    cloudLookup: Boolean,
    onCloudLookupChange: (Boolean) -> Unit,
    fingerbankKey: String,
    onFingerbankChange: (String) -> Unit,
    webSecurityMode: Boolean,
    onWebModeChange: (Boolean) -> Unit,
    historyCount: Int,
    onOpenHistory: () -> Unit,
    onBack: () -> Unit,
    onCopy: (String) -> Unit,
    onOpenUrl: (String) -> Unit
) {
    var feedDraft by rememberSaveable(feedUrl) { mutableStateOf(feedUrl) }
    var scopeDraft by rememberSaveable(scopeText) { mutableStateOf(scopeText) }
    var shodanDraft by rememberSaveable(shodanKey) { mutableStateOf(shodanKey) }
    var vtDraft by rememberSaveable(vtKey) { mutableStateOf(vtKey) }
    var fingerbankDraft by rememberSaveable(fingerbankKey) { mutableStateOf(fingerbankKey) }
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onBack, contentPadding = PaddingValues(0.dp)) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = Accent, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Back", color = Accent)
                }
                Text("Settings", color = TextMain, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            }
        }

        // ---- Appearance ----
        item {
            SettingsCard(Icons.Filled.Palette, "APPEARANCE", "Theme") {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(if (themeLight) "Light & Crisp" else "Cyber Contrast", color = TextMain, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                        Text(if (themeLight) "Bright light mode for daytime use." else "True-black OLED with cyan + magenta.", color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                    }
                    Switch(
                        checked = themeLight,
                        onCheckedChange = onThemeChange,
                        colors = SwitchDefaults.colors(checkedThumbColor = OnAccent, checkedTrackColor = Accent)
                    )
                }
            }
        }

        // ---- Web scanner mode ----
        item {
            SettingsCard(Icons.Filled.Language, "WEB SCANNER", "Mode") {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("Security mode", color = TextMain, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                        Text(
                            if (webSecurityMode) "On — the website tool runs the security audit (HTTPS, TLS, headers, cookies, WordPress)."
                            else "Off — the website tool builds a developer intake report (hosting, DNS, registrar, cert, stack, integrations, SEO). Turn on for the security audit instead.",
                            color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Switch(checked = webSecurityMode, onCheckedChange = onWebModeChange, colors = SwitchDefaults.colors(checkedThumbColor = OnAccent, checkedTrackColor = Accent))
                }
            }
        }

        // ---- Scheduled scans ----
        item {
            SettingsCard(Icons.Filled.Schedule, "AUTOMATIC SCANS", "Schedule") {
                Text("Run a full scan of your authorized network on a schedule and get a notification when it finishes.", color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    ScanSchedule.entries.forEach { opt ->
                        FilterChip(
                            selected = scanSchedule == opt, onClick = { onScheduleChange(opt) },
                            label = { Text(opt.label, fontSize = 12.sp) },
                            colors = FilterChipDefaults.filterChipColors(containerColor = SurfaceRaised, labelColor = TextMuted, selectedContainerColor = Accent.copy(alpha = 0.18f), selectedLabelColor = Accent),
                            border = FilterChipDefaults.filterChipBorder(enabled = true, selected = scanSchedule == opt, borderColor = Border, selectedBorderColor = Accent.copy(alpha = 0.6f))
                        )
                    }
                }
                Text("Scans only run when the phone is back on the authorized network. Turn on Alerts (Home) to be notified.", color = TextMuted, fontSize = 11.sp, lineHeight = 15.sp)
            }
        }

        // ---- Engagement scope ----
        item {
            SettingsCard(Icons.Filled.Shield, "ENGAGEMENT", "Authorized scope") {
                Text("List the IPs, CIDRs and domains you're authorized to assess (one per line or comma-separated). Findings outside this are flagged in the report. Leave empty to disable scope checks.", color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                OutlinedTextField(
                    value = scopeDraft, onValueChange = { scopeDraft = it },
                    placeholder = { Text("192.168.1.0/24\nexample.com", color = TextMuted) },
                    modifier = Modifier.fillMaxWidth(), minLines = 2, maxLines = 5
                )
                OutlinedButton(onClick = { onScopeChange(scopeDraft) }, enabled = scopeDraft != scopeText, border = BorderStroke(1.dp, Border)) {
                    Text("Save scope", color = Accent)
                }
            }
        }

        // ---- External intel keys ----
        item {
            SettingsCard(Icons.Filled.OpenInNew, "EXTERNAL INTEL", "API keys (optional)") {
                Text("Bring-your-own keys for the External Intel tool. Shodan enriches IPs; VirusTotal checks IP/domain reputation. Stored only on this device.", color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                ToolField(shodanDraft, { shodanDraft = it }, "Shodan API key", enabled = true, onGo = { onShodanChange(shodanDraft) })
                ToolField(vtDraft, { vtDraft = it }, "VirusTotal API key", enabled = true, onGo = { onVtChange(vtDraft) })
                OutlinedButton(onClick = { onShodanChange(shodanDraft); onVtChange(vtDraft) }, enabled = shodanDraft != shodanKey || vtDraft != vtKey, border = BorderStroke(1.dp, Border)) {
                    Text("Save keys", color = Accent)
                }
            }
        }

        // ---- Online device lookup (opt-in) ----
        item {
            SettingsCard(Icons.Filled.Public, "DEVICE NAMES", "Online lookup (optional)") {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("Look devices up online", color = TextMain, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                        Text(
                            "Off by default. When on, Sentinel fills in a maker/model for devices that don't reveal one on the network — by sending a device's MAC and name to a lookup service. Local results always win; nothing is sent while this is off.",
                            color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Switch(
                        checked = cloudLookup,
                        onCheckedChange = onCloudLookupChange,
                        colors = SwitchDefaults.colors(checkedThumbColor = OnAccent, checkedTrackColor = Accent)
                    )
                }
                if (cloudLookup) {
                    Text("Maker from MAC works without a key. For a model/type guess, add a free Fingerbank API key (fingerbank.org). Stored only on this device.", color = TextMuted, fontSize = 11.sp, lineHeight = 15.sp)
                    ToolField(fingerbankDraft, { fingerbankDraft = it }, "Fingerbank API key (optional)", enabled = true, onGo = { onFingerbankChange(fingerbankDraft) })
                    OutlinedButton(onClick = { onFingerbankChange(fingerbankDraft) }, enabled = fingerbankDraft != fingerbankKey, border = BorderStroke(1.dp, Border)) {
                        Text("Save key", color = Accent)
                    }
                }
            }
        }

        // ---- Scan history ----
        item {
            SurfaceCard(onClick = onOpenHistory) {
                Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Icon(Icons.Filled.History, contentDescription = null, tint = Accent, modifier = Modifier.size(20.dp))
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                        Eyebrow("HISTORY")
                        Text("Scan history & trends", color = TextMain, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
                        Text(if (historyCount == 0) "No scans recorded yet." else "$historyCount saved scan(s) — tap to view and compare.", color = TextMuted, fontSize = 12.sp)
                    }
                    Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, tint = TextMuted, modifier = Modifier.size(18.dp))
                }
            }
        }

        // ---- Exploit database ----
        item {
            SettingsCard(Icons.Filled.Shield, "EXPLOIT DATABASE", "Known-exploit feed") {
                val line = if (vulnDb.count == 0) "No entries yet — tap Update."
                else "${vulnDb.count} CVEs · updated ${vulnDb.updated} · ${vulnDb.source.substringAfterLast('/').ifBlank { vulnDb.source }}"
                Text(line, color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                vulnDb.message?.let { Text(it, color = if (vulnDb.isError) HighColor else Accent, fontSize = 11.sp, lineHeight = 15.sp) }
                OutlinedButton(onClick = onUpdateDb, enabled = !vulnDb.updating, border = BorderStroke(1.dp, Border), modifier = Modifier.fillMaxWidth()) {
                    if (vulnDb.updating) CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Accent)
                    else Icon(Icons.Filled.Refresh, contentDescription = null, tint = Accent, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(if (vulnDb.updating) "Updating…" else "Update now", color = Accent)
                }
                HorizontalDivider(color = Border)
                Text("FEED SOURCE", color = TextMain, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.8.sp)
                Text("Pulls a JSON feed published by your GitHub project. Leave as-is unless you host your own.", color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                ToolField(feedDraft, { feedDraft = it }, "Feed URL", enabled = true, keyboard = KeyboardType.Uri)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { onFeedUrl(feedDraft) }, enabled = feedDraft.isNotBlank() && feedDraft != feedUrl, border = BorderStroke(1.dp, Border)) {
                        Text("Save", color = Accent)
                    }
                    TextButton(onClick = { onResetFeed(); feedDraft = VulnFeed.DEFAULT_FEED_URL }) {
                        Text("Reset to default", color = TextMuted)
                    }
                }
            }
        }

        // ---- App version ----
        item {
            SettingsCard(Icons.Filled.SystemUpdate, "APP VERSION", "Updates") {
                Text("Installed: v${appUpdate.currentVersion}", color = TextMuted, fontSize = 12.sp)
                appUpdate.message?.let { Text(it, color = if (appUpdate.isError) HighColor else Accent, fontSize = 12.sp, lineHeight = 16.sp) }
                if (appUpdate.available && appUpdate.notes.isNotBlank()) {
                    Text(appUpdate.notes.take(400), color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp, maxLines = 8, overflow = TextOverflow.Ellipsis)
                }
                if (appUpdate.available) {
                    PrimaryButton(
                        text = if (appUpdate.installing) "Downloading…" else "Download & install v${appUpdate.latestVersion}",
                        icon = Icons.Filled.SystemUpdate,
                        enabled = !appUpdate.installing,
                        onClick = onInstallUpdate,
                        busy = appUpdate.installing
                    )
                } else {
                    OutlinedButton(onClick = onCheckUpdate, enabled = !appUpdate.checking, border = BorderStroke(1.dp, Border), modifier = Modifier.fillMaxWidth()) {
                        if (appUpdate.checking) CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Accent)
                        else Icon(Icons.Filled.Refresh, contentDescription = null, tint = Accent, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(if (appUpdate.checking) "Checking…" else "Check for updates", color = Accent)
                    }
                }
                TextButton(onClick = { onOpenUrl("https://github.com/${AppUpdateLogic.OWNER}/${AppUpdateLogic.REPO}") }, contentPadding = PaddingValues(0.dp)) {
                    Icon(Icons.Filled.OpenInNew, contentDescription = null, tint = TextMuted, modifier = Modifier.size(15.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("View project on GitHub", color = TextMuted, fontSize = 13.sp)
                }
            }
        }
    }
}

@Composable
private fun SettingsCard(icon: ImageVector, eyebrow: String, title: String, content: @Composable ColumnScope.() -> Unit) {
    SurfaceCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(icon, contentDescription = null, tint = Accent, modifier = Modifier.size(20.dp))
                Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
                    Eyebrow(eyebrow)
                    Text(title, color = TextMain, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
                }
            }
            content()
        }
    }
}

// ---------------------------------------------------------------- Scan history

@Composable
internal fun HistoryScreen(
    modifier: Modifier,
    entries: List<HistoryEntry>,
    onClear: () -> Unit,
    onBack: () -> Unit
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onBack, contentPadding = PaddingValues(0.dp)) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = Accent, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Settings", color = Accent)
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Scan history", color = TextMain, fontSize = 25.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                    if (entries.isNotEmpty()) {
                        TextButton(onClick = onClear) { Text("Clear", color = TextMuted) }
                    }
                }
            }
        }
        if (entries.isEmpty()) {
            item {
                Text("No scans recorded yet. Run a network scan or website audit and it'll appear here.",
                    color = TextMuted, fontSize = 13.sp, lineHeight = 18.sp)
            }
        }
        items(entries.size) { i ->
            val e = entries[i]
            val diff = ScanHistoryCodec.diffAgainstPrevious(entries, e)
            SurfaceCard {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(e.label, color = TextMain, fontWeight = FontWeight.SemiBold, fontSize = 15.sp, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(DateUtils.getRelativeTimeSpanString(e.at).toString(), color = TextMuted, fontSize = 11.sp)
                    }
                    val meta = buildList {
                        add(if (e.type == FindingSource.NETWORK) "Network" else "Website")
                        if (e.type == FindingSource.NETWORK) add("${e.deviceCount} device(s)")
                    }
                    Text(meta.joinToString(" · "), color = TextMuted, fontSize = 12.sp)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        listOf(Severity.HIGH, Severity.MEDIUM, Severity.LOW).forEach { sev ->
                            val n = e.count(sev)
                            if (n > 0) HistoryCountPill(n, sev.label, sev.color())
                        }
                        if (e.issueCount == 0) HistoryCountPill(0, "No issues", LowColor)
                    }
                    if (diff != null && !diff.isEmpty) {
                        HorizontalDivider(color = Border)
                        Text("SINCE PREVIOUS SCAN", color = TextMain, fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.8.sp)
                        ScanDiffer.summaryLines(diff).take(6).forEach {
                            Text("• $it", color = TextMuted, fontSize = 12.sp, lineHeight = 16.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun HistoryCountPill(count: Int, label: String, color: Color) {
    Box(Modifier.background(color.copy(alpha = 0.15f), RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 3.dp)) {
        Text(if (count > 0) "$count $label" else label, color = color, fontSize = 11.sp, fontWeight = FontWeight.Bold)
    }
}
