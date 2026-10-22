package com.yellowowl.sentinel.wear

import android.os.Bundle
import android.text.format.DateUtils
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.wear.compose.foundation.lazy.ScalingLazyColumn
import androidx.wear.compose.foundation.lazy.rememberScalingLazyListState
import androidx.wear.compose.material.Chip
import androidx.wear.compose.material.ChipDefaults
import androidx.wear.compose.material.CircularProgressIndicator
import androidx.wear.compose.material.Colors
import androidx.wear.compose.material.Icon
import androidx.wear.compose.material.MaterialTheme
import androidx.wear.compose.material.Scaffold
import androidx.wear.compose.material.Text
import androidx.wear.compose.material.TimeText
import com.google.android.gms.wearable.DataClient
import com.google.android.gms.wearable.DataEvent
import com.google.android.gms.wearable.DataMapItem
import com.google.android.gms.wearable.Wearable
import kotlinx.coroutines.launch

private val Accent = Color(0xFF45E0B4)
private val OnAccent = Color(0xFF052018)
private val Muted = Color(0xFF9DB0BE)
private val HighColor = Color(0xFFFF647C)
private val MediumColor = Color(0xFFFFC66D)
private val LowColor = Color(0xFF8AC8FF)

class WatchActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colors = Colors(primary = Accent, onPrimary = OnAccent)) {
                WatchApp()
            }
        }
    }
}

@Composable
private fun WatchApp() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf<PhoneStatus?>(null) }
    var loaded by remember { mutableStateOf(false) }
    var sending by remember { mutableStateOf(false) }
    var note by remember { mutableStateOf<String?>(null) }

    // Live updates while the app is open.
    DisposableEffect(Unit) {
        val client = Wearable.getDataClient(context)
        val listener = DataClient.OnDataChangedListener { events ->
            events.forEach { event ->
                if (event.type == DataEvent.TYPE_CHANGED && event.dataItem.uri.path == WatchPaths.STATUS) {
                    status = PhoneStatus.from(DataMapItem.fromDataItem(event.dataItem).dataMap)
                    note = null
                }
            }
        }
        client.addListener(listener)
        onDispose { client.removeListener(listener) }
    }

    // Cached status first, then ask the phone for a fresh one.
    LaunchedEffect(Unit) {
        status = PhoneLink.loadStatus(context)
        loaded = true
        PhoneLink.send(context, WatchPaths.REFRESH)
    }

    fun sendCommand(path: String) {
        if (sending) return
        sending = true
        note = null
        scope.launch {
            val delivered = PhoneLink.send(context, path)
            if (!delivered) note = "Phone not reachable. Check Bluetooth and that Sentinel is installed on your phone."
            sending = false
        }
    }

    val listState = rememberScalingLazyListState()
    Scaffold(timeText = { TimeText() }) {
        ScalingLazyColumn(
            modifier = Modifier.fillMaxSize(),
            state = listState,
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            item {
                Text("Sentinel", color = Accent, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.title3)
            }

            val current = status
            if (current == null) {
                item {
                    Text(
                        if (loaded) "Open Sentinel on your phone once to connect." else "Loading…",
                        color = Muted,
                        textAlign = TextAlign.Center,
                        style = MaterialTheme.typography.body2,
                        modifier = Modifier.padding(horizontal = 12.dp)
                    )
                }
            } else {
                item { SeverityCounts(current) }
                item {
                    Text(
                        lastScanText(current),
                        color = Muted,
                        textAlign = TextAlign.Center,
                        style = MaterialTheme.typography.caption2,
                        modifier = Modifier.padding(horizontal = 10.dp)
                    )
                }
                if (current.scanning) {
                    item {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            CircularProgressIndicator(
                                progress = current.percent / 100f,
                                modifier = Modifier.size(28.dp),
                                indicatorColor = Accent,
                                strokeWidth = 3.dp
                            )
                            Text(
                                if (current.phase.isNotBlank()) "${current.phase} ${current.percent}%" else "Starting…",
                                style = MaterialTheme.typography.caption1
                            )
                        }
                    }
                }
            }

            item {
                val scanning = status?.scanning == true
                Chip(
                    onClick = { sendCommand(if (scanning) WatchPaths.CANCEL_SCAN else WatchPaths.START_SCAN) },
                    enabled = !sending,
                    label = { Text(if (scanning) "Cancel scan" else "Scan network") },
                    icon = {
                        Icon(
                            imageVector = if (scanning) Icons.Filled.Close else Icons.Filled.PlayArrow,
                            contentDescription = null
                        )
                    },
                    colors = if (scanning) ChipDefaults.secondaryChipColors() else ChipDefaults.primaryChipColors(),
                    modifier = Modifier.fillMaxWidth()
                )
            }

            item {
                Chip(
                    onClick = { sendCommand(WatchPaths.REFRESH) },
                    enabled = !sending,
                    label = { Text("Refresh") },
                    icon = { Icon(imageVector = Icons.Filled.Refresh, contentDescription = null) },
                    colors = ChipDefaults.secondaryChipColors(),
                    modifier = Modifier.fillMaxWidth()
                )
            }

            val message = note ?: status?.message?.takeIf { it.isNotBlank() && status?.scanning != true }
            if (message != null) {
                item {
                    Text(
                        message,
                        color = if (note != null || status?.isError == true) HighColor else Muted,
                        textAlign = TextAlign.Center,
                        style = MaterialTheme.typography.caption2,
                        modifier = Modifier.padding(horizontal = 12.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun SeverityCounts(status: PhoneStatus) {
    Row(horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.CenterVertically) {
        CountColumn(status.high, "High", HighColor)
        CountColumn(status.medium, "Med", MediumColor)
        CountColumn(status.low, "Low", LowColor)
    }
}

@Composable
private fun CountColumn(value: Int, label: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value.toString(), color = if (value > 0) color else Color.White, style = MaterialTheme.typography.title2)
        Text(label, color = Muted, style = MaterialTheme.typography.caption3)
    }
}

private fun lastScanText(status: PhoneStatus): String {
    if (status.lastScanAt <= 0L) return "No network scan yet"
    val ago = DateUtils.getRelativeTimeSpanString(status.lastScanAt)
    return "${status.devices} devices · ${status.network}\nLast scan $ago"
}
