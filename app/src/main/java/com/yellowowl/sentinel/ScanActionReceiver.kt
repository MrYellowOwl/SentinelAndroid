package com.yellowowl.sentinel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Handles the "Scan again" notification action (also shown on mirrored watch notifications). */
class ScanActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_SCAN) ScanRunner.request(context)
    }

    companion object {
        const val ACTION_SCAN = "com.yellowowl.sentinel.action.SCAN_AGAIN"
    }
}
