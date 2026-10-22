package com.yellowowl.sentinel

import android.app.Application

class SentinelApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        SentinelRepo.init(this)
        VulnStore.init(this)
        HistoryStore.init(this)
        NicknameStore.init(this)
        Notifier.createChannels(this)
    }
}
