package com.yellowowl.sentinel

import android.content.Context

/** Small persisted preferences: authorized networks, alert opt-in and a summary of the last scan. */
object SentinelSettings {
    private const val PREFS = "sentinel_settings"
    private const val KEY_AUTHORIZED = "authorized_cidrs"
    private const val KEY_ALERTS = "alerts_enabled"
    private const val KEY_LAST_CIDR = "last_scan_cidr"
    private const val KEY_LAST_AT = "last_scan_at"
    private const val KEY_LAST_DEVICES = "last_scan_devices"
    private const val KEY_FEED_URL = "vuln_feed_url"
    private const val KEY_SCAN_PROFILE = "scan_profile"
    private const val KEY_THEME_LIGHT = "theme_light"
    private const val KEY_SCAN_SCHEDULE = "scan_schedule"
    private const val KEY_SCOPE = "engagement_scope"
    private const val KEY_SHODAN = "shodan_key"
    private const val KEY_VT = "virustotal_key"

    data class LastScan(val cidr: String, val at: Long, val devices: Int)

    fun isAuthorized(context: Context, cidr: String): Boolean =
        prefs(context).getStringSet(KEY_AUTHORIZED, emptySet()).orEmpty().contains(cidr)

    /** Background scans (watch, "Scan again") only run on networks the user has confirmed here. */
    fun setAuthorized(context: Context, cidr: String, authorized: Boolean) {
        val updated = prefs(context).getStringSet(KEY_AUTHORIZED, emptySet()).orEmpty().toMutableSet()
        if (authorized) updated += cidr else updated -= cidr
        prefs(context).edit().putStringSet(KEY_AUTHORIZED, updated).apply()
    }

    fun alertsEnabled(context: Context): Boolean = prefs(context).getBoolean(KEY_ALERTS, false)

    fun setAlertsEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_ALERTS, enabled).apply()
    }

    fun lastScan(context: Context): LastScan? {
        val p = prefs(context)
        val cidr = p.getString(KEY_LAST_CIDR, null) ?: return null
        return LastScan(cidr, p.getLong(KEY_LAST_AT, 0L), p.getInt(KEY_LAST_DEVICES, 0))
    }

    fun saveLastScan(context: Context, scan: LastScan) {
        prefs(context).edit()
            .putString(KEY_LAST_CIDR, scan.cidr)
            .putLong(KEY_LAST_AT, scan.at)
            .putInt(KEY_LAST_DEVICES, scan.devices)
            .apply()
    }

    fun scanProfile(context: Context): ScanProfile = ScanProfile.parse(prefs(context).getString(KEY_SCAN_PROFILE, null))

    fun setScanProfile(context: Context, profile: ScanProfile) {
        prefs(context).edit().putString(KEY_SCAN_PROFILE, profile.name).apply()
    }

    /** Theme: false = Cyber Contrast (default dark), true = Light & Crisp. */
    fun themeLight(context: Context): Boolean = prefs(context).getBoolean(KEY_THEME_LIGHT, false)

    fun setThemeLight(context: Context, light: Boolean) {
        prefs(context).edit().putBoolean(KEY_THEME_LIGHT, light).apply()
    }

    fun scanSchedule(context: Context): ScanSchedule = ScanSchedule.parse(prefs(context).getString(KEY_SCAN_SCHEDULE, null))

    fun setScanSchedule(context: Context, schedule: ScanSchedule) {
        prefs(context).edit().putString(KEY_SCAN_SCHEDULE, schedule.name).apply()
    }

    fun shodanKey(context: Context): String = prefs(context).getString(KEY_SHODAN, "").orEmpty()
    fun setShodanKey(context: Context, key: String) { prefs(context).edit().putString(KEY_SHODAN, key.trim()).apply() }
    fun virusTotalKey(context: Context): String = prefs(context).getString(KEY_VT, "").orEmpty()
    fun setVirusTotalKey(context: Context, key: String) { prefs(context).edit().putString(KEY_VT, key.trim()).apply() }

    fun scopeText(context: Context): String = prefs(context).getString(KEY_SCOPE, "").orEmpty()

    fun setScopeText(context: Context, text: String) {
        prefs(context).edit().putString(KEY_SCOPE, text.trim()).apply()
    }

    fun feedUrl(context: Context): String =
        prefs(context).getString(KEY_FEED_URL, null)?.takeIf { it.isNotBlank() } ?: VulnFeed.DEFAULT_FEED_URL

    fun setFeedUrl(context: Context, url: String) {
        prefs(context).edit().putString(KEY_FEED_URL, url.trim()).apply()
    }

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
