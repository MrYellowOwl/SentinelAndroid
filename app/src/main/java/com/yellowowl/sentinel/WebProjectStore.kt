package com.yellowowl.sentinel

import android.content.Context
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Persists saved web-intake client projects (see [WebProject]). Survives app restarts. Projects are
 * only removed by an explicit action; each saved run keeps its rendered HTML snapshot.
 */
object WebProjectStore {
    private const val FILE = "web_projects.json"
    private val _projects = MutableStateFlow<List<ClientProject>>(emptyList())
    val projects: StateFlow<List<ClientProject>> = _projects.asStateFlow()

    @Volatile private var loaded = false

    fun init(context: Context) {
        if (loaded) return
        synchronized(this) {
            if (loaded) return
            _projects.value = runCatching { WebProjectCodec.decode(file(context).readText()) }.getOrDefault(emptyList())
            loaded = true
        }
    }

    private fun file(context: Context) = File(context.applicationContext.filesDir, FILE)

    private fun persist(context: Context, projects: List<ClientProject>) {
        _projects.value = projects.sortedByDescending { it.lastRun }
        runCatching { file(context).writeText(WebProjectCodec.encode(_projects.value)) }
    }

    /** Appends a run to the matching client project (creating it if new), capping run history. */
    fun saveRun(context: Context, profile: SiteProfile, html: String) {
        val app = context.applicationContext
        init(app)
        val now = System.currentTimeMillis()
        val run = WebProjectCodec.runFromProfile(profile, html)
        val existing = _projects.value
        val prior = existing.firstOrNull { it.domain.equals(profile.domain, ignoreCase = true) }
        val updated = if (prior != null) {
            prior.copy(runs = (listOf(run) + prior.runs).sortedByDescending { it.at }.take(WebProjectCodec.MAX_RUNS))
        } else {
            ClientProject(domain = profile.domain, label = profile.businessName ?: profile.domain, firstSeen = now, runs = listOf(run))
        }
        persist(app, existing.filterNot { it.domain.equals(profile.domain, ignoreCase = true) } + updated)
    }

    fun remove(context: Context, domain: String) {
        val app = context.applicationContext
        init(app)
        persist(app, _projects.value.filterNot { it.domain.equals(domain, ignoreCase = true) })
    }
}
