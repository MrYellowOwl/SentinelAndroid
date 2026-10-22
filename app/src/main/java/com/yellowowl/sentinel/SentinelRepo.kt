package com.yellowowl.sentinel

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * App-wide source of truth for saved findings. Shared by the UI, background scans and the watch bridge,
 * so every surface sees the same list.
 */
object SentinelRepo {
    private val lock = Mutex()
    private val _findings = MutableStateFlow<List<Finding>>(emptyList())
    val findings: StateFlow<List<Finding>> = _findings.asStateFlow()

    private val _annotations = MutableStateFlow<Map<String, FindingAnnotation>>(emptyMap())
    val annotations: StateFlow<Map<String, FindingAnnotation>> = _annotations.asStateFlow()

    @Volatile private var appContext: Context? = null

    /** Called from [SentinelApplication.onCreate]. */
    fun init(context: Context) {
        if (appContext != null) return
        synchronized(this) {
            if (appContext != null) return
            val app = context.applicationContext
            _findings.value = FindingStore.load(app)
            _annotations.value = AnnotationStore.load(app)
            appContext = app
        }
    }

    private fun context(): Context = checkNotNull(appContext) { "SentinelRepo.init() was not called." }

    suspend fun replaceRun(source: String, scope: String, run: List<Finding>) =
        mutate { FindingStore.replaceRun(context(), source, scope, run) }

    suspend fun replaceHost(source: String, scope: String, hostIp: String, run: List<Finding>) =
        mutate { FindingStore.replaceHost(context(), source, scope, hostIp, run) }

    suspend fun remove(id: String) = mutate { FindingStore.remove(context(), id) }

    suspend fun clear() = mutate {
        FindingStore.clear(context())
        emptyList()
    }

    fun setAnnotation(key: String, annotation: FindingAnnotation) {
        _annotations.value = AnnotationStore.put(context(), key, annotation)
    }

    private suspend fun mutate(block: () -> List<Finding>) {
        val updated = withContext(Dispatchers.IO) { lock.withLock { block() } }
        _findings.value = updated
        WatchSync.publish(context())
    }
}
