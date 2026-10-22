package com.yellowowl.sentinel

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class WpAuditResult(
    val isWordPress: Boolean,
    val signals: WpSignals? = null,
    val findings: List<Finding> = emptyList()
)

/**
 * Runs the WordPress checks against a host: detection, version, user enumeration, XML-RPC, plugin/theme
 * inventory + CVE matching, and sensitive-file exposure. All plain GETs — no login attempts, no exploitation.
 */
object WpAudit {
    private val backupPaths = listOf(
        "/wp-config.php.bak", "/wp-config.php.save", "/wp-config.php~", "/wp-config.php.old", "/wp-config.php.txt"
    )

    suspend fun audit(host: String, scope: String, matcher: VulnMatcher): WpAuditResult = withContext(Dispatchers.IO) {
        val base = "https://$host"
        val home = Http.get("$base/") ?: return@withContext WpAuditResult(false)
        val signals = WpScan.detect(home.body, home.headers)
        if (!signals.isWordPress) return@withContext WpAuditResult(false)

        val findings = ArrayList<Finding>()

        // Version: generator tag, else readme.html (which is itself an exposure).
        var version = signals.version
        val readme = Http.get("$base/readme.html")
        if (readme != null && readme.code == 200 && readme.body.contains("WordPress", ignoreCase = true)) {
            findings += WpScan.exposureFinding(scope, host, "/readme.html")
            if (version == null) version = WpScan.versionFromReadme(readme.body)
        }
        version?.let { findings += WpScan.versionFinding(scope, host, it) }

        // User enumeration via REST and author archive.
        val usersResp = Http.get("$base/wp-json/wp/v2/users")
        val users = if (usersResp != null && usersResp.code == 200) WpScan.parseUsers(usersResp.body) else emptyList()
        val authorResp = Http.get("$base/?author=1", followRedirects = false)
        val authorSlug = WpScan.authorSlug(authorResp?.header("location"))
        findings += WpScan.userFindings(scope, host, users, authorSlug)

        // XML-RPC.
        val xmlrpc = Http.get("$base/xmlrpc.php")
        if (xmlrpc != null && WpScan.xmlrpcEnabled(xmlrpc.code, xmlrpc.body)) findings += WpScan.xmlrpcFinding(scope, host)

        // Sensitive-file exposure.
        for (path in backupPaths) {
            val r = Http.get(base + path) ?: continue
            if (r.code == 200 && r.body.contains("DB_", ignoreCase = false)) {
                findings += WpScan.exposureFinding(scope, host, path); break
            }
        }
        Http.get("$base/.git/config")?.let { r ->
            if (r.code == 200 && (r.body.contains("[core]") || r.body.contains("repositoryformatversion"))) {
                findings += WpScan.exposureFinding(scope, host, "/.git/config")
            }
        }
        Http.get("$base/wp-content/debug.log")?.let { r ->
            if (r.code == 200 && r.body.isNotBlank() && !r.body.contains("<html", ignoreCase = true)) {
                findings += WpScan.exposureFinding(scope, host, "/wp-content/debug.log")
            }
        }
        Http.get("$base/wp-content/uploads/")?.let { r ->
            if (r.code == 200 && r.body.contains("Index of", ignoreCase = true)) {
                findings += WpScan.exposureFinding(scope, host, "/wp-content/uploads/")
            }
        }

        // Plugin/theme inventory + CVE matching.
        WpScan.inventoryFinding(scope, host, signals)?.let { findings += it }
        findings += WpScan.assetCveFindings(scope, host, signals, matcher)

        WpAuditResult(true, signals.copy(version = version), FindingMerge.prioritized(findings))
    }
}
