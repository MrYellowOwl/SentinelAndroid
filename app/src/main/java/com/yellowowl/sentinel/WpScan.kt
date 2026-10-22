package com.yellowowl.sentinel

import org.json.JSONArray

/**
 * WordPress-specific detection and findings. Pure parsing (no I/O) so it is unit tested; the HTTP requests
 * live in [WpAudit]. Every check is a plain GET — no login attempts, no exploitation.
 */

data class WpAsset(val slug: String, val version: String?)
data class WpUser(val id: Int?, val name: String?, val slug: String?)

data class WpSignals(
    val isWordPress: Boolean,
    val version: String? = null,
    val generator: String? = null,
    val plugins: List<WpAsset> = emptyList(),
    val themes: List<WpAsset> = emptyList()
)

object WpScan {
    private val PLUGIN_RE = Regex("""/wp-content/plugins/([a-z0-9][a-z0-9_-]+)/[^"'?\s]*(?:\?ver=([0-9][\w.\-]*))?""", RegexOption.IGNORE_CASE)
    private val THEME_RE = Regex("""/wp-content/themes/([a-z0-9][a-z0-9_-]+)/[^"'?\s]*(?:\?ver=([0-9][\w.\-]*))?""", RegexOption.IGNORE_CASE)
    private val GENERATOR_RE = Regex("""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']*WordPress[^"']*)["']""", RegexOption.IGNORE_CASE)
    private val WP_VERSION_RE = Regex("""WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)""", RegexOption.IGNORE_CASE)
    private val README_VERSION_RE = Regex("""Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)""", RegexOption.IGNORE_CASE)

    fun detect(html: String, headers: Map<String, List<String>>): WpSignals {
        val linkHeader = headers["link"]?.joinToString(" ").orEmpty()
        val isWp = html.contains("/wp-content/", true) || html.contains("/wp-includes/", true) ||
            GENERATOR_RE.containsMatchIn(html) || linkHeader.contains("/wp-json/", true)
        if (!isWp) return WpSignals(false)

        val generator = GENERATOR_RE.find(html)?.groupValues?.get(1)?.trim()
        val version = generator?.let { WP_VERSION_RE.find(it)?.groupValues?.get(1) }
        return WpSignals(
            isWordPress = true,
            version = version,
            generator = generator,
            plugins = assets(PLUGIN_RE, html),
            themes = assets(THEME_RE, html)
        )
    }

    private fun assets(regex: Regex, html: String): List<WpAsset> =
        regex.findAll(html)
            .map { WpAsset(it.groupValues[1].lowercase(), it.groupValues[2].ifBlank { null }) }
            .groupBy { it.slug }
            .map { (slug, list) -> WpAsset(slug, list.firstNotNullOfOrNull { it.version }) }
            .sortedBy { it.slug }

    fun versionFromReadme(readmeHtml: String): String? =
        README_VERSION_RE.find(readmeHtml)?.groupValues?.get(1)

    /** Parses the /wp-json/wp/v2/users response (a JSON array of {id,name,slug}). */
    fun parseUsers(json: String): List<WpUser> = try {
        val array = JSONArray(json)
        buildList {
            for (i in 0 until array.length()) {
                val o = array.optJSONObject(i) ?: continue
                add(WpUser(
                    id = if (o.has("id")) o.optInt("id") else null,
                    name = o.optString("name").ifBlank { null },
                    slug = o.optString("slug").ifBlank { null }
                ))
            }
        }
    } catch (_: Exception) {
        emptyList()
    }

    /** From an ?author=1 redirect Location like ".../author/admin/", the username slug. */
    fun authorSlug(location: String?): String? {
        if (location.isNullOrBlank()) return null
        val match = Regex("""/author/([^/?#]+)""", RegexOption.IGNORE_CASE).find(location) ?: return null
        return match.groupValues[1].takeIf { it.isNotBlank() }
    }

    /** True when an xmlrpc.php GET response indicates the endpoint is live (WP replies 405 to GET). */
    fun xmlrpcEnabled(statusCode: Int, body: String): Boolean =
        statusCode == 405 || body.contains("XML-RPC server accepts POST requests only", ignoreCase = true)

    // ---- findings ----

    private fun web(scope: String, host: String, title: String, severity: Severity, details: String, fix: String) =
        Finding(title = title, severity = severity, source = FindingSource.WEB, scope = scope, target = host, details = details, remediation = fix)

    fun userFindings(scope: String, host: String, users: List<WpUser>, authorSlug: String?): List<Finding> {
        val names = (users.mapNotNull { it.slug ?: it.name } + listOfNotNull(authorSlug)).distinct()
        if (names.isEmpty()) return emptyList()
        val via = buildList {
            if (users.isNotEmpty()) add("the REST API (/wp-json/wp/v2/users)")
            if (authorSlug != null) add("author archives (?author=1)")
        }.joinToString(" and ")
        return listOf(web(
            scope, host, "WordPress usernames are enumerable", Severity.MEDIUM,
            "Valid usernames are exposed through $via: ${names.take(8).joinToString(", ")}${if (names.size > 8) " and ${names.size - 8} more" else ""}. These are half of a password-guessing attack.",
            "Block /wp-json/wp/v2/users for anonymous users, disable author archives or change the author slug, and require strong passwords plus login rate-limiting."
        ))
    }

    fun xmlrpcFinding(scope: String, host: String): Finding = web(
        scope, host, "XML-RPC is enabled", Severity.MEDIUM,
        "xmlrpc.php is reachable. It can be abused for brute-force amplification (system.multicall) and pingback-based attacks.",
        "Disable XML-RPC if unused (block xmlrpc.php or use a plugin). If needed, restrict it and rate-limit requests."
    )

    fun versionFinding(scope: String, host: String, version: String): Finding = web(
        scope, host, "WordPress version disclosed ($version)", Severity.INFO,
        "The WordPress version is published in the page's generator tag or readme.html, helping an attacker pick version-specific exploits.",
        "Remove the generator meta tag and delete /readme.html. Keep core updated regardless."
    )

    /** Exposed file. [severity] and messaging depend on which path leaked. */
    fun exposureFinding(scope: String, host: String, path: String): Finding {
        val (severity, what, fix) = when {
            path.contains("wp-config") -> Triple(Severity.HIGH, "A wp-config backup is downloadable, which can contain database credentials and secret keys.", "Delete the backup immediately, rotate the DB password and salts, and block access to wp-config* files.")
            path.contains(".git") -> Triple(Severity.HIGH, "The .git directory is exposed, allowing the full source (and often secrets) to be reconstructed.", "Block access to /.git and don't deploy the repository to the web root.")
            path.contains("debug.log") -> Triple(Severity.MEDIUM, "wp-content/debug.log is readable and may leak paths, queries and errors.", "Turn off WP_DEBUG_LOG in production and block access to the file.")
            path.contains("uploads") -> Triple(Severity.LOW, "Directory listing is enabled on the uploads folder, exposing all uploaded files.", "Disable directory listing (Options -Indexes) and add an index file.")
            else -> Triple(Severity.INFO, "A file that usually should not be public is reachable.", "Remove or block access to the file.")
        }
        return web(scope, host, "Exposed: $path", severity, what, fix)
    }

    /** An informational inventory of the plugins/themes detected in the page source. */
    fun inventoryFinding(scope: String, host: String, signals: WpSignals): Finding? {
        if (signals.plugins.isEmpty() && signals.themes.isEmpty()) return null
        fun list(assets: List<WpAsset>) = assets.joinToString(", ") { a -> a.version?.let { "${a.slug} $it" } ?: a.slug }
        val parts = buildList {
            if (signals.plugins.isNotEmpty()) add("Plugins: ${list(signals.plugins)}")
            if (signals.themes.isNotEmpty()) add("Themes: ${list(signals.themes)}")
        }
        return web(
            scope, host, "WordPress components detected", Severity.INFO,
            parts.joinToString("\n") + "\nDetected from the public page source; versions may be hidden or spoofed.",
            "Keep plugins and themes updated, remove unused ones, and consider hiding version query strings."
        )
    }

    /** Runs each detected plugin/theme version through the CVE matcher. */
    fun assetCveFindings(scope: String, host: String, signals: WpSignals, matcher: VulnMatcher): List<Finding> =
        (signals.plugins + signals.themes).flatMap { asset ->
            val version = asset.version ?: return@flatMap emptyList()
            val fp = ServiceFingerprint(asset.slug, version)
            matcher.match(fp).map { it.toFinding(scope, host, 443, fp) }
        }
}
