package com.yellowowl.sentinel

import java.util.UUID

enum class Severity(val rank: Int, val label: String) {
    HIGH(3, "High"),
    MEDIUM(2, "Medium"),
    LOW(1, "Low"),
    INFO(0, "Info");

    companion object {
        fun parse(value: String?): Severity = when (value?.trim()?.uppercase()) {
            "CRITICAL", "HIGH" -> HIGH
            "MEDIUM" -> MEDIUM
            "LOW" -> LOW
            else -> INFO
        }
    }
}

object FindingSource {
    const val NETWORK = "Network scan"
    const val WEB = "Website audit"
}

/** Operator's triage state for a finding during a walkthrough. */
enum class FindingStatus(val label: String) {
    NEW("New"),
    VERIFIED("Verified"),
    FALSE_POSITIVE("False positive"),
    FIXED("Fixed");

    companion object {
        fun parse(value: String?): FindingStatus = entries.firstOrNull { it.name == value } ?: NEW
    }
}

/** Per-finding triage annotation, kept separately so it survives rescans (keyed by [Finding.key]). */
data class FindingAnnotation(
    val status: FindingStatus = FindingStatus.NEW,
    val notes: String = "",
    val updatedAt: Long = System.currentTimeMillis()
) {
    val isDefault: Boolean get() = status == FindingStatus.NEW && notes.isBlank()
}

/**
 * A single saved result. [scope] identifies the run it belongs to (the LAN CIDR or the website host),
 * so a new scan of the same scope replaces the previous results instead of piling up duplicates.
 */
data class Finding(
    val id: String = UUID.randomUUID().toString(),
    val title: String,
    val severity: Severity,
    val source: String,
    val scope: String,
    val target: String,
    val details: String,
    val remediation: String,
    val createdAt: Long = System.currentTimeMillis()
) {
    /** Stable identity of the underlying issue, independent of scan run, so annotations re-attach on rescan. */
    val key: String get() = "$source|$scope|$target|$title"

    /** IP portion of a network finding's "ip:port" target, for grouping by host. */
    val hostIp: String? get() = if (source == FindingSource.NETWORK) target.substringBefore(':').ifBlank { null } else null
}

data class PortFinding(
    val port: Int,
    val service: String,
    val fingerprint: ServiceFingerprint? = null
) {
    /** e.g. "SSH (OpenSSH 8.2p1)" or just "SSH" when no banner was read. */
    val label: String get() = fingerprint?.let { "$service (${it.display})" } ?: service
}

data class DeviceResult(
    val ipAddress: String,
    val openPorts: List<PortFinding>,
    val hostname: String? = null,
    val identity: DeviceIdentity? = null,
    val isThisDevice: Boolean = false,
    val isGateway: Boolean = false
) {
    /** Best display name: a discovered name, else reverse-DNS, else the IP. */
    val displayName: String get() = identity?.name?.takeIf { it.isNotBlank() } ?: hostname ?: ipAddress
    val vendor: String? get() = identity?.vendor
    val model: String? get() = identity?.model
    val kind: String? get() = identity?.kind
    val mac: String? get() = identity?.mac
}

data class LocalNetworkRange(
    val cidr: String,
    val phoneIp: String,
    val firstHost: Long,
    val lastHost: Long,
    val prefixLength: Int,
    val gatewayIp: String? = null
) {
    val hostCount: Int get() = (lastHost - firstHost + 1).coerceAtLeast(0).toInt()
    fun hosts(): List<String> =
        if (lastHost < firstHost) emptyList() else (firstHost..lastHost).map(Ipv4::format)
}

data class NetworkScanResult(
    val cidr: String,
    val scannedHosts: Int,
    val devices: List<DeviceResult>,
    val durationMillis: Long
)

data class WebsiteAuditResult(
    val requestedUrl: String,
    val finalUrl: String,
    val statusCode: Int?,
    val redirectChain: List<String>,
    val findings: List<Finding>
)

/** Pure list operations for saved findings (kept separate from storage so they can be unit tested). */
object FindingMerge {
    /**
     * Replaces every saved finding from the same [source] and [scope] with [newRun].
     * Issues that were fixed since the last scan therefore disappear, and rescans never duplicate.
     */
    fun replaceRun(
        existing: List<Finding>,
        source: String,
        scope: String,
        newRun: List<Finding>,
        max: Int
    ): List<Finding> {
        val kept = existing.filterNot { it.source == source && it.scope.equals(scope, ignoreCase = true) }
        return (newRun + kept)
            .distinctBy { it.id }
            .sortedByDescending { it.createdAt }
            .take(max)
    }

    fun remove(existing: List<Finding>, id: String): List<Finding> = existing.filterNot { it.id == id }

    /** Replaces findings for one host (same source/scope and IP) with a fresh single-host scan. */
    fun replaceHost(
        existing: List<Finding>,
        source: String,
        scope: String,
        hostIp: String,
        newRun: List<Finding>,
        max: Int
    ): List<Finding> {
        val kept = existing.filterNot {
            it.source == source && it.scope.equals(scope, ignoreCase = true) && it.hostIp == hostIp
        }
        return (newRun + kept)
            .distinctBy { it.id }
            .sortedByDescending { it.createdAt }
            .take(max)
    }

    /** Hides findings the operator marked fixed or false-positive, unless [includeResolved]. */
    fun visible(
        findings: List<Finding>,
        annotations: Map<String, FindingAnnotation>,
        includeResolved: Boolean = false
    ): List<Finding> = if (includeResolved) findings else findings.filter {
        when (annotations[it.key]?.status) {
            FindingStatus.FIXED, FindingStatus.FALSE_POSITIVE -> false
            else -> true
        }
    }

    /** Highest severity first, newest first within a severity. */
    fun prioritized(findings: List<Finding>): List<Finding> =
        findings.sortedWith(compareByDescending<Finding> { it.severity.rank }.thenByDescending { it.createdAt })

    fun countBySeverity(findings: List<Finding>): Map<Severity, Int> =
        Severity.entries.associateWith { severity -> findings.count { it.severity == severity } }
}
