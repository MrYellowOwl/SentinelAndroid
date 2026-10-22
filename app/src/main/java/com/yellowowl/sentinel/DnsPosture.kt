package com.yellowowl.sentinel

/**
 * Evaluates a domain's email/DNS security posture (SPF, DMARC, DKIM, DNSSEC, CAA) from its DNS
 * records and turns weaknesses into findings. Pure + unit tested; the lookups live in [NetToolsNet].
 */
object DnsPosture {
    data class DnsRecords(
        val domain: String,
        val spf: String? = null,        // the v=spf1 TXT at the apex, if any
        val dmarc: String? = null,      // the v=DMARC1 TXT at _dmarc, if any
        val dkimFound: Boolean = false, // a DKIM key at a common selector
        val caaPresent: Boolean = false,
        val dnssecPresent: Boolean = false,
        val hasMx: Boolean = false
    )

    /** The qualifier on the SPF "all" mechanism: '-' (fail), '~' (softfail), '?' (neutral), '+' (pass/any). */
    fun spfAllQualifier(spf: String?): Char? {
        val m = Regex("""([-~?+])all""", RegexOption.IGNORE_CASE).find(spf ?: return null) ?: return null
        return m.groupValues[1].first()
    }

    /** DMARC policy value: none / quarantine / reject, or null if absent/unparseable. */
    fun dmarcPolicy(dmarc: String?): String? {
        val m = Regex("""\bp\s*=\s*(none|quarantine|reject)""", RegexOption.IGNORE_CASE).find(dmarc ?: return null) ?: return null
        return m.groupValues[1].lowercase()
    }

    fun findings(scope: String, records: DnsRecords): List<Finding> {
        val out = ArrayList<Finding>()
        val host = records.domain
        fun f(title: String, sev: Severity, details: String, fix: String) =
            out.add(Finding(title = title, severity = sev, source = FindingSource.WEB, scope = scope, target = host, details = details, remediation = fix))

        // SPF
        when (val q = spfAllQualifier(records.spf)) {
            null -> if (records.spf == null)
                f("No SPF record", if (records.hasMx) Severity.MEDIUM else Severity.LOW,
                    "No SPF record found for $host, so receivers can't verify which servers may send mail as this domain — easing spoofing.",
                    "Publish an SPF TXT record ending in -all once you've listed every legitimate sender.")
            else
                f("SPF has no explicit 'all'", Severity.LOW,
                    "SPF record exists but lacks a terminal all mechanism, so enforcement is undefined.",
                    "End the SPF record with -all (hardfail) or ~all (softfail).")
            '+' -> f("SPF allows any sender (+all)", Severity.HIGH,
                "The SPF record ends in +all, which authorizes any server to send as $host — effectively no protection.",
                "Replace +all with -all and list only legitimate senders.")
            '?' -> f("SPF is neutral (?all)", Severity.MEDIUM,
                "The SPF record ends in ?all (neutral), so it provides no real enforcement.",
                "Tighten to ~all or -all after confirming your senders.")
            '~' -> f("SPF softfail (~all)", Severity.LOW,
                "SPF ends in ~all (softfail) — mail from unlisted servers is marked but usually still delivered.",
                "Move to -all once you're confident all senders are listed.")
            '-' -> f("SPF hardfail configured", Severity.INFO,
                "SPF ends in -all (hardfail) — a strong configuration.", "No action needed.")
        }

        // DMARC
        when (val p = dmarcPolicy(records.dmarc)) {
            null -> f("No DMARC record", if (records.hasMx) Severity.MEDIUM else Severity.LOW,
                "No DMARC policy at _dmarc.$host, so SPF/DKIM failures aren't acted on and you get no spoofing reports.",
                "Publish a DMARC record, starting at p=none to monitor, then move to quarantine/reject.")
            "none" -> f("DMARC in monitor-only mode (p=none)", Severity.LOW,
                "DMARC is published but p=none only monitors — spoofed mail isn't rejected.",
                "After reviewing aggregate reports, raise the policy to quarantine, then reject.")
            else -> f("DMARC enforced (p=$p)", Severity.INFO,
                "DMARC policy is p=$p — enforcing.", "No action needed.")
        }

        if (!records.dkimFound) f("DKIM not found at common selectors", Severity.INFO,
            "No DKIM key found at the selectors checked; this doesn't prove DKIM is missing, only that it couldn't be confirmed automatically.",
            "Verify your DKIM selector is published and signing outbound mail.")

        if (!records.caaPresent) f("No CAA record", Severity.LOW,
            "No CAA record for $host, so any certificate authority can issue certificates for it.",
            "Publish a CAA record naming only the CAs you use (e.g. letsencrypt.org).")

        if (!records.dnssecPresent) f("DNSSEC not enabled", Severity.LOW,
            "No DNSKEY found for $host — DNS responses aren't cryptographically signed and can be spoofed in transit.",
            "Enable DNSSEC signing at your DNS provider and add the DS record at the registrar.")

        out.add(Finding(
            title = "DNS/email posture summary", severity = Severity.INFO, source = FindingSource.WEB, scope = scope, target = host,
            details = "SPF: ${records.spf?.let { "present" } ?: "missing"} · DMARC: ${dmarcPolicy(records.dmarc)?.let { "p=$it" } ?: "missing"} · " +
                "DKIM: ${if (records.dkimFound) "found" else "unverified"} · CAA: ${if (records.caaPresent) "present" else "none"} · " +
                "DNSSEC: ${if (records.dnssecPresent) "on" else "off"} · MX: ${if (records.hasMx) "yes" else "no"}",
            remediation = "Aim for enforced SPF (-all), DMARC (quarantine/reject), DKIM signing, a CAA record, and DNSSEC."
        ))
        return out
    }

    /** Common DKIM selectors to probe (we can't enumerate them, so we check the usual ones). */
    val dkimSelectors = listOf("default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2")
}
