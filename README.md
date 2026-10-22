# Sentinel Security

[![CI](https://github.com/MrYellowOwl/SentinelAndroid/actions/workflows/ci.yml/badge.svg)](https://github.com/MrYellowOwl/SentinelAndroid/actions/workflows/ci.yml)

**A local-first network and website security scanner for Android, with a Wear OS companion.**

Sentinel audits the networks and websites you own or are authorized to assess — from your phone, with no accounts, analytics, or backend. It discovers and classifies devices, fingerprints services, matches versions against a continuously updated vulnerability feed, audits websites and TLS, and produces shareable reports. All assessment is **detection and reconnaissance only** — it never exploits, authenticates, or attacks.

Kotlin · Jetpack Compose · Android 8.0+ (API 26) · targets API 36.

---

## Features

**Network assessment**
- Device discovery on your private Wi-Fi/Ethernet network via TCP sweep, SSDP/mDNS/NetBIOS and SNMP, with naming, vendor/type classification, and MAC recovery from the router's ARP table where SNMP is readable.
- Service fingerprinting (SSH, FTP, SMTP, HTTP, MySQL/MariaDB, Redis…) with per-service risk flags and specific fixes.
- Opt-in background monitoring that alerts on new/departed devices and port changes (matched by MAC, so a DHCP change isn't a false positive).

**Website audit**
- HTTP→HTTPS enforcement, TLS certificate validity, and a graded TLS inspection (protocol versions + cipher suites, A–F).
- Security headers (HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy), cookie flags (Secure/HttpOnly/SameSite), CORS reflection, Subresource Integrity, and a sensitive-path sweep.
- Optional WordPress audit: version, user enumeration, XML-RPC, plugin/theme inventory with CVE matching, exposed-file checks.

**Prioritization & intelligence**
- Vulnerability matching against a live feed with **CISA KEV** (actively-exploited) flags, **EPSS** exploitation-likelihood scores, and end-of-life software detection.
- Optional external intel (bring-your-own API key): Shodan host exposure and VirusTotal reputation.

**Tools**
- Ping, DNS lookup, port scan, WHOIS, subnet calculator, MAC-vendor lookup, Wake-on-LAN, internet speed test, nearby-Wi-Fi scanner.
- DNS/email posture (SPF/DMARC/DKIM/CAA/DNSSEC), CT-log subdomain finder, SSH algorithm audit, SMB signing check, SNMP info, and a public-IP exposure check.

**Reporting**
- Findings sorted by severity, filterable, with status tracking and notes; OWASP Top 10 and CIS Controls tags on every finding.
- Export as HTML, PDF, CSV or JSON, with an executive summary and optional engagement-scope flagging.

**Platform**
- Cyber Contrast (OLED dark) and Light themes; scan history with trends; scheduled scans.
- Wear OS companion (status + start/cancel scans) on Wear OS 3+; mirrored alerts to other paired watches, including Tizen Galaxy models.
- In-app updates from GitHub Releases.

---

## Install

1. Download the latest `.apk` from the [Releases](../../releases) page.
2. Open it on your phone and allow "install unknown apps" when prompted.
3. After the first install, updates are automatic: **Settings → Updates → Check for updates**.

**Requirements:** Android 8.0 (API 26) or newer. Network scanning requires a real device on Wi-Fi.

## Build from source

Open the project in a recent Android Studio with SDK Platform 36, let Gradle sync, and run the `app` configuration on a device or emulator.

```bash
./gradlew :app:assembleDebug        # debug APK → app/build/outputs/apk/debug/
./gradlew :app:testDebugUnitTest    # unit tests
```

> Network scanning needs a physical phone on Wi-Fi — an emulator only sees its own virtual network.

## Responsible use

Sentinel is for assessing systems you **own or are explicitly authorized to test**. It enforces a scope guard (private RFC 1918 ranges only, limited to the phone's /24, with per-network authorization), and every check is non-intrusive: ordinary connections and reads, no exploitation, credential testing, payloads, or fuzzing. Missing-header and version-based findings are indicators to verify in context, not proof of exploitability. You are responsible for having authorization for anything you scan.

## Limits

- No ICMP ping sweep, SYN scan, OS fingerprinting, or hop-by-hop traceroute — these need raw sockets/root, which an unprivileged Android app can't use.
- Discovery relies on TCP behavior; devices that silently drop all connections may be missed.
- ARP/MAC recovery works only where a router or managed device exposes SNMP.

## Privacy

No accounts, analytics, or backend. Findings stay on your device (and, for the watch companion, the paired watch via the Wear OS Data Layer). Data is excluded from cloud backup and device transfer, and nothing leaves your devices unless you share a report. See [PRIVACY.md](PRIVACY.md).

## License

Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE). You're free to use, modify, and redistribute it, including commercially, provided you retain the license and attribution notices. The license includes an explicit patent grant and provides the software "as is," without warranty.

---

## Changelog

**1.12.0** — External intel: Shodan host lookup and VirusTotal reputation (bring-your-own-key, passive/read-only).

**1.11.0** — OWASP/CIS compliance tags on findings and exports; engagement scope with out-of-scope flagging; executive summary; Save-as-PDF.

**1.10.0** — Deeper web checks (CORS reflection, cookie SameSite, security.txt, SRI, sensitive-path sweep); SSH algorithm audit; SMB signing check; SNMP default-community info.

**1.9.0** — CISA KEV tagging and EPSS scores in prioritization; end-of-life software flagging; DNS/email posture (SPF/DMARC/DKIM/CAA/DNSSEC).

**1.8.0** — Graded TLS/SSL inspection (protocols + ciphers); CT-log subdomain finder; device nicknames.

**1.7.0** — Scan history & trends; CSV/JSON export; scheduled scans; public-IP exposure check.

**1.6.0** — Cyber Contrast / Light themes; Settings screen; in-app updates; auto-updating exploit feed.

**1.5.x** — PHP2Shell (CVE-2026-109618/9) detection; network monitoring; speed test; nearby-Wi-Fi scanner.

**1.4.0** — Tools tab (ping, DNS, port scan, WHOIS, subnet, MAC vendor, Wake-on-LAN); offline device-type inference.

**1.3.x** — WordPress audit; laptop-handoff command generation.

**1.2.0** — SNMP recon and ARP-table MAC recovery; scan-depth profiles; two-stage mDNS.

**1.1.0** — Per-host walkthrough; CVE matching; discovery engine (SSDP/mDNS/NetBIOS) and service fingerprinting.

**1.0.0** — Initial release: network scan, website audit, phone/watch alerts, background-safe scans, signed release build.
