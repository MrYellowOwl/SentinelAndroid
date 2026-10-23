# Sentinel Security

[![CI](https://github.com/MrYellowOwl/SentinelAndroid/actions/workflows/ci.yml/badge.svg)](https://github.com/MrYellowOwl/SentinelAndroid/actions/workflows/ci.yml)

**A local-first network and website security scanner for Android, with a Wear OS companion.**

Sentinel audits the networks and websites you own or are authorized to assess — from your phone, with no accounts, analytics, or backend. It discovers and classifies devices, fingerprints services, matches versions against a continuously updated vulnerability feed, audits websites and TLS, and produces shareable reports. All assessment is **detection and reconnaissance only** — it never exploits, authenticates, or attacks.

Kotlin · Jetpack Compose · Android 8.0+ (API 26) · targets API 36.

---

## Features

**Network assessment**
- Device discovery on your private Wi-Fi/Ethernet network via TCP sweep, SSDP/mDNS/NetBIOS and SNMP, with naming, vendor/type classification, and MAC recovery from the router's ARP table where SNMP is readable.
- Service fingerprinting (SSH, FTP, SMTP, HTTP, MySQL/MariaDB, Redis, Memcached, Elasticsearch, BIND/unbound, Apache/nginx/IIS/Jetty/lighttpd/Tomcat…) with per-service risk flags, version→CVE matching, and specific fixes.
- Opt-in background monitoring that alerts on new/departed devices and port changes (matched by MAC, so a DHCP change isn't a false positive).

**Website audit**
- HTTP→HTTPS enforcement, TLS certificate validity and strength (signature algorithm, key size, self-signed), and a graded TLS inspection (protocol versions + cipher suites, A–F).
- Security headers (HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy), cookie flags (Secure/HttpOnly/SameSite), CORS reflection, Subresource Integrity, and a soft-404-aware sensitive-path sweep.
- Optional WordPress audit: version, user enumeration, XML-RPC, plugin/theme inventory with CVE matching, exposed-file checks.

**Prioritization & intelligence**
- Vulnerability matching against a database that ships inside the app (works offline) and auto-updates, covering the full CVE history of the services Sentinel fingerprints, with **CISA KEV** (actively-exploited) flags, **EPSS** exploitation-likelihood scores, and end-of-life software detection.
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

**1.18.6** — Network list polish. The device list is now a single clean card of flat rows with hairline dividers (Fing-style) instead of separate chunky cards, each row carries a device-type icon (router, printer, TV, camera, NAS, PC, phone, server, IoT…), and there are sort controls (IP, Name, Status) plus an "Online only" filter.

**1.18.5** — Cleaner device list (Fing-style). Devices are now compact rows — icon with an online/offline dot, name and IP, vendor and status — with open ports shown as a risk-coloured count (full details on tap) instead of a stack of chips. Fixed a glitch where the gateway could appear twice (a live row plus a stale "offline" twin) when its MAC was recovered on one scan but not the next, and stopped `null` from leaking into device subtitles.

**1.18.4** — Crash fix (root cause). A scan could record two devices under the same identity (e.g. one MAC seen on two IPs via the router's ARP table), which produced duplicate list keys and crashed the Network screen right after a scan. The merge now keeps one row per device, and existing saved data with duplicates is repaired on load — so networks saved before this fix open without crashing too.

**1.18.3** — Crash fix: the Network screen could crash when a saved network held two devices sharing an IP address (an offline device whose address was later reused by a new one), because the device list keyed its rows by IP. Rows are now keyed by a unique device identity.

**1.18.2** — Better hostname resolution. The scanner now asks the router's own DNS (PTR / in-addr.arpa) for each host's name before falling back to Android's resolver — home routers (dnsmasq and friends) name their DHCP clients, so far more devices show a real name instead of a bare IP. Names are also tidied (trailing dot and noisy `.lan`/`.home`/`.local` suffixes removed).

**1.18.1** — Fing-style per-network memory. Every network you scan is now saved separately and survives restarts: switch between saved networks, and each keeps its own device list with online/offline state and first-seen / last-seen times. Device entries show vendor, type, MAC, IP and open ports at a glance. This data is independent of Findings — clearing findings no longer touches it, and a network is only removed with the in-app **Forget** action.

**1.17.0** — Layout cleanup. The Tools tab's utilities are grouped into collapsible categories — Reachability & Discovery, DNS & Domain, Service Assessment, Exposure & Intel, and Utilities — so it reads as a tidy menu instead of one long scroll. Card padding is now consistent across every screen (less cramped, more uniform), and the Findings screen's export controls are tidied into an even row.

**1.16.0** — Broader, more reliable passive recon. The subdomain finder now queries crt.sh and Certspotter together and unions the results (each indexes certificates the other misses), with internal-resolving hosts listed first. The external-intel tool now works on domains as well as IPs (it resolves the domain for Shodan) and reports precisely why a lookup came back empty — bad key (401), rate limit (429), not indexed (404), or unreachable — instead of a single vague message. The website audit adds a dangerous-HTTP-methods check (read via OPTIONS, never exercised): it flags TRACE/TRACK (Cross-Site Tracing) and advertised PUT/DELETE/PATCH/CONNECT.

**1.15.1** — Fix and extend the subdomain finder. crt.sh often took longer than the old 15s timeout and its large responses could be truncated past the body cap (which silently parsed to "no results"); it now gets a 45s read timeout and a 16 MB cap, tolerates a truncated/non-JSON body by salvaging host names, falls back to Certspotter when crt.sh is slow or down, and reports a clear reason when both fail. Discovered subdomains are now resolved to their A records, with any that point at RFC 1918 (internal) addresses flagged — surfacing DNS that leaks internal infrastructure.

**1.15.0** — Closes the loop on the expanded CVE database by teaching Sentinel to fingerprint more services: Memcached (`version`), Elasticsearch (REST version, and an exposed-cluster warning), BIND/unbound (`version.bind` CHAOS query), and Jetty/lighttpd/Tomcat from their `Server` header — so hundreds of previously-dormant CVEs now match. Adds Elasticsearch/Memcached exposure checks, end-of-life flagging for PostgreSQL/Elasticsearch/BIND, and a note on version-based findings reminding you that distros backport fixes without changing the version string.

**1.14.0** — Much larger, fully-offline CVE database. The vulnerability feed now pulls the complete CVE history for every service Sentinel fingerprints (SSH, web, FTP, mail, database and DNS daemons) instead of a recent slice, with far better version-range extraction (inclusive/exclusive bounds and pinned versions), and the whole database is baked into the app so a fresh install matches CVEs with no network. The in-app Update still refreshes it between releases.

**1.13.2** — Website-audit accuracy: TLS certificate strength checks (broken/weak signature algorithms, undersized RSA/EC keys, self-signed certs) and a soft-404 guard that suppresses false positives on servers that answer 200 for every path.

**1.13.1** — In-app updater: when the OS hasn't granted Sentinel permission to install apps, it now opens the correct "allow this app to install" screen with a clear prompt instead of silently falling back to the GitHub page.

**1.13.0** — Accuracy improvements: SMBv1 detection (EternalBlue-era risk), deeper SPF/DMARC checks (multiple-record, >10-lookup limit, DMARC pct/rua), and a tightened SSH weak-algorithm classifier.

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
