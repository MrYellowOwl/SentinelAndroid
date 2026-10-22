# Sentinel Security (Android) — v1.0.0

A local-first security checkup for your own network and websites. Kotlin + Jetpack Compose, Android 8.0+ (API 26), targets API 36.

**Theme:** ships in **Cyber Contrast** (true-black OLED, cyan + magenta). A **Light & Crisp** light mode is a one-tap toggle in **Settings → Appearance** (the gear icon, top-right).

**What it does**
- **Network scan**: finds devices on the current private Wi-Fi/Ethernet network (your /24 only) via TCP sweep, SSDP/mDNS/NetBIOS and SNMP; names and classifies them, recovers MAC/vendor from the router's ARP table where SNMP is readable, marks your phone and router, and flags risky open services (Telnet, VNC, exposed Docker, SMB, RDP, databases, etc.) with specific fixes.
- **Website audit**: follows redirects step by step, checks HTTP→HTTPS enforcement, TLS certificate validity/expiry/hostname, HSTS, CSP, clickjacking, nosniff, Referrer-Policy, cookie flags and version disclosure.
- **Findings**: sorted by severity, filterable, dismissible. Re-running a scan replaces that network's/site's previous results, so fixed issues disappear. Share as an HTML report.
- **Alerts (phone + watch)**: optional notifications when a network scan finishes or finds high-severity issues, with a **Scan again** button. Paired watches mirror them automatically, **including Tizen Galaxy watches like the Active 2**.
- **Wear OS app** (`wear/` module): shows High/Medium/Low counts and last scan, and starts, cancels or refreshes a scan on the phone. Works on Galaxy Watch 4 or newer and Pixel Watch (Wear OS 3+). It can't run on Tizen watches (Active 2, Watch 3 and older); those get the mirrored alerts instead.
- Private by design: no accounts, analytics or backend. Data is excluded from cloud backup and device transfer.

## Build and run

1. Open this folder in a current Android Studio (Narwhal or newer) with SDK Platform 36 installed.
2. Let Gradle sync, then run the `app` configuration on a device or emulator.

Command line: `./gradlew assembleDebug` (Windows: `gradlew.bat assembleDebug`) → `app/build/outputs/apk/debug/`.

Unit tests: `./gradlew :app:testDebugUnitTest`

**Watch app (Wear OS 3+ only):** select the `wear` run configuration with a Wear OS emulator or a watch in developer mode (Settings → Developer options → ADB/Wireless debugging). Install the phone app on the paired phone too, built from the same machine so both use the same signing key; the watch can only talk to a phone app with the same package name **and** key. Open Sentinel on the phone once, and confirm the network in the Network tab: watch-started scans only run on networks you've confirmed there.

**Galaxy Watch Active 2 (Tizen):** no install needed. Turn on **Alerts on phone & watch** on the Home tab and make sure Sentinel notifications are allowed in the Galaxy Wearable app (Watch settings → Notifications).

> Network scanning needs a real phone on Wi-Fi. The emulator sits behind its own virtual network, so it only "sees" itself and the virtual router.

## Release build (Google Play)

1. Create an upload key once, and back it up somewhere safe. Losing it locks you out of updates:
   ```bash
   keytool -genkeypair -v -keystore sentinel-release.jks -keyalg RSA -keysize 2048 -validity 10000 -alias sentinel
   ```
2. Copy `keystore.properties.example` to `keystore.properties` and fill in the passwords. Both files are git-ignored.
3. Build the bundles: `./gradlew :app:bundleRelease :wear:bundleRelease`
   → `app/build/outputs/bundle/release/app-release.aab` and `wear/build/outputs/bundle/release/wear-release.aab`
   (or `assembleRelease` for signed APKs to sideload). Upload the watch bundle to the **Wear OS** release track of the same Play listing.
4. Release builds are minified and resource-shrunk with R8. Smoke-test the release build on a phone before uploading.
5. For each update, bump `versionCode` (and `versionName`) in `app/build.gradle.kts` and `wear/build.gradle.kts`. The watch uses a separate range (10001+) because Play requires unique version codes.

Play Console checklist:
- [ ] Host `PRIVACY.md` at a public URL and enter it as the privacy policy.
- [ ] Data safety: **no data collected, no data shared**. Findings stay on the user's own devices: the phone, plus the paired watch via the Wear OS Data Layer, which Google doesn't count as collection. Nothing leaves them unless the user shares a report.
- [ ] Wear OS: add watch screenshots, then opt in under Advanced settings → Form factors → Wear OS.
- [ ] Store listing text: see `docs/STORE_LISTING.md`. Hi-res icon: `docs/play-store-icon-512.png`.
- [ ] Phone screenshots (at least 2) and a 1024×500 feature graphic.
- [ ] Content rating questionnaire. Target audience: 18+ / not designed for children.

### Exploit database (and how to add to it)

The app ships a seed set so version-matching works offline, and pulls the live feed from this repo:
`feed/vuln_feed.json`. Tap **Update now** in **Settings → Exploit database** (or the card on the Findings tab) to refresh it. The source URL is editable in Settings if you host your own.

The feed is kept current automatically by **`.github/workflows/feed.yml`**: daily (and on demand) it runs `tools/build_feed.py`, which pulls recent CVEs from NVD, flags which have a public exploit using the Exploit-DB index (metadata only — never exploit code), **merges your hand-written entries from `feed/manual.json`**, and commits the result. A source outage never wipes the feed — it falls back to your manual entries.

**To add an exploit by hand:** edit **`feed/manual.json`** and add an object to `vulns`:
```json
{ "id": "CVE-2025-12345", "product": "nginx", "introduced": "1.25.0", "fixed": "1.25.4",
  "cvss": 8.1, "exploit": true, "summary": "What it is, in one line.",
  "fix": "Upgrade to 1.25.4+.", "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-12345" }
```
Use `"exact": ["2.3.4"]` instead of `introduced`/`fixed` for a single affected version. `product` must match a Sentinel fingerprint key (`apache_httpd`, `nginx`, `openssh`, `php`, `mysql`, `redis`, …). Commit the change — the Action republishes within a minute, and your manual entries always win over auto-sourced duplicates.

## Get the latest version (in-app update)

The app updates itself from this repo's GitHub **Releases**. **Settings → Updates** checks the latest release, and if it's newer than what's installed, **Download & install** fetches the APK and hands it to Android's installer (allow "install unknown apps" once).

Publishing a release is one push — **`.github/workflows/release.yml`** builds and attaches the APK:
```bash
# bump versionCode + versionName in app/build.gradle.kts first, then:
git tag v1.1.0 && git push origin v1.1.0
```
For in-app updates to work across versions the APK must be signed with the **same key every time**. Add these repository secrets once (**Settings → Secrets and variables → Actions**):
`SIGNING_KEYSTORE_B64` (`base64 -w0 sentinel-release.jks`), `SIGNING_STORE_PASSWORD`, `SIGNING_KEY_ALIAS`, `SIGNING_KEY_PASSWORD`. Without them the workflow still builds a debug-signed APK to test with, but debug keys change per build and won't satisfy an in-app update.

Prefer to build it yourself? `git pull` and run `./gradlew :app:assembleRelease`.

## How it works and limits

- **Scope guard**: only RFC 1918 private IPv4 on Wi-Fi/Ethernet. Larger networks are limited to the phone's /24. Mobile data and public ranges are refused. The user must confirm authorization for each network before scanning.
- **Discovery**: a device counts as present if any of 10 common TCP ports either accepts **or actively refuses** a connection. Devices that silently drop everything can still be missed.
- **Website audit**: ordinary GET requests only. No forms, payloads, fuzzing or authentication. Missing headers are recommendations, not proof of exploitability.
- Scans run as a WorkManager job, so they finish even if you leave the app, and can be started from a notification or the watch. They only run when you or your watch ask. This is not a 24/7 monitoring service.

## Project layout

| File | Purpose |
|---|---|
| `NetLogic.kt`, `WebChecks.kt`, `Models.kt`, `ReportHtml.kt` | Pure Kotlin logic (unit tested in `app/src/test`) |
| `NetworkScanner.kt`, `WebsiteAuditor.kt` | Network I/O |
| `FindingStore.kt`, `ReportExporter.kt` | Local storage and report sharing |
| `ScanRunner.kt`, `ScanWorker.kt` | Single scan engine for the phone UI, notifications and the watch |
| `SentinelRepo.kt`, `SentinelSettings.kt` | Shared findings state; remembered networks, alert opt-in |
| `Notifier.kt`, `ScanActionReceiver.kt` | Notifications (mirrored to watches) and the "Scan again" action |
| `WatchSync.kt` | Wear OS Data Layer: publishes status, receives watch commands |
| `SentinelViewModel.kt` | Screen state |
| `wear/…/PhoneLink.kt`, `WatchActivity.kt` | Wear OS app |
| `MainActivity.kt`, `Screens.kt` | Compose UI |
| `Theme.kt` | Swappable palettes (Cyber Contrast / Light & Crisp) + `SentinelTheme` |
| `AppUpdate.kt`, `AppInstaller.kt` | In-app updater: read GitHub Releases, download + install the APK |
| `ReportData.kt` | CSV + JSON export of findings (pure, tested) |
| `ScanHistory.kt`, `HistoryStore.kt` | Saved-scan model/codec + persistence for the History screen |
| `Scheduler.kt` | Recurring scheduled full scans (WorkManager) |
| `IpExposure.kt` | Public-IP classification + info parsing for the exposure tool |
| `TlsInspect.kt`, `TlsProbe.kt` | TLS grading logic (tested) + the handshake probe |
| `CertSearch.kt` | crt.sh CT-log subdomain parsing |
| `Nicknames.kt`, `NicknameStore.kt` | Device-nickname helpers (tested) + persistence |
| `tools/build_feed.py`, `feed/manual.json`, `feed/vuln_feed.json` | Exploit-feed builder, your curated entries, the published feed |
| `.github/workflows/feed.yml`, `release.yml` | Daily feed refresh; tag-triggered APK build + release |

## Changelog

**1.8.0 (in progress)**
- **TLS/SSL deep inspection** in the website audit: probes which protocol versions a host accepts and the cipher each negotiates, grades the config A–F, and flags obsolete protocols (TLS 1.0/1.1, SSLv3), weak ciphers (RC4/3DES/NULL/EXPORT/anon) and missing TLS 1.3.
- **Subdomain finder** (Tools): passive discovery from Certificate Transparency logs (crt.sh) — read-only, never touches the target.
- **Device nicknames**: name any device (keyed by MAC so it survives DHCP changes) from its detail screen. Names show in the device list, host detail, scan-history diffs and new-device alerts.

**1.7.0 (in progress)**
- **Scan history & trends**: every network scan and website audit is saved (last 60). A History screen (Settings → History) lists them with severity counts and, for repeat scans of the same network, a "since previous scan" diff (new/departed devices, port changes).
- **CSV + JSON export**: the Findings tab can now share findings as CSV (spreadsheets) or JSON (tooling/pipelines) in addition to the HTML report.
- **Scheduled scans**: Settings → Automatic scans runs a full scan of your authorized network on a cadence (Off / 12h / Daily / Weekly) with a completion notification; it only runs when you're back on that network.
- **Public-IP exposure check** (Tools): shows your internet-facing IP, ISP/ASN and city, classifies it (public / CGNAT / private), and best-effort checks whether common inbound ports answer — with honest caveats about NAT and outside-in testing.

**1.6.0 (in progress)**
- Redesigned UI: new **Cyber Contrast** theme (true-black OLED, cyan + magenta) as default, with a **Light & Crisp** light mode you can toggle in the new **Settings** screen (gear icon, top-right). The whole app re-themes instantly and the choice persists.
- **Settings screen** gathers appearance, the exploit-database status/update + feed source, and app updates in one place.
- **In-app app updates**: checks this repo's GitHub Releases and installs a newer APK from inside the app (`AppUpdate.kt` / `AppInstaller.kt`).
- **Exploit feed pipeline on GitHub**: `.github/workflows/feed.yml` auto-pulls CVEs daily and merges hand-written entries from `feed/manual.json`; `.github/workflows/release.yml` builds and publishes the APK on a version tag. The in-app feed URL now points at `feed/vuln_feed.json` in this repo.

**1.5.1 (in progress)**
- PHP2Shell detection: added CVE-2026-109618 / CVE-2026-109619 (critical PHP RCE, CVSS 9.2, public exploit, NSA/FBI warning) to the vulnerability database as per-branch version matches (fixed in PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; 5.4.0-8.1.x are EOL). The website audit now reads the PHP version from headers and flags a vulnerable server with the exact upgrade. When the version is hidden, it notes that version-based checks can't confirm status and to patch regardless. Detection only — no exploitation.

**1.5.0 (in progress)**
- Network monitoring (Fing-style): opt-in background rescans (~every 30 min) of your authorized network that alert on new devices, devices that left, and newly opened/closed ports. Diffing matches by MAC so a DHCP lease change isn't a false "new device". Toggle on the Network tab; alerts respect the Home alert switch and mirror to your watch.
- Internet speed test (download + latency, via Cloudflare) in the Tools tab.
- Nearby Wi-Fi scanner in the Tools tab: SSID, channel, band, signal and security, with weak-security (Open/WEP) flagged. Needs location permission (Android's requirement for Wi-Fi scans), asked only when you use it.

**1.4.0 (in progress)**
- New Tools tab (PortDroid-style utilities): Ping, DNS lookup (A/AAAA/MX/TXT/NS/CNAME via a public resolver), Port scan (custom host + range), WHOIS, Subnet calculator, MAC-vendor lookup, and Wake-on-LAN.
- Device-type inference (Fing-style, offline): guesses a category (Printer, IP camera, Router, Windows PC, Server, Raspberry Pi, IoT…) from vendor + open ports when discovery didn't already classify the device.
- Honest limits: hop-by-hop traceroute and SYN/OS-fingerprint scans need raw sockets and aren't possible on an unrooted phone; Fing's cloud device-recognition database can't be replicated offline.

**1.3.1 (in progress)**
- Fix: Wear OS module now depends on material-icons-extended so PlayArrow/Refresh/Close resolve (they aren't all in material-icons-core).

**1.3.0 (in progress)**
- WordPress audit (opt-in toggle on the Website tab): detects WordPress + version, enumerates users via the REST API and author archives, checks XML-RPC, inventories plugins/themes with versions and runs them through the CVE matcher, and flags exposed sensitive files (wp-config backups, .git, debug.log, directory listing, readme.html). All plain GETs — no login attempts.
- Laptop-handoff commands: the per-host walkthrough now generates copy-ready commands for your rig (nmap, ssh, smbclient, testssl.sh, wpscan, etc.) tailored to the host's open ports. The phone does recon and hands off the next command; it never runs them.

**1.2.0 (in progress)**
- SNMP recon (read-only, "public"): reads sysName/sysDescr and walks the gateway's ARP table (ipNetToMediaPhysAddress) to recover MAC↔IP for the whole LAN — data Android blocks an app from reading locally. MACs resolve to vendors via an embedded OUI table. Device cards and the host screen now show MAC + manufacturer.
- Scan depth profiles: Fast (~15 ports), Normal (~28), Thorough (~110), selectable on the Network tab.
- Two-stage mDNS: queries the service-type meta-record plus the common service types, so one scan window names and classifies many more devices.
- Honest note: ARP/MAC via SNMP only works when the router (or a managed device) has SNMP readable. ICMP ping sweep, SYN scan and OS fingerprinting remain impossible on an unrooted phone (no raw sockets).

**1.1.0 (in progress)**
- New walkthrough view: tap a device on the Network tab for a per-host screen — open ports with versions, all its CVEs/risks sorted by severity, a status chip per finding (New / Verified / False positive / Fixed) and a notes field (kept across rescans), plus Copy IP, Rescan host, and Reference/Copy quick actions. The shared HTML report is now grouped by host and includes status and notes.
- New: known-vulnerability matching — fingerprinted service versions are checked against a CVE database (with a 'public exploit exists' priority flag) and flagged with the fix. Update button on the Findings tab pulls the latest feed from a GitHub raw URL; bundled seed works offline. Feed generator: tools/build_feed.py (NVD + Exploit-DB metadata index; no exploit code).
- New recon engine: device discovery via SSDP/UPnP, mDNS and NetBIOS (names and classifies devices with no open TCP port), plus service version fingerprinting (SSH, FTP, SMTP, HTTP Server, MySQL/MariaDB, Redis). Device cards now show vendor/type and service versions. Lays the groundwork for CVE matching.

**1.0.0**
- New: phone and watch alerts, "Scan again" notification action, Wear OS companion app, background-safe scans, remembered network authorization, overall scan progress.
- Fixed: website audit reported a false "not using HTTPS" for sites that redirect http→https (Android's HttpURLConnection doesn't follow cross-scheme redirects; redirects are now followed manually).
- Fixed: devices that refuse connections were treated as offline.
- Fixed: scans were cancelled when switching tabs or rotating.
- Fixed: rescans duplicated findings; network errors were saved as security findings.
- New: TLS failure diagnosis (expired / untrusted / wrong hostname), cookie and HSTS strength checks, http↔https enforcement probe, device names, router/phone labels, per-port remediation, scan progress and cancel, severity filters, dismiss, confirm-before-clear, top priorities on Home.
- New: app icon, release signing + R8, official Gradle wrapper, backup exclusion, unit tests.

## Roadmap (not in this release)

CVE enrichment, scheduled re-scans, PDF export, Windows/AD agent, Wear OS tile and complication.
