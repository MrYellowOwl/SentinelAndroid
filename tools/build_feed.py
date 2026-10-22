#!/usr/bin/env python3
"""
Build the Sentinel vulnerability feed (vuln_feed.json) from authoritative public sources.

It pulls CVE metadata from the NVD and cross-references Exploit-DB's CSV INDEX to flag which
CVEs have a public exploit. It downloads only metadata — never exploit code or payloads.

Publish the output to the GitHub raw URL the app points at (Findings tab → Update), e.g. a repo
you own:  https://raw.githubusercontent.com/<you>/sentinel-feed/main/vuln_feed.json
A GitHub Action on a schedule can run this and commit the result.

Usage:
    python3 build_feed.py --out vuln_feed.json
    # optional: --nvd-key YOURKEY  (higher NVD rate limit)

Products matched to Sentinel's fingerprints. Extend PRODUCTS as you add fingerprinters.
"""
import argparse, csv, io, json, os, re, sys, time, urllib.error, urllib.request

# NVD CPE vendor:product -> Sentinel product key (must match ServiceFingerprint.productKey / VulnMatcher.normalize).
# A CVE only ever matches on-device if its product key equals what a fingerprinter emits for that service, so
# this list is scoped to daemons Sentinel can identify from a banner/handshake (plus close future candidates).
# NVD vendor/product names that don't exist just return nothing and are skipped — a wrong guess is harmless.
PRODUCTS = {
    # SSH
    ("openbsd", "openssh"): "openssh",
    ("dropbear_ssh_project", "dropbear_ssh"): "dropbear",
    ("matt_johnston", "dropbear"): "dropbear",
    # Web servers
    ("apache", "http_server"): "apache_httpd",
    ("f5", "nginx"): "nginx",
    ("nginx", "nginx"): "nginx",
    ("lighttpd", "lighttpd"): "lighttpd",
    ("apache", "tomcat"): "tomcat",
    ("eclipse", "jetty"): "jetty",
    ("microsoft", "internet_information_services"): "microsoft_iis",
    # FTP
    ("vsftpd_project", "vsftpd"): "vsftpd",
    ("proftpd", "proftpd"): "proftpd",
    ("pureftpd", "pure-ftpd"): "pure-ftpd",
    ("filezilla", "filezilla_server"): "filezilla",
    # Mail
    ("exim", "exim"): "exim",
    ("postfix", "postfix"): "postfix",
    ("proofpoint", "sendmail"): "sendmail",
    ("sendmail", "sendmail"): "sendmail",
    ("dovecot", "dovecot"): "dovecot",
    # Databases / caches
    ("redis", "redis"): "redis",
    ("redislabs", "redis"): "redis",
    ("mysql", "mysql"): "mysql",
    ("oracle", "mysql"): "mysql",
    ("mariadb", "mariadb"): "mariadb",
    ("postgresql", "postgresql"): "postgresql",
    ("mongodb", "mongodb"): "mongodb",
    ("memcached", "memcached"): "memcached",
    ("elastic", "elasticsearch"): "elasticsearch",
    # DNS
    ("isc", "bind"): "bind",
    ("nlnetlabs", "unbound"): "unbound",
    # File sharing
    ("samba", "samba"): "samba",
    # Runtimes
    ("php", "php"): "php",
}
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def cve_in(text):
    """First CVE id embedded in an entry's id (manual ids may add suffixes)."""
    m = CVE_RE.search(text or "")
    return m.group(0).upper() if m else None


# Some gov/API WAFs reject non-browser agents, so use a browser-like UA for KEV/EPSS.
BROWSER_UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) SentinelFeedBuilder/1.0"}


def cisa_kev_set():
    """CVE ids in CISA's Known Exploited Vulnerabilities catalog (actively exploited)."""
    data = json.loads(fetch(KEV_JSON, headers=BROWSER_UA).decode("utf-8", "replace"))
    return {v.get("cveID", "").upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}


def epss_scores(cve_ids):
    """EPSS probability per CVE, batched against the FIRST API. Missing ids just get no score."""
    out = {}
    ids = [c for c in cve_ids if c]
    for i in range(0, len(ids), 50):
        batch = ids[i:i + 50]
        url = f"{EPSS_API}?cve={','.join(batch)}"
        try:
            payload = json.loads(fetch(url, headers=BROWSER_UA).decode("utf-8", "replace"))
            for row in payload.get("data", []):
                cve, score = row.get("cve", "").upper(), row.get("epss")
                if cve and score is not None:
                    out[cve] = round(float(score), 4)
        except Exception as e:  # noqa: BLE001
            print(f"WARNING: EPSS batch failed ({e}); those scores omitted.", file=sys.stderr)
    return out


def fetch(url, headers=None, retries=3):
    """GET with simple backoff on the throttling/transient statuses NVD and gitlab return."""
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers or {"User-Agent": "sentinel-feed-builder"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429, 503, 504) and attempt < retries - 1:
                time.sleep(6)  # NVD asks unauthenticated clients to slow down; keep it bounded
                continue
            raise
        except Exception as e:  # noqa: BLE001 - transient network errors get one more try
            last = e
            if attempt < retries - 1:
                time.sleep(4 * (attempt + 1))
                continue
            raise
    raise last if last else RuntimeError("fetch failed")


def exploitdb_cve_set():
    """CVE ids that appear in the Exploit-DB index (i.e. a public exploit exists)."""
    data = fetch(EDB_CSV).decode("utf-8", "replace")
    cves = set()
    for row in csv.DictReader(io.StringIO(data)):
        for field in (row.get("codes", ""), row.get("cve", "")):
            for tok in field.replace(";", " ").split():
                if tok.startswith("CVE-"):
                    cves.add(tok.strip())
    return cves


def nvd_entries(vendor, product, api_key):
    headers = {"User-Agent": "sentinel-feed-builder"}
    if api_key:
        headers["apiKey"] = api_key
    cpe = f"cpe:2.3:a:{vendor}:{product}"
    start, out = 0, []
    while True:
        url = f"{NVD_API}?virtualMatchString={cpe}&resultsPerPage=2000&startIndex={start}"
        payload = json.loads(fetch(url, headers))
        out.extend(payload.get("vulnerabilities", []))
        start += payload.get("resultsPerPage", 0)
        if start >= payload.get("totalResults", 0) or not payload.get("resultsPerPage"):
            break
        time.sleep(0.8 if api_key else 6)  # respect NVD rate limits
    return out


def best_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            return metrics[key][0]["cvssData"]["baseScore"]
    return None


def version_bounds(cve, product_key):
    """Collect affected-version info from this product's CPE matches.

    NVD gives upper bounds two ways, so we keep both: versionEndExcluding ("fixed in", exclusive) and
    versionEndIncluding ("affected up to and including", inclusive). CPEs that pin a concrete version
    (no range attrs) contribute to an `exact` list. Returns (introduced, fixed, last_affected, exact[]).
    """
    prod = product_key.split("_")[0]
    intro = fixed = last = None
    exacts = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable") is False:
                    continue
                c = m.get("criteria", "")
                if f":{prod}:" not in c and product_key not in c:
                    continue
                si = m.get("versionStartIncluding")
                se = m.get("versionStartExcluding")  # rare; treated as ~inclusive lower (slight over-match)
                ee = m.get("versionEndExcluding")
                ei = m.get("versionEndIncluding")
                if si or se or ee or ei:
                    if intro is None:
                        intro = si or se
                    if fixed is None and ee:
                        fixed = ee
                    if last is None and ei:
                        last = ei
                else:
                    # e.g. cpe:2.3:a:apache:http_server:2.4.49:*:*:... -> version is field index 5
                    parts = c.split(":")
                    if len(parts) > 5 and parts[5] not in ("*", "-", ""):
                        if parts[5] not in exacts:
                            exacts.append(parts[5])
    return intro, fixed, last, exacts[:40]  # cap exacts so a sprawling CVE can't bloat the feed


def dedupe_key(v):
    """Identity of an entry: same CVE + product + version window is the same finding."""
    return (
        v.get("id", "").strip().lower(),
        v.get("product", "").strip().lower(),
        v.get("introduced", ""),
        v.get("fixed", ""),
        v.get("last_affected", ""),
        ",".join(v.get("exact", []) or []),
    )


def load_manual(path):
    """Hand-written entries. Accepts {"vulns":[...]} or a bare [...]. These always win on conflict."""
    if not path or not os.path.exists(path):
        return []
    with open(path) as f:
        data = json.load(f)
    entries = data.get("vulns", data) if isinstance(data, dict) else data
    return [e for e in entries if e.get("id") and e.get("product")]


def enrich_kev_epss(entries):
    """Tag entries in place with CISA KEV + EPSS. Both best-effort; fast (no NVD)."""
    kev = set()
    try:
        print("Fetching CISA KEV catalog…", file=sys.stderr)
        kev = cisa_kev_set()
    except Exception as e:  # noqa: BLE001
        print(f"WARNING: KEV catalog unavailable ({e}); kev flags omitted.", file=sys.stderr)
    epss = {}
    try:
        print("Fetching EPSS scores…", file=sys.stderr)
        epss = epss_scores({cve_in(v.get("id", "")) for v in entries})
    except Exception as e:  # noqa: BLE001
        print(f"WARNING: EPSS unavailable ({e}); scores omitted.", file=sys.stderr)
    kev_count = 0
    for v in entries:
        cid = cve_in(v.get("id", ""))
        if cid and cid in kev:
            v["kev"] = True
            kev_count += 1
        if cid and cid in epss:
            v["epss"] = epss[cid]
    print(f"Tagged {kev_count} KEV and {sum(1 for v in entries if 'epss' in v)} EPSS entries.", file=sys.stderr)
    return kev_count


def enrich_only(path):
    """Load an existing feed, add KEV/EPSS, write it back. Decoupled from the slow NVD pull."""
    with open(path) as f:
        feed = json.load(f)
    entries = feed.get("vulns", [])
    enrich_kev_epss(entries)
    kev = sum(1 for v in entries if v.get("kev"))
    eps = sum(1 for v in entries if "epss" in v)
    feed["note"] = (feed.get("note", "").split(" · ")[0]) + f" · {kev} KEV, {eps} EPSS-scored."
    with open(path, "w") as f:
        json.dump(feed, f, separators=(",", ":"))
    print(f"Enriched {path}: {kev} KEV, {eps} EPSS.", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="vuln_feed.json")
    ap.add_argument("--merge", default=None, help="manual entries JSON to merge in (always kept)")
    ap.add_argument("--nvd-key", default=None)
    ap.add_argument("--min-entries", type=int, default=1,
                    help="fail (non-zero exit, no write) if the result has fewer than this many entries")
    ap.add_argument("--enrich-only", default=None,
                    help="skip the NVD pull; just add KEV/EPSS to an existing feed JSON and rewrite it")
    args = ap.parse_args()

    if args.enrich_only:
        enrich_only(args.enrich_only)
        return

    manual = load_manual(args.merge)
    print(f"Manual entries: {len(manual)}", file=sys.stderr)

    vulns = []
    # Exploit-DB index is best-effort: if it's unreachable, entries just miss the "exploit" flag.
    edb = set()
    try:
        print("Fetching Exploit-DB index…", file=sys.stderr)
        edb = exploitdb_cve_set()
    except Exception as e:
        print(f"WARNING: Exploit-DB index unavailable ({e}); exploit flags default to false.", file=sys.stderr)

    # Per-product so one product throttling/erroring doesn't zero out the whole auto-pull.
    for (vendor, product), key in PRODUCTS.items():
        try:
            print(f"NVD: {vendor}:{product} -> {key}", file=sys.stderr)
            for item in nvd_entries(vendor, product, args.nvd_key):
                cve = item["cve"]
                cid = cve["id"]
                intro, fixed, last, exacts = version_bounds(cve, key)
                # Keep a CVE only when we have something to match a version against — a range bound or
                # concrete versions. Entries with no bound at all would match every version (false positives).
                if not (intro or fixed or last or exacts):
                    continue
                desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
                vulns.append({
                    "id": cid,
                    "product": key,
                    **({"introduced": intro} if intro else {}),
                    **({"fixed": fixed} if fixed else {}),
                    **({"last_affected": last} if last else {}),
                    **({"exact": exacts} if exacts else {}),
                    "cvss": best_cvss(cve.get("metrics", {})),
                    "exploit": cid in edb,
                    "summary": desc[:300],
                    "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                })
        except Exception as e:
            print(f"WARNING: NVD fetch for {vendor}:{product} failed ({e}); skipping it this run.", file=sys.stderr)

    # Merge: manual entries first and authoritative, then auto entries that aren't duplicates.
    merged, seen = [], set()
    for v in manual + vulns:
        k = dedupe_key(v)
        if k in seen:
            continue
        seen.add(k)
        merged.append(v)

    enrich_kev_epss(merged)

    if len(merged) < args.min_entries:
        print(f"ERROR: only {len(merged)} entries (< {args.min_entries}); refusing to publish.", file=sys.stderr)
        sys.exit(1)

    feed = {
        "version": 1,
        "updated": time.strftime("%Y-%m-%d"),
        "count": len(merged),
        "note": f"{len(manual)} curated + {len(merged) - len(manual)} auto-sourced entries.",
        "vulns": merged,
    }
    with open(args.out, "w") as f:
        json.dump(feed, f, separators=(",", ":"))
    print(f"Wrote {len(merged)} entries to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
