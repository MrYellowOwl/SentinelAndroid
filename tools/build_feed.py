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
import argparse, csv, io, json, os, sys, time, urllib.error, urllib.request

# NVD CPE vendor:product -> Sentinel product key (must match ServiceFingerprint.productKey / VulnMatcher.normalize)
PRODUCTS = {
    ("openbsd", "openssh"): "openssh",
    ("apache", "http_server"): "apache_httpd",
    ("f5", "nginx"): "nginx",
    ("nginx", "nginx"): "nginx",
    ("vsftpd_project", "vsftpd"): "vsftpd",
    ("proftpd", "proftpd"): "proftpd",
    ("redis", "redis"): "redis",
    ("mysql", "mysql"): "mysql",
    ("mariadb", "mariadb"): "mariadb",
    ("php", "php"): "php",
    ("isc", "bind"): "bind",
    ("microsoft", "internet_information_services"): "microsoft_iis",
}
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"


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
    """Extract (introduced, fixed) from CPE match ranges for this product."""
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                c = m.get("criteria", "")
                if f":{product_key.split('_')[0]}:" in c or product_key in c:
                    intro = m.get("versionStartIncluding")
                    fixed = m.get("versionEndExcluding")
                    if intro or fixed:
                        return intro, fixed
    return None, None


def dedupe_key(v):
    """Identity of an entry: same CVE + product + version window is the same finding."""
    return (
        v.get("id", "").strip().lower(),
        v.get("product", "").strip().lower(),
        v.get("introduced", ""),
        v.get("fixed", ""),
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="vuln_feed.json")
    ap.add_argument("--merge", default=None, help="manual entries JSON to merge in (always kept)")
    ap.add_argument("--nvd-key", default=None)
    ap.add_argument("--min-entries", type=int, default=1,
                    help="fail (non-zero exit, no write) if the result has fewer than this many entries")
    args = ap.parse_args()

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
                intro, fixed = version_bounds(cve, key)
                if not (intro or fixed):
                    continue
                desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
                vulns.append({
                    "id": cid,
                    "product": key,
                    **({"introduced": intro} if intro else {}),
                    **({"fixed": fixed} if fixed else {}),
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
