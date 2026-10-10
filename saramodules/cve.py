# cve.py

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from saramodules.report import cve_table, cve_unanalyzed, error

nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
routeros_cpe = "cpe:2.3:o:mikrotik:routeros"

# beta < rc < release, so 7.15beta2 < 7.15rc1 < 7.15
stage_rank = {"beta": 0, "rc": 1, "": 2}

# NVD prefers the newest CVSS version it has
CVSS_versions = [("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")]


# RouterOS version text -> tuple for comparison, None if it does not look like a version
# "7.23.3 (stable)" -> (7, 23, 3, 2, 0), "7.15beta2" -> (7, 15, 0, 0, 2)
def parse_version(text):
    if not text:
        return None

    # drop the channel: "7.23.3 (stable)" -> "7.23.3"
    text = str(text).split()[0]
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:(beta|rc)(\d+))?", text)
    if not match:
        return None

    major, minor, patch, stage, stage_number = match.groups()
    return (int(major), int(minor), int(patch or 0), stage_rank[stage or ""], int(stage_number or 0))


# one NVD API request -> list of CVE records; stops Sara with a clear message if NVD fails
def fetch(params):
    url = nvd_url + "?" + urllib.parse.urlencode(params, safe=":")
    request = urllib.request.Request(url, headers={"User-Agent": "sara"})

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = json.load(response)
    except urllib.error.HTTPError as http_error:
        error(f"NVD request failed: HTTP {http_error.code} (limit without an API key is 5 requests per 30 seconds)")
        sys.exit(1)
    except (urllib.error.URLError, TimeoutError) as connection_error:
        error(f"NVD is unreachable: {connection_error}")
        sys.exit(1)

    records = []
    for item in data.get("vulnerabilities", []):
        records.append(item["cve"])
    return records


# best available CVSS: (version, score, severity, attack vector)
def cvss(record):
    metrics = record.get("metrics", {})

    for key, label in CVSS_versions:
        if key not in metrics:
            continue
        metric = metrics[key][0]
        data = metric["cvssData"]
        # v2 keeps severity next to cvssData, v3/v4 inside it
        severity = str(data.get("baseSeverity") or metric.get("baseSeverity") or "medium").lower()
        if severity not in ("critical", "high", "medium", "low"):
            severity = "low"
        vector = str(data.get("attackVector") or data.get("accessVector") or "unknown").lower()
        return label, data.get("baseScore"), severity, vector

    return None, None, "unknown", "unknown"


# cpeMatch entries that mark RouterOS as vulnerable
# NVD layout: configurations -> nodes -> cpeMatch
def routeros_ranges(record):
    ranges = []
    for configuration in record.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and ":mikrotik:routeros:" in match.get("criteria", ""):
                    ranges.append(match)
    return ranges


# exact version written into the CPE itself: cpe:2.3:o:mikrotik:routeros:6.42:*:... ("*" means any)
# rc and beta live in the next CPE field: routeros:6.41:rc31 -> "6.41rc31"
def exact_version(match):
    parts = match["criteria"].split(":")
    exact = parts[5]
    update = parts[6]
    if exact in ("*", "-"):
        return None
    if update not in ("*", "-"):
        exact = exact + update
    return exact


# is this version inside one cpeMatch range
def is_affected(version, match):
    if exact_version(match):
        return parse_version(exact_version(match)) == version

    # a bound that is not a version (NVD sometimes writes a date like 2021-01-04) cannot be trusted
    for field in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
        if match.get(field) and parse_version(match.get(field)) is None:
            return False

    start_including = parse_version(match.get("versionStartIncluding"))
    start_excluding = parse_version(match.get("versionStartExcluding"))
    end_including = parse_version(match.get("versionEndIncluding"))
    end_excluding = parse_version(match.get("versionEndExcluding"))

    if start_including and version < start_including:
        return False
    if start_excluding and version <= start_excluding:
        return False
    if end_including and version > end_including:
        return False
    if end_excluding and version >= end_excluding:
        return False
    return True


# sort key: highest CVSS first, unknown scores last
def by_score(pair):
    record, match = pair
    return cvss(record)[1] or 0


# sort key: newest first
def by_published(row):
    return row["published"]


# look up CVEs for one RouterOS version
def run(version_text):
    version = parse_version(version_text)
    if version is None:
        error(f"Cannot parse RouterOS version: {version_text}")
        return

    analyzed = fetch({"virtualMatchString": routeros_cpe, "resultsPerPage": 2000})

    # one CVE can list several ranges (one per branch), the first hit is enough
    matched = []
    for record in analyzed:
        for match in routeros_ranges(record):
            if is_affected(version, match):
                matched.append((record, match))
                break

    matched.sort(key=by_score, reverse=True)

    # one table row per CVE
    rows = []
    for record, match in matched:
        cvss_version, score, severity, vector = cvss(record)

        # "-" when NVD lists no fixed version, "> X" when only the last vulnerable one is known
        fixed = "-"
        if match.get("versionEndExcluding"):
            fixed = match["versionEndExcluding"]
        elif match.get("versionEndIncluding"):
            fixed = f"> {match['versionEndIncluding']}"

        rows.append({
            "id": record["id"],
            "severity": severity,
            "score": score,
            "published": record.get("published", "")[:10],
            "fixed": fixed,
        })

    cve_table(version_text, rows)

    # CVEs that mention RouterOS but have no version ranges in NVD yet
    analyzed_ids = set()
    for record in analyzed:
        analyzed_ids.add(record["id"])

    unanalyzed = []
    for record in fetch({"keywordSearch": "routeros", "resultsPerPage": 2000}):
        if record["id"] in analyzed_ids:
            continue
        if record.get("vulnStatus") == "Rejected":
            continue
        # analyzed, but for some other product that only mentions RouterOS
        if record.get("configurations"):
            continue
        unanalyzed.append({
            "id": record["id"],
            "status": record.get("vulnStatus", ""),
            "published": record.get("published", "")[:10],
        })

    if unanalyzed:
        unanalyzed.sort(key=by_published, reverse=True)
        cve_unanalyzed(unanalyzed)
