# Auxiliary module cve_analyzer.py for searching CVE using the NIST NVD database
#
# Copyright (c) 2026 Mahama Bazarov
# Licensed under the Apache 2.0 License
# This project is not affiliated with or endorsed by SIA Mikrotīkls

import json, re, os, requests, time
from packaging.version import Version, InvalidVersion
from colorama import Fore, Style

# NVD v2.0 URL and settings
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEYWORD = "routeros"
RESULTS_PER_PAGE = 2000
OUTPUT_FILE = "routeros_cves.json"
GUTTER = 2  # spaces between columns


# Simple role-based color mapping
def paint(role: str, text: str) -> str:
    role_value = (role or "").lower()

    if role_value in ("crit", "fail"):
        return Fore.RED + text + Style.RESET_ALL
    if role_value == "warn":
        return Fore.YELLOW + text + Style.RESET_ALL
    if role_value == "ok":
        return Fore.GREEN + text + Style.RESET_ALL
    if role_value == "info":
        return Fore.CYAN + text + Style.RESET_ALL
    if role_value == "label":
        return Fore.CYAN + text + Style.RESET_ALL
    if role_value == "value":
        return Style.BRIGHT + text + Style.RESET_ALL

    return text


# ANSI and OSC-8 stripping for width calculation
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
OSC8_BEL = re.compile(r"\x1b]8;;.*?\x07")
OSC8_ST = re.compile(r"\x1b]8;;.*?\x1b\\")


def strip_osc8(s: str) -> str:
    tmp = OSC8_BEL.sub("", s)
    tmp = OSC8_ST.sub("", tmp)
    return tmp


def visible_len(s: str) -> int:
    raw = strip_osc8(s)
    no_ansi = ANSI_RE.sub("", raw)
    return len(no_ansi)


def pad_r(s: str, width: int) -> str:
    length = visible_len(s)
    pad_len = width - length
    if pad_len < 0:
        pad_len = 0
    return s + " " * pad_len


def pad_l(s: str, width: int) -> str:
    length = visible_len(s)
    pad_len = width - length
    if pad_len < 0:
        pad_len = 0
    return " " * pad_len + s


# Clickable hyperlink (OSC-8)
def term_link(text: str, url: str) -> str:
    return f"\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\"


# Convert RouterOS version string to Version object
def normalize_version(v):
    if not v:
        return None
    try:
        return Version(v)
    except InvalidVersion:
        cleaned = re.sub(r"(rc|beta|testing|stable)[\d\-]*", "", v, flags=re.IGNORECASE)
        try:
            return Version(cleaned)
        except InvalidVersion:
            return None


# Extract version ranges from CVE description text
def extract_ranges_from_description(description):
    description = (description or "").lower()
    ranges = []

    matches = re.findall(r"(?:from\s+)?v?(\d+\.\d+(?:\.\d+)?)\s+to\s+v?(\d+\.\d+(?:\.\d+)?)", description)
    for start, end in matches:
        ranges.append({"versionStartIncluding": start, "versionEndIncluding": end})

    matches = re.findall(r"before\s+v?(\d+\.\d+(?:\.\d+)?)", description)
    for end in matches:
        ranges.append({"versionEndExcluding": end})

    matches = re.findall(r"after\s+v?(\d+\.\d+(?:\.\d+)?)", description)
    for start in matches:
        ranges.append({"versionStartExcluding": start})

    matches = re.findall(r"through\s+v?(\d+\.\d+(?:\.\d+)?)", description)
    for end in matches:
        ranges.append({"versionEndIncluding": end})

    matches = re.findall(r"v?(\d+\.\d+)\.x", description)
    for base in matches:
        ranges.append({"versionStartIncluding": f"{base}.0", "versionEndIncluding": f"{base}.999"})

    matches = re.findall(r"(?:up to|and below)\s+v?(\d+\.\d+(?:\.\d+)?)", description)
    for end in matches:
        ranges.append({"versionEndIncluding": end})

    return ranges


# Check if current version falls into a vulnerable range
def is_version_affected(current_v, version_info):
    def get(v_key):
        return normalize_version(version_info.get(v_key))

    criteria_raw = version_info.get("criteria", "") or ""
    criteria = criteria_raw.lower()
    end_excl_raw = version_info.get("versionEndExcluding", "")

    if criteria and ("mikrotik" not in criteria or "routeros" not in criteria):
        return False

    if isinstance(end_excl_raw, str) and end_excl_raw.startswith("7") and str(current_v).startswith("6."):
        return False
    if isinstance(end_excl_raw, str) and end_excl_raw.startswith("6") and str(current_v).startswith("7."):
        return False

    start_incl = get("versionStartIncluding")
    start_excl = get("versionStartExcluding")
    end_incl = get("versionEndIncluding")
    end_excl = get("versionEndExcluding")

    if not any([start_incl, start_excl, end_incl, end_excl]):
        version_match = re.search(r"routeros:([\w.\-]+)", criteria_raw)
        if version_match:
            version_exact = normalize_version(version_match.group(1))
            return version_exact is not None and current_v == version_exact
        return False

    for raw_key, normed in zip(
        ["versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"],
        [start_incl, start_excl, end_incl, end_excl],
    ):
        if version_info.get(raw_key) and normed is None:
            return False

    if start_incl and current_v < start_incl:
        return False
    if start_excl and current_v <= start_excl:
        return False
    if end_incl and current_v > end_incl:
        return False
    if end_excl and current_v >= end_excl:
        return False

    return True


# Download all RouterOS CVEs from NVD and save locally
def fetch_all_cves():
    all_cves = []
    start_index = 0

    print(Fore.CYAN + "[*] Fetching CVEs from NVD...")
    while True:
        params = {
            "keywordSearch": KEYWORD,
            "startIndex": start_index,
            "resultsPerPage": RESULTS_PER_PAGE,
        }
        try:
            response = requests.get(NVD_URL, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[-] HTTP Error: {e}")
            break
        except json.JSONDecodeError:
            print(Fore.RED + "[-] Failed to parse JSON from NVD.")
            break

        cve_items = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        for item in cve_items:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            severity = "UNKNOWN"
            score = "N/A"
            published = cve.get("published", "")

            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                score = cvss.get("baseScore", "N/A")
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                score = cvss.get("baseScore", "N/A")

            affected_versions = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if not match.get("vulnerable", False):
                            continue
                        criteria = match.get("criteria", "") or ""
                        crit_l = criteria.lower()
                        if "mikrotik" not in crit_l or "routeros" not in crit_l:
                            continue
                        affected_versions.append(
                            {
                                "criteria": criteria,
                                "versionStartIncluding": match.get("versionStartIncluding"),
                                "versionStartExcluding": match.get("versionStartExcluding"),
                                "versionEndIncluding": match.get("versionEndIncluding"),
                                "versionEndExcluding": match.get("versionEndExcluding"),
                            }
                        )

            all_cves.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "severity": severity,
                    "cvss_score": score,
                    "published": published,
                    "affected_versions": affected_versions,
                }
            )

        start_index += RESULTS_PER_PAGE
        if start_index >= total_results:
            break
        time.sleep(1.5)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_cves, f, indent=2, ensure_ascii=False)
    print(Fore.GREEN + f"[+] Saved {len(all_cves)} CVEs to {OUTPUT_FILE}")


# Load local CVE cache and optionally refresh it
def load_cve_data():
    if not os.path.isfile(OUTPUT_FILE):
        print(Fore.YELLOW + f"[!] {OUTPUT_FILE} not found.")
        fetch_all_cves()
    else:
        print(Fore.YELLOW + f"[?] {OUTPUT_FILE} already exists.")
        answer = input(Fore.YELLOW + "    Overwrite it with fresh CVE data? [yes/no]: ").strip().lower()
        if answer == "yes":
            fetch_all_cves()

    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(Fore.RED + f"[-] Failed to load {OUTPUT_FILE}: {e}")
        return None


# Format CVSS score as 0.1 or N/A
def fmt_cvss(x):
    try:
        value = float(x)
        return f"{value:0.1f}"
    except Exception:
        return "N/A"


# Severity rank for sorting
sev_rank = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}


def key_tuple(m):
    sev = m.get("severity", "UNKNOWN") or "UNKNOWN"
    sev_u = sev.upper()
    rank = sev_rank.get(sev_u, 4)
    pub = m.get("published") or ""
    return (rank, pub)


# Severity tag (CRIT/HIGH/MED/LOW/UNK)
def sev_tag(sev: str):
    sev_u = (sev or "UNKNOWN").upper()
    if sev_u == "CRITICAL":
        return paint("crit", "CRIT")
    if sev_u == "HIGH":
        return paint("fail", "HIGH")
    if sev_u == "MEDIUM":
        return paint("warn", "MED")
    if sev_u == "LOW":
        return paint("info", "LOW")
    return paint("value", "UNK")


def count_seg(label: str, n: int):
    role_map = {
        "CRIT": "crit",
        "HIGH": "fail",
        "MED": "warn",
        "LOW": "info",
        "UNK": "value",
    }
    role = role_map[label]
    return paint(role, label) + ": " + paint("value", str(n))


# Summary header
def render_summary(version: str, matches, counters):
    c_crit = counters.get("CRITICAL", 0)
    c_high = counters.get("HIGH", 0)
    c_med = counters.get("MEDIUM", 0)
    c_low = counters.get("LOW", 0)
    c_unk = counters.get("UNKNOWN", 0)

    line1 = (
        paint("label", "Target RouterOS Version:") + " " + paint("value", version)
        + "    "
        + paint("label", "Matched CVEs:") + " " + paint("value", str(len(matches)))
    )

    parts = [
        count_seg("CRIT", c_crit),
        count_seg("HIGH", c_high),
        count_seg("MED", c_med),
        count_seg("LOW", c_low),
        count_seg("UNK", c_unk),
    ]
    line2 = " | ".join(parts)

    print(line1)
    print(line2)
    print()


# Table rendering
def render_cve(rows):
    max_id_len = 14
    for m in rows:
        cve_id = m.get("cve_id", "") or ""
        length = len(cve_id)
        if length > max_id_len:
            max_id_len = length

    id_w = max_id_len + 2
    if id_w < 16:
        id_w = 16
    if id_w > 22:
        id_w = 22

    sev_w = 5
    cvss_w = 4
    pub_w = 10
    sep = " " * GUTTER

    head = (
        pad_r(paint("label", "CVE ID"), id_w)
        + sep
        + pad_r(paint("label", "SEV"), sev_w)
        + sep
        + pad_r(paint("label", "CVSS"), cvss_w)
        + sep
        + pad_r(paint("label", "PUBLISHED"), pub_w)
    )
    print(head)

    for m in rows:
        cve_id = m.get("cve_id", "") or ""
        link = term_link(cve_id, "https://nvd.nist.gov/vuln/detail/" + cve_id)

        sev_t = sev_tag(m.get("severity", "UNKNOWN"))
        cvss = fmt_cvss(m.get("cvss_score", "N/A"))

        published = m.get("published") or "-"
        published = str(published)[:10]

        line = (
            pad_r(paint("info", link), id_w)
            + sep
            + pad_r(sev_t, sev_w)
            + sep
            + pad_l(paint("value", cvss), cvss_w)
            + sep
            + pad_r(paint("value", published), pub_w)
        )
        print(line)


# Core CVE matching logic for a given RouterOS version
def run_cve_match_for_version(current_v, current_version: str):
    cve_data = load_cve_data()
    if not cve_data:
        return

    counters = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    matches = []

    for cve in cve_data:
        matched = False
        affected_versions = cve.get("affected_versions", [])

        if not affected_versions:
            affected_versions = extract_ranges_from_description(cve.get("description", ""))

        for version_info in affected_versions:
            if is_version_affected(current_v, version_info):
                matched = True
                break

        if not matched:
            continue

        sev = (cve.get("severity", "UNKNOWN") or "UNKNOWN").upper()
        counters[sev] = counters.get(sev, 0) + 1

        matches.append(
            {
                "cve_id": cve.get("cve_id", ""),
                "severity": sev,
                "cvss_score": cve.get("cvss_score", "N/A"),
                "published": cve.get("published", ""),
            }
        )

    print()
    render_summary(current_version, matches, counters)

    if not matches:
        print(paint("ok", "[*] No known CVEs found for this RouterOS version"))
        print()
        return

    rows = sorted(matches, key=key_tuple)
    render_cve(rows)


# Live CVE audit based on device version (kept for potential reuse)
def run_cve_audit(connection):
    print(paint("label", "[+] Search for CVEs for a specific version"))
    output = connection.send_command("/system resource print")
    match = re.search(r"version:\s*([\w.\-]+)", output)
    if not match:
        print(Fore.RED + "[-] ERROR: Could not determine RouterOS version.")
        return

    current_version = match.group(1)
    current_v = normalize_version(current_version)
    if not current_v:
        print(Fore.RED + f"[-] ERROR: RouterOS version '{current_version}' is invalid.")
        return

    run_cve_match_for_version(current_v, current_version)



# CVE audit for manually provided RouterOS version string (used by Sara)
def run_cve_audit_for_version(version_str: str):
    print(paint("label", "[+] Search for CVEs for a specific version"))
    current_version = version_str.strip()
    current_v = normalize_version(current_version)
    if not current_v:
        print(Fore.RED + f"[-] ERROR: RouterOS version '{current_version}' is invalid.")
        return

    run_cve_match_for_version(current_v, current_version)
