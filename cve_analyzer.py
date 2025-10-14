# Auxiliary module cve_analyzer.py for searching CVE using the NIST NVD database

# Copyright (c) 2025 Mahama Bazarov
# Licensed under the Apache 2.0 License
# This project is not affiliated with or endorsed by MikroTik

import json, re, os, requests, time
from packaging.version import Version, InvalidVersion
from colorama import Fore, Style

# Constants
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEYWORD = "routeros"
RESULTS_PER_PAGE = 2000
OUTPUT_FILE = "routeros_cves.json"

# Converts version string to a comparable Version object
def normalize_version(v):
    if not v:
        return None
    try:
        return Version(v)
    except InvalidVersion:
        # Strip unstable labels like 'rc', 'beta', etc
        cleaned = re.sub(r'(rc|beta|testing|stable)[\d\-]*', '', v, flags=re.IGNORECASE)
        try:
            return Version(cleaned)
        except InvalidVersion:
            return None

# Extract version ranges from CVE descriptions
def extract_ranges_from_description(description):
    description = description.lower()
    ranges = []

    # Match version ranges in various formats
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
        ranges.append({"versionEndIncluding": f"{base}.999"})

    matches = re.findall(r"(?:up to|and below)\s+v?(\d+\.\d+(?:\.\d+)?)", description)
    for end in matches:
        ranges.append({"versionEndIncluding": end})

    return ranges

# Determines if the given version falls within a vulnerable range
def is_version_affected(current_v, version_info):
    def get(v_key):
        return normalize_version(version_info.get(v_key))

    criteria = version_info.get("criteria", "")
    end_excl_raw = version_info.get("versionEndExcluding", "")
    
    # RouterOS 6.x vs 7.x false positive prevention
    if isinstance(end_excl_raw, str) and end_excl_raw.startswith("7") and str(current_v).startswith("6."):
        return False
    if isinstance(end_excl_raw, str) and end_excl_raw.startswith("6") and str(current_v).startswith("7."):
        return False

    # Parse version range keys
    start_incl = get("versionStartIncluding")
    start_excl = get("versionStartExcluding")
    end_incl   = get("versionEndIncluding")
    end_excl   = get("versionEndExcluding")

    # Fallback: match exact version in criteria if no range info is provided
    if not any([start_incl, start_excl, end_incl, end_excl]):
        version_match = re.search(r"routeros:([\w.\-]+)", criteria)
        if version_match:
            version_exact = normalize_version(version_match.group(1))
            return version_exact is not None and current_v == version_exact
        return False

    # Skip if range is invalid or unparseable
    for raw, normed in zip(["versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"],
                           [start_incl, start_excl, end_incl, end_excl]):
        if version_info.get(raw) and normed is None:
            return False

    # Perform actual version comparisons
    if start_incl and current_v < start_incl:
        return False
    if start_excl and current_v <= start_excl:
        return False
    if end_incl and current_v > end_incl:
        return False
    if end_excl and current_v >= end_excl:
        return False

    return True

# Downloads and stores all CVEs from NVD
def fetch_all_cves():
    all_cves = []
    start_index = 0

    print(Fore.CYAN + "[*] Fetching CVEs from NVD...")
    while True:
        params = {
            "keywordSearch": KEYWORD,
            "startIndex": start_index,
            "resultsPerPage": RESULTS_PER_PAGE
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

        # Process each CVE entry
        for item in cve_items:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            description = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            severity = "UNKNOWN"
            score = "N/A"

            # Extract CVSS score/severity
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                score = cvss.get("baseScore", "N/A")
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                score = cvss.get("baseScore", "N/A")

            # Extract affected version ranges
            affected_versions = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        affected_versions.append({
                            "criteria": match.get("criteria"),
                            "versionStartIncluding": match.get("versionStartIncluding"),
                            "versionStartExcluding": match.get("versionStartExcluding"),
                            "versionEndIncluding": match.get("versionEndIncluding"),
                            "versionEndExcluding": match.get("versionEndExcluding")
                        })

            all_cves.append({
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "cvss_score": score,
                "affected_versions": affected_versions
            })

        start_index += RESULTS_PER_PAGE
        if start_index >= total_results:
            break
        time.sleep(1.5)

    # Write results to file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_cves, f, indent=2, ensure_ascii=False)
    print(Fore.GREEN + f"[+] Saved {len(all_cves)} CVEs to {OUTPUT_FILE}")

# Perform local audit of current RouterOS version against cached CVE data
def run_cve_audit(connection):
    # Banner
    print(Fore.WHITE + "=" * 60)
    print(Fore.WHITE + "[!] Checking CVE Vulnerabilities")
    print(Fore.MAGENTA + "[!] In any case, validate results manually due to potential false positives.")
    print(Fore.WHITE + "=" * 60)

    # Retrieve RouterOS version from device
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

    print(Fore.GREEN + f"[+] Detected RouterOS Version: {current_version}")

    # Load or refresh CVE data
    if not os.path.isfile(OUTPUT_FILE):
        print(Fore.YELLOW + f"[!] {OUTPUT_FILE} not found.")
        fetch_all_cves()
    else:
        print(Fore.YELLOW + f"[?] {OUTPUT_FILE} already exists.")
        answer = input(Fore.YELLOW + "    Overwrite it with fresh CVE data? [yes/no]: ").strip().lower()
        if answer == "yes":
            fetch_all_cves()

    # Load local CVE file
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            cve_data = json.load(f)
    except Exception as e:
        print(Fore.RED + f"[-] Failed to load {OUTPUT_FILE}: {e}")
        return

    # CVE match logic
    counters = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    hits = []

    for cve in cve_data:
        matched = False
        affected_versions = cve.get("affected_versions", [])
        
        # Fallback: try parsing version from description if structured data is missing
        if not affected_versions:
            affected_versions = extract_ranges_from_description(cve.get("description", ""))

        for version_info in affected_versions:
            if is_version_affected(current_v, version_info):
                matched = True
                break

        if matched:
            hits.append(cve)
            severity = cve.get("severity", "UNKNOWN").upper()
            counters[severity] = counters.get(severity, 0) + 1

    # Display summary
    total = len(hits)
    print(Fore.WHITE + f"[*] Total matching CVEs: {total}")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = counters.get(level, 0)
        if count > 0:
            color = {
                "CRITICAL": Fore.RED + Style.BRIGHT,
                "HIGH": Fore.RED,
                "MEDIUM": Fore.YELLOW,
                "LOW": Fore.CYAN,
                "UNKNOWN": Fore.WHITE
            }[level]
            print(color + f"[*] {level}: {count}")

    # Print vulnerability details
    if total > 0:
        print(Fore.WHITE + "[*] Vulnerability details:")
        for cve in hits:
            severity = cve.get("severity", "UNKNOWN").upper()
            description = cve.get("description", "").strip()
            score = cve.get("cvss_score", "N/A")
            color = {
                "CRITICAL": Fore.RED + Style.BRIGHT,
                "HIGH": Fore.RED,
                "MEDIUM": Fore.YELLOW,
                "LOW": Fore.CYAN,
                "UNKNOWN": Fore.WHITE
            }.get(severity, Fore.WHITE)

            print(color + f"\n→ {cve['cve_id']} [{severity}]")
            print(Fore.WHITE + "    " + description)
            print(Fore.WHITE + f"    CVSS Score: {score}")