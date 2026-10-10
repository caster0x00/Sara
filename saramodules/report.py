# report.py

from colorama import Fore, Style, init

init(autoreset=True)

INDENT = "    "

severity_color = {
    "critical": Fore.MAGENTA,
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
}

# NVD URL
nvd_detail_url = "https://nvd.nist.gov/vuln/detail/"

# short severity labels for the CVE table, same order as the summary line
severity_short = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED",
    "low": "LOW",
    "unknown": "UNK",
}

# device information
def header(rows):
    print()
    print("[*] Device Information")
    for label, value in rows:
        print(f"  {label:<10} {value}")
    print()


# info line
def info(msg):
    print(INDENT + f"[*] {msg}")


# ok line
def ok(msg):
    print(Fore.GREEN + INDENT + f"[✓] {msg}")


# error line
def error(msg):
    print(Fore.RED + INDENT + f"[-] {msg}")


# print one finding block
def finding(id, severity, title, evidence, impact, fix):
    color = severity_color[severity]
    print()
    print(color + Style.BRIGHT + f"[{severity.upper()}] {id}: {title}")
    print(Fore.CYAN + "  - Evidence:")
    for line in evidence:
        print(f"      {line}")
    print(Fore.YELLOW + f"  - Impact: {impact}")
    print(Fore.GREEN + f"  - How to Fix: {fix}")


# CVE ID padded to width and turned into a terminal hyperlink (OSC 8) to its NVD page
# terminals without hyperlink support just show the plain ID
def cve_link(cve_id, width):
    padding = " " * (width - len(cve_id))
    return f"\033]8;;{nvd_detail_url}{cve_id}\033\\{cve_id}\033]8;;\033\\" + padding


# CVE summary line and table, rows are dicts with id, severity, score, published, fixed
def cve_table(version, rows):
    counts = {}
    for severity in severity_short:
        counts[severity] = 0
    for row in rows:
        counts[row["severity"]] += 1

    print()
    print(Style.BRIGHT + f"Target RouterOS Version: {version}    Matched CVEs: {len(rows)}")

    # autoreset only works at the end of a print, so reset each colored part by hand
    parts = []
    for severity, short in severity_short.items():
        color = severity_color.get(severity, "")
        parts.append(color + f"{short}: {counts[severity]}" + Style.RESET_ALL)
    print(" | ".join(parts))

    if not rows:
        return

    print()
    print(Style.BRIGHT + f"{'CVE ID':<18}{'SEV':<6}{'CVSS':<6}{'PUBLISHED':<12}FIXED IN")
    for row in rows:
        color = severity_color.get(row["severity"], "")
        short = severity_short[row["severity"]]
        score = str(row["score"]) if row["score"] is not None else "-"
        print(cve_link(row["id"], 18) + color + f"{short:<6}" + Style.RESET_ALL
              + f"{score:<6}{row['published']:<12}{row['fixed']}")


# CVEs that mention RouterOS but have no version ranges in NVD, rows are dicts with id, status, published
def cve_unanalyzed(rows):
    print()
    print(Style.BRIGHT + f"Not analyzed by NVD: {len(rows)}")
    print(Style.DIM + "These CVEs mention RouterOS, but NVD has not linked them to affected versions yet.")
    print(Style.DIM + "Check each one manually against its advisory or the MikroTik changelog.")
    print()
    print(Style.BRIGHT + f"{'CVE ID':<18}{'NVD STATUS':<20}PUBLISHED")
    for row in rows:
        print(cve_link(row["id"], 18) + f"{row['status']:<20}{row['published']}")
