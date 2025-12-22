#!/usr/bin/env python3

# Sara: MikroTik RouterOS Security Inspector
# Copyright (c) 2026 Magama Bazarov
# Licensed under the Apache 2.0 License
# This project is not affiliated with or endorsed by SIA Mikrotīkls

import argparse
import colorama
import re
import sys
import os
from getpass import getpass
from netmiko import ConnectHandler
from colorama import Fore, Style
from packaging.version import Version
from cve_analyzer import run_cve_audit, run_cve_audit_for_version

# init colors
colorama.init(autoreset=True)

INDENT = "    "


# print banner
def banner():
    banner_art = r"""
       _____                 
      / ___/____ __________ _
      \__ \/ __ `/ ___/ __ `/
     ___/ / /_/ / /  / /_/ / 
    /____/\__,_/_/   \__,_/                              
"""
    print(INDENT + banner_art)
    print(INDENT + "Sara: " + Style.RESET_ALL + "MikroTik RouterOS Security Inspector")
    print(INDENT + "Developer: " + Style.RESET_ALL + "Magama Bazarov (Caster)")
    print(INDENT + "Contact: " + Style.RESET_ALL + "magamabazarov@mailbox.org")
    print(INDENT + "Version: " + Style.RESET_ALL + "1.3.0")
    print(INDENT + "Documentation & Usage: " + Style.RESET_ALL + "https://github.com/caster0x00/Sara")


# section header
def section(title: str):
    print()
    print(Fore.WHITE + f"[+] {title}" + Style.RESET_ALL)


# info line
def info(msg: str):
    print(Fore.WHITE + INDENT + f"[*] {msg}")


# ok line
def ok(msg: str):
    print(Fore.GREEN + INDENT + f"[✓] {msg}")


# warning line
def warn(msg: str):
    print(Fore.YELLOW + INDENT + f"[!] {msg}")


# high severity line
def alert(msg: str):
    print(Fore.RED + INDENT + f"[!] {msg}")


# error line
def error(msg: str):
    print(Fore.RED + INDENT + f"[-] {msg}")


# detailed line
def detail(msg: str):
    print(Fore.LIGHTWHITE_EX + INDENT * 2 + f"[*] {msg}" + Style.RESET_ALL)


# ssh connection helper
def connect_to_router(ip, user, password=None, port=22, key_file=None, key_passphrase=None):
    device = {
        "device_type": "mikrotik_routeros",
        "host": ip,
        "username": user,
        "port": port,
    }

    # key-based auth
    if key_file:
        key_path = os.path.expanduser(key_file)
        if not os.path.exists(key_path):
            error(f"SSH key not found: {key_path}")
            info("Provide path to the private key (not .pub)")
            sys.exit(1)

        device["use_keys"] = True
        device["key_file"] = key_path

        if key_passphrase:
            device["passphrase"] = key_passphrase
    else:
        # password auth
        if not password:
            error("No authentication method provided")
            sys.exit(1)
        device["password"] = password
        device["use_keys"] = False

    # connect
    try:
        conn = ConnectHandler(**device)
        ok(f"SSH connection established: {user}@{ip}")
        return conn
    except Exception as e:
        error(f"SSH connection failed: {e}")
        sys.exit(1)


# resolve auth method and prompt
def normalize_auth_and_prompt(args):
    key_file = args.key
    key_passphrase = None

    # key flow
    if key_file:
        key_file = os.path.expanduser(key_file)
        if not os.path.exists(key_file):
            error(f"SSH key file not found: {key_file}")
            info("Provide path to the private key (not .pub)")
            sys.exit(1)

        prompt = f"[?] Passphrase for key {key_file} (leave empty if none): "
        entered = getpass(prompt)
        if entered:
            key_passphrase = entered

        return None, key_file, key_passphrase

    # password flow
    password = getpass(f"[?] SSH password for {args.username}@{args.ip}: ")
    return password, None, None


# simple version wrapper
def parse_version(version_str):
    return Version(version_str)


# detect and print RouterOS version
def check_routeros_version(connection):
    # run resource print
    output = connection.send_command("/system resource print")
    match = re.search(r"version:\s*([\d.]+)", output)
    if match:
        routeros_version = parse_version(match.group(1))
        info(f"Detected RouterOS: {Fore.MAGENTA}{routeros_version}{Style.RESET_ALL}")
    else:
        error("Could not determine RouterOS version")


# SMB service check
def check_smb(connection):
    section("SMB Service")
    output = connection.send_command("/ip smb print")
    if "enabled: yes" in output:
        alert("SMB service is enabled! Do you need SMB? Also avoid CVE-2018-7445")
    else:
        ok("SMB is disabled")
        ok("No issues detected")


# RMI services exposure check
def check_rmi_services(connection):
    section("Remote Management (RMI/MGMT)")
    output = connection.send_command("/ip service print")
    high_risk = ["telnet", "ftp", "www"]
    moderate_risk = ["api", "api-ssl", "winbox", "www-ssl"]
    ssh = ["ssh"]
    risks_found = False

    # scan line by line
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # skip disabled/default
        if re.search(r"^\d+\s+X\b", line):
            continue
        if re.search(r"^\d+\s+D\b", line):
            continue

        match = re.search(r"(\S+)\s+\d+", line)
        if not match:
            continue

        service_name = match.group(1).lower()
        display_name = service_name.upper().replace("WWW", "HTTP").replace("WWW-SSL", "HTTPS")

        # high risk
        if service_name in high_risk:
            alert(f"{display_name} is enabled (high risk)")
            if service_name == "ftp":
                warn("FTP transmits credentials in cleartext")
            if service_name == "telnet":
                warn("Telnet allows credential interception")
            if service_name == "www":
                warn("HTTP credentials can be sniffed over the network")
            risks_found = True
            continue

        # medium risk
        if service_name in moderate_risk:
            warn(f"{display_name} is enabled")
            if service_name in ["api", "api-ssl"]:
                info("RouterOS API is a brute-force target; restrict access")
            elif service_name == "www-ssl":
                info("Ensure HTTPS uses strong ciphers and valid certificates")
            elif service_name == "winbox":
                warn("Winbox enabled. Winbox 'Keep Password' may store credentials in plaintext. If the PC is compromised, saved passwords may be extracted!")
            continue

        # ssh
        if service_name in ssh:
            ok(f"{display_name} enabled. Use strong passwords or SSH keys for authentication")

    if not risks_found:
        ok("No high-risk RMI services detected")


# default usernames check
def check_default_users(connection):
    section("Default Usernames")
    output = connection.send_command("/user print detail")
    default_users = {"admin", "engineer", "user", "test", "root", "mikrotik", "routeros"}
    risks_found = False

    # split user blocks
    for block in output.split("\n\n"):
        match = re.search(r'name="([^"]+)"', block)
        if not match:
            continue
        username = match.group(1).lower()
        if username in default_users:
            warn(f"Default username detected: '{username}'")
            info("Change it to a unique value to reduce attack surface")
            risks_found = True

    if not risks_found:
        ok("No default usernames found")


# check service address-list on /ip service
def checking_access_to_RMI(connection):
    section("RMI/MGMT Access Restrictions")
    output = connection.send_command("/ip service print")
    lines = output.splitlines()
    header_line = None

    # find header
    for line in lines:
        if line.strip().startswith("#"):
            header_line = line
            break

    if not header_line:
        error("Unable to parse /ip service print header")
        return

    try:
        idx_name = header_line.index("NAME")
        idx_addr = header_line.index("ADDRESS")
        idx_cert = header_line.index("CERTIFICATE") if "CERTIFICATE" in header_line else None
    except ValueError:
        error("Expected columns NAME/ADDRESS not found in /ip service print output")
        return

    risks_found = False

    # parse body
    for line in lines:
        if not line.strip():
            continue
        if line == header_line or line.strip().startswith("Flags:") or line.strip().startswith("Columns:"):
            continue

        stripped = line.lstrip()
        if not stripped or not stripped[0].isdigit():
            continue

        flags_field = line[:idx_name]
        if "X" in flags_field or "D" in flags_field:
            continue

        service_name_raw = line[idx_name:idx_addr].strip()
        if not service_name_raw:
            continue
        service_name = service_name_raw.upper()

        if idx_cert is not None and len(line) > idx_addr:
            addr_raw = line[idx_addr:idx_cert]
        else:
            addr_raw = line[idx_addr:]
        address = addr_raw.strip()

        # empty address -> no restrictions
        if not address:
            alert(f"{service_name} has no IP restriction")
            risks_found = True
        else:
            ok(f"{service_name} restricted to: {address}")

    if not risks_found:
        ok("All RMI services have proper IP restrictions")


# WiFi / PMKID / WPS check (/interface/wifi/print detail, RouterOS v7+)
def check_wifi_security(connection):
    section("WiFi Security")
    try:
        output = connection.send_command("/interface/wifi/print detail")
    except Exception as e:
        error(f"Error while checking WiFi: {e}")
        return

    if not output.strip():
        ok("No WiFi interfaces found")
        return

    interfaces = output.split("\n\n")
    risks_found = False

    # scan interfaces
    for iface in interfaces:
        if not iface.strip():
            continue

        name_match = re.search(r'\bname="([^"]+)"', iface)
        if not name_match:
            name_match = re.search(r'\bdefault-name="([^"]+)"', iface)

        if name_match:
            iface_name = name_match.group(1)
        else:
            iface_name = "Unknown"

        pmkid_enabled = re.search(r'\.disable-pmkid=no\b', iface)
        wps_push = re.search(r'\.wps=push-button\b', iface)

        if pmkid_enabled or wps_push:
            warn(f"WiFi interface '{iface_name}' has potentially weak security settings")
            if pmkid_enabled:
                detail("PMKID is enabled (.disable-pmkid=no) - allows offline PMKID-based attacks on WPA/WPA2-PSK")
            if wps_push:
                detail("WPS push-button is enabled (.wps=push-button) - WPS is a known attack surface; disable it in production")
            risks_found = True

    if not risks_found:
        ok("No risky WiFi security settings detected")


# UPnP check
def check_upnp_status(connection):
    section("UPnP Status")
    output = connection.send_command("/ip upnp print")
    if "enabled: yes" in output:
        alert("UPnP is enabled")
        detail("UPnP allows automatic port forwarding to internal hosts")
        detail("Can expose devices to the Internet without your awareness")
        detail("Ensure this was intentionally enabled")
    else:
        ok("UPnP is disabled")


# DNS behavior check
def check_dns_status(connection):
    section("DNS Settings")
    output = connection.send_command("/ip dns print")
    if "allow-remote-requests: yes" in output:
        warn("Router is acting as a DNS server")
        detail("DNS queries from the network are accepted")
        detail("Ensure DNS is not exposed on external interfaces")
    else:
        ok("Remote DNS requests are disabled")


# DDNS check
def check_ddns_status(connection):
    section("DDNS Settings")
    output = connection.send_command("/ip cloud print")
    if "ddns-enabled: yes" in output:
        warn("Dynamic DNS is enabled")
        detail("Your router may become reachable via a public hostname")
        detail("Ensure this is needed for remote access or VPN setups")
    else:
        ok("DDNS is disabled")


# PoE check
def check_poe_status(connection):
    section("PoE Status")
    output = connection.send_command("/interface ethernet print detail")
    interfaces = output.split("\n\n")
    risks_found = False

    # inspect each port
    for iface in interfaces:
        if not iface.strip():
            continue

        name_match = re.search(r'name="([^"]+)"', iface)
        poe_match = re.search(r'poe-out=(\S+)', iface)
        name = name_match.group(1) if name_match else "Unknown"
        poe_mode = poe_match.group(1) if poe_match else "none"

        if poe_mode in ("auto-on", "forced-on"):
            warn(f"PoE is enabled on interface '{name}'")
            detail("Ensure connected devices support PoE to avoid hardware damage")
            risks_found = True

    if not risks_found:
        ok("No PoE-enabled interfaces detected")


# RouterBOOT protection check
def check_routerboot_protection(connection):
    section("RouterBOOT Protection")
    output = connection.send_command("/system routerboard settings print")
    if "protected-routerboot: disabled" in output:
        alert("RouterBOOT protection is disabled")
        detail("Device can be reset or reflashed via Netinstall without authentication")
        detail("Enable 'protected-routerboot' to prevent unauthorized boot changes")
    else:
        ok("RouterBOOT protection is enabled")


# SOCKS proxy check
def check_socks_status(connection):
    section("SOCKS Proxy Status")
    output = connection.send_command("/ip socks print")
    if "enabled: yes" in output:
        alert("SOCKS proxy is enabled")
        detail("SOCKS may indicate unauthorized tunneling or compromise")
        detail("Attackers often use SOCKS as a pivot into internal networks")
        detail("Disable unless explicitly required for your environment")
    else:
        ok("SOCKS proxy is disabled")


# bandwidth-server check
def check_bandwidth_server_status(connection):
    section("Bandwidth Server Status")
    output = connection.send_command("/tool bandwidth-server print")
    if "enabled: yes" in output:
        warn("Bandwidth server is enabled")
        detail("May generate unwanted test traffic")
        detail("Can increase CPU load under active use")
    else:
        ok("Bandwidth server is disabled")


# neighbor discovery config check
def check_neighbor_discovery(connection):
    section("Neighbor Discovery Protocols")
    output = connection.send_command("/ip neighbor discovery-settings print")
    risks_found = False

    if "discover-interface-list: all" in output:
        warn("Discovery packets are sent on all interfaces")
        detail("This allows attackers to map RouterOS presence on multiple segments")
        risks_found = True

    protocol_match = re.search(r'protocol: ([\w,]+)', output)
    if protocol_match:
        protocols = protocol_match.group(1)
        warn(f"Neighbor discovery protocols enabled: {protocols}")
        detail("Limit discovery to management or trusted interfaces only")
        risks_found = True

    if not risks_found:
        ok("No security risks found in Neighbor Discovery configuration")


# password policy check
def check_password_length_policy(connection):
    section("Password Policy")
    output = connection.send_command("/user settings print")
    if "minimum-password-length: 0" in output:
        warn("No minimum password length is enforced")
        detail("Short passwords significantly reduce brute-force resistance")
        detail("Set a minimum length (e.g. 10-12 characters or more)")
    else:
        ok("Password length policy is enforced")


# SSH security check
def check_ssh_security(connection):
    section("SSH Security")
    output = connection.send_command("/ip ssh print")
    risks_found = False

    if "forwarding-enabled: both" in output:
        warn("SSH dynamic port forwarding is enabled")
        detail("May be used as a tunneling/pivoting channel")
        detail("Verify this is required and properly restricted")
        risks_found = True

    if "strong-crypto: no" in output:
        warn("Strong SSH crypto is disabled")
        detail("Enable 'strong-crypto' to enforce stronger ciphers and MACs")
        detail("Disables weak algorithms (MD5, null encryption, small DH groups)")
        risks_found = True

    if not risks_found:
        ok("SSH security settings are properly configured")


# Connection tracking check
def check_connection_tracking(connection):
    section("Connection Tracking")
    output = connection.send_command("/ip firewall connection tracking print")
    if "enabled: auto" in output or "enabled: on" in output:
        warn("Connection tracking is enabled")
        detail("RouterOS tracks connection states for firewall/NAT")
        detail("On pure transit routers without NAT, disabling may reduce CPU load")
    else:
        ok("Connection tracking is configured appropriately")


# RoMON check
def check_romon_status(connection):
    section("RoMON Status")
    output = connection.send_command("/tool romon print")
    if "enabled: yes" in output:
        warn("RoMON is enabled")
        detail("Provides Layer 2 management access to RouterOS devices")
        detail("Disable RoMON if not explicitly required to reduce attack surface")
    else:
        ok("RoMON is disabled")


# MAC Winbox / MAC Telnet / MAC ping checks
def check_mac_winbox_security(connection):
    section("Winbox MAC Server Settings")

    # MAC Winbox
    try:
        output = connection.send_command("/tool mac-server mac-winbox print")
        if "allowed-interface-list" in output:
            if "allowed-interface-list: all" in output:
                warn("MAC Winbox access is allowed on all interfaces")
                detail("Limit MAC Winbox to management or trusted segments only")
            else:
                ok("MAC Winbox is restricted to specific interfaces")
        else:
            # legacy layout
            if re.search(r"\bINTERFACE\s*\n.*\ball\b", output, re.DOTALL | re.IGNORECASE):
                warn("MAC Winbox access is allowed on all interfaces (legacy format)")
                detail("Limit MAC Winbox to management or trusted segments only")
            else:
                ok("MAC Winbox is properly restricted (legacy format)")
    except Exception as e:
        error(f"Error while checking MAC Winbox: {e}")

    # MAC Telnet
    try:
        output = connection.send_command("/tool mac-server print")
        if "allowed-interface-list" in output:
            if "allowed-interface-list: all" in output:
                warn("MAC Telnet access is allowed on all interfaces")
                detail("Limit MAC Telnet to management or trusted segments only")
            else:
                ok("MAC Telnet is restricted to specific interfaces")
        else:
            if re.search(r"\bINTERFACE\s*\n.*\ball\b", output, re.DOTALL | re.IGNORECASE):
                warn("MAC Telnet access is allowed on all interfaces (legacy format)")
                detail("Limit MAC Telnet to management or trusted segments only")
            else:
                ok("MAC Telnet is properly restricted (legacy format)")
    except Exception as e:
        error(f"Error while checking MAC Telnet: {e}")

    # MAC ping
    try:
        output = connection.send_command("/tool mac-server ping print")
        if "enabled: yes" in output:
            warn("MAC Ping is enabled")
            detail("May generate unnecessary Layer 2 broadcast traffic")
        else:
            ok("MAC Ping is restricted or disabled")
    except Exception as e:
        error(f"Error while checking MAC Ping: {e}")


# SNMP communities check
def check_snmp(connection):
    section("SNMP Community Strings")
    output = connection.send_command("/snmp community print")
    bad_names = {"public", "private", "admin", "mikrotik", "mikrotik_admin", "root", "routeros", "zabbix"}
    risks_found = False

    # scan table
    for line in output.splitlines():
        match = re.search(r'^\s*\d+\s+[*X]?\s*([\w-]+)', line)
        if not match:
            continue
        community_name = match.group(1).lower()
        if community_name in bad_names:
            warn(f"Weak SNMP community string detected: '{community_name}'")
            detail("Change it to a long, random value and restrict source IPs")
            risks_found = True

    if not risks_found:
        ok("SNMP community strings checked - no weak values detected")


# dst-nat / netmap rules check
def check_dst_nat_rules(connection):
    section("Firewall NAT Rules")
    output = connection.send_command("/ip firewall nat print")
    dst_nat_rules = []

    for line in output.splitlines():
        if "action=dst-nat" in line or "action=netmap" in line:
            dst_nat_rules.append(line.strip())

    if dst_nat_rules:
        warn("Destination NAT (dst-nat/netmap) rules detected")
        detail("Exposing internal services to the Internet can be dangerous")
        detail("Verify that each rule is intentional and properly restricted")
        for rule in dst_nat_rules:
            detail(rule)
    else:
        ok("No Destination NAT (dst-nat/netmap) rules detected")


# scheduler / persistence check
def detect_malicious_schedulers(connection):
    section("Schedulers & Persistence")
    output = connection.send_command("/system scheduler print detail")
    risks_found = False
    fetch_files = set()
    tasks = output.split("\n\n")

    # first pass: track fetch targets
    for task in tasks:
        if not task.strip():
            continue

        event_match = re.search(r'on-event="?([^"\n]+)"?', task)
        event = event_match.group(1).strip() if event_match else ""
        fetch_match = re.search(r'dst-path=([\S]+)', event)
        if "fetch" in event and fetch_match:
            fetched_file = fetch_match.group(1).strip(";")
            fetch_files.add(fetched_file)

    # second pass: analyze schedulers
    for task in tasks:
        if not task.strip():
            continue

        name_match = re.search(r'name="?([^"]+)"?', task)
        event_match = re.search(r'on-event="?([^"\n]+)"?', task)
        policy_match = re.search(r'policy=([\w,]+)', task)
        interval_match = re.search(r'interval=(\d+)([smhd])', task)

        name = name_match.group(1) if name_match else "Unknown"
        event = event_match.group(1).strip() if event_match else ""
        policies = policy_match.group(1).split(",") if policy_match else []
        interval_value, interval_unit = (int(interval_match.group(1)), interval_match.group(2)) if interval_match else (None, None)

        issues = []

        # fetch + import chain
        import_match = re.search(r'import\s+([\S]+)', event)
        if "import" in event and import_match:
            imported_file = import_match.group(1).strip(";")
            if imported_file in fetch_files:
                issues.append("Imports a previously fetched script - potential backdoor")
                if interval_value and interval_unit:
                    issues.append(f"Runs every {interval_value}{interval_unit}, ensures persistence")

        # dangerous policies
        dangerous_policies = {"password", "sensitive", "sniff", "ftp"}
        used_dangerous = [p for p in policies if p in dangerous_policies]
        if used_dangerous:
            issues.append(f"Uses high-privilege policies: {', '.join(used_dangerous)}")

        # reboots
        if "reboot" in event:
            if interval_value and interval_unit in ["s", "m", "h"] and interval_value < 12:
                issues.append(f"Frequently reboots router ({interval_value}{interval_unit}) - possible anti-forensics")
            else:
                issues.append("Schedules router reboot - verify it is intentional")

        # tight intervals
        if interval_value and interval_unit in ["s", "m", "h"] and interval_value < 25:
            issues.append(f"Executes too frequently ({interval_value}{interval_unit}) - may indicate persistence or botnet-like activity")

        if issues:
            alert(f"Scheduler '{name}' looks suspicious")
            for msg in issues:
                detail(msg)
            risks_found = True

    if not risks_found:
        ok("No suspicious schedulers detected")


# static DNS entries check
def check_static_dns_entries(connection):
    section("Static DNS Entries")
    output = connection.send_command("/ip dns static print detail")
    dns_entries = []
    entry_blocks = output.split("\n\n")

    # parse entries
    for entry in entry_blocks:
        if not entry.strip():
            continue
        name_match = re.search(r'name="([^"]+)"', entry)
        address_match = re.search(r'address=([\d.]+)', entry)
        if name_match and address_match:
            name = name_match.group(1)
            address = address_match.group(1)
            dns_entries.append((name, address))

    if dns_entries:
        warn("Static DNS entries are configured")
        detail("Verify that each record is legitimate and expected")
        for name, address in dns_entries:
            detail(f"{name} → {address}")
        detail("Attackers often modify DNS for phishing or traffic redirection during post-exploitation")
    else:
        ok("No static DNS entries found")


# parse audit profiles
def parse_profiles(profiles_str):
    raw = [p.strip().lower() for p in profiles_str.split(",")]
    selected = {p for p in raw if p}
    valid = {"system", "protocols", "wifi"}

    if not selected:
        error("No profiles specified")
        info("Use at least one profile: system, protocols, wifi")
        sys.exit(1)

    invalid = selected - valid
    if invalid:
        error("Unknown profiles: " + ", ".join(sorted(invalid)))
        info("Valid profiles: system, protocols, wifi")
        sys.exit(1)

    return selected


# main audit dispatcher
def run_sara_audit(args):
    section("Sara Audit Mode")
    info(f"Target Device: {args.ip}")
    info(f"Transport: SSH (port {args.port})")

    profiles = parse_profiles(args.profiles)
    password, key_file, key_passphrase = normalize_auth_and_prompt(args)
    connection = connect_to_router(
        args.ip,
        args.username,
        password=password,
        port=args.port,
        key_file=key_file,
        key_passphrase=key_passphrase,
    )

    # system profile
    if "system" in profiles:
        check_routeros_version(connection)
        check_default_users(connection)
        check_rmi_services(connection)
        checking_access_to_RMI(connection)
        check_poe_status(connection)
        check_routerboot_protection(connection)
        check_bandwidth_server_status(connection)
        check_password_length_policy(connection)
        check_ssh_security(connection)
        check_connection_tracking(connection)
        check_romon_status(connection)
        check_mac_winbox_security(connection)
        check_dst_nat_rules(connection)
        detect_malicious_schedulers(connection)

    # protocols profile
    if "protocols" in profiles:
        check_smb(connection)
        check_upnp_status(connection)
        check_socks_status(connection)
        check_dns_status(connection)
        check_static_dns_entries(connection)
        check_ddns_status(connection)
        check_neighbor_discovery(connection)
        check_snmp(connection)

    # wifi profile
    if "wifi" in profiles:
        check_wifi_security(connection)

    connection.disconnect()
    print(f"[*] Disconnected from RouterOS ({args.ip})")


# CVE command dispatcher
def run_cve_command(args):
    # mode 1: manual version
    if args.mode_or_ip.lower() == "version":
        version = args.username_or_version.strip()

        section("CVE Search (Manual)")
        info(f"RouterOS Version: {version}")

        # always pass string here
        run_cve_audit_for_version(version)
        return

    # mode 2: live device
    ip = args.mode_or_ip
    username = args.username_or_version

    # reuse auth helper
    args.ip = ip
    args.username = username

    section("CVE Search (Live)")
    info(f"Target Device: {ip}")
    info(f"Transport: SSH (port {args.port})")

    password, key_file, key_passphrase = normalize_auth_and_prompt(args)
    connection = connect_to_router(
        ip,
        username,
        password=password,
        port=args.port,
        key_file=key_file,
        key_passphrase=key_passphrase,
    )

    # here we pass connection, not version string
    run_cve_audit(connection)

    connection.disconnect()
    print(f"[*] Disconnected from RouterOS ({ip})")

def main():
    banner()
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    # Audit mode
    audit = sub.add_parser("audit", help="Run RouterOS security configuration audit")
    audit.add_argument("ip", help="RouterOS IP address")
    audit.add_argument("username", help="SSH username")
    audit.add_argument("profiles", help="Profiles: system,protocols,wifi (comma-separated)")
    audit.add_argument("key", nargs="?", default=None, help="Path to SSH private key (optional)")
    audit.add_argument("port", nargs="?", type=int, default=22, help="SSH port (default: 22)")
    audit.set_defaults(func=run_sara_audit)

    # CVE mode
    cve = sub.add_parser("cve", help="Run RouterOS CVE audit (live or by version)")
    cve.add_argument("mode_or_ip", help="'version' or RouterOS IP address")
    cve.add_argument("username_or_version", help="SSH username or RouterOS version string")
    cve.add_argument("key", nargs="?", default=None, help="Path to SSH private key (optional)")
    cve.add_argument("port", nargs="?", type=int, default=22, help="SSH port (default: 22)")
    cve.set_defaults(func=run_cve_command)

    # no args = help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    try:
        # dispatch
        args = parser.parse_args()
        args.func(args)
    except KeyboardInterrupt:
        print()
        error("Interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()