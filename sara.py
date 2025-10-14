#!/usr/bin/env python3

# Copyright (c) 2025 Mahama Bazarov
# Licensed under the Apache 2.0 License
# This project is not affiliated with or endorsed by MikroTik

import argparse, colorama, time, re, sys
from netmiko import ConnectHandler
from colorama import Fore, Style
from packaging.version import Version
from cve_analyzer import run_cve_audit

# Initialize colorama for colored console output
colorama.init(autoreset=True)

def banner():
    banner_text = r"""
    _____                 
   / ____|                
  | (___   __ _ _ __ __ _ 
   \___ \ / _` | '__/ _` |
   ____) | (_| | | | (_| |
  |_____/ \__,_|_|  \__,_|
"""
    # Display the program banner and metadata
    print(banner_text)
    print("    " + Fore.YELLOW + "RouterOS Security Inspector. Designed for security engineers")
    print("    " + Fore.YELLOW + "Author: " + Style.RESET_ALL + "Mahama Bazarov, <mahamabazarov@mailbox.org>")
    print("    " + Fore.YELLOW + "Alias: " + Style.RESET_ALL + "Caster")
    print("    " + Fore.YELLOW + "Version: " + Style.RESET_ALL + "1.2")
    print("    " + Fore.YELLOW + "Documentation & Usage: " + Style.RESET_ALL + "https://github.com/caster0x00/Sara\n")

    # Display a legal disclaimer to emphasize responsible usage
    print("    " + Fore.YELLOW + "[!] DISCLAIMER: Use this tool only for auditing your own devices.")
    print("    " + Fore.YELLOW + "[!] Unauthorized use on third-party systems is ILLEGAL.")
    print("    " + Fore.YELLOW + "[!] The author is not responsible for misuse.")
    print()

# Establish SSH connection to the RouterOS device using Netmiko
def connect_to_router(ip, username, password, port, key_file, passphrase):
    device = {
        "device_type": "mikrotik_routeros",
        "host": ip,
        "username": username,
        "password": password,
        "port": port,
        "key_file": key_file,
        "passphrase": passphrase,
    }
    try:
        print(Fore.WHITE + f"[*] Connecting to RouterOS at {ip}:{port}")
        connection = ConnectHandler(**device)
        print(Fore.WHITE + "[*] Connection successful!")
        return connection
    except Exception as e:
        print(Fore.RED + f"[-] Connection failed: {e}")
        exit(1)

# Print a visual separator for better readability in the output
def separator(title):
    print(Fore.WHITE + Style.BRIGHT + '=' * 50)
    print(Fore.WHITE + Style.BRIGHT + f"[*] {title}")

def parse_version(version_str):
    # Parses a version string into a comparable Version object. Example: "6.49.7" → Version(6.49.7)
    return Version(version_str)

# Retrieves the RouterOS version
def check_routeros_version(connection):
    # Separator outlet
    separator("Checking RouterOS Version")
    command = "/system resource print"
    output = connection.send_command(command)

    match = re.search(r"version:\s*([\d.]+)", output)
    if match:
        routeros_version = parse_version(match.group(1))
        print(Fore.GREEN + f"[+] Detected RouterOS Version: {routeros_version}")
    else:
        print(Fore.RED + Style.BRIGHT + "[-] ERROR: Could not determine RouterOS version.")

# Check if SMB service is enabled (potential security risk)
def check_smb(connection):
    # Separator outlet
    separator("Checking SMB Service")
    command = "/ip smb print"
    output = connection.send_command(command)
    
    if "enabled: yes" in output:
        print(Fore.RED + "[*] CAUTION: SMB service is enabled! Did you turn it on? Do you need SMB? Also avoid CVE-2018-7445")
    else:
        print(Fore.GREEN + "[+] SMB is disabled. No risk detected.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")
       
# Check for high-risk remote management interfaces (RMI)
def check_rmi_services(connection):
    # Separator outlet
    separator("Checking RMI Services")
    command = "/ip service print"
    output = connection.send_command(command)

    high_risk = ["telnet", "ftp", "www"]
    moderate_risk = ["api", "api-ssl", "winbox", "www-ssl"] 
    safe = ["ssh"]

    risks_found = False

    for line in output.splitlines():
        line = line.strip()
        if re.search(r"^\d+\s+X", line):  
            continue  
        match = re.search(r"(\S+)\s+\d+", line)  
        if match:
            service_name = match.group(1).lower()
            display_name = service_name.upper().replace("WWW", "HTTP").replace("WWW-SSL", "HTTPS")

            if service_name in high_risk:
                print(Fore.RED + f"[!] ALERT: {display_name} is ENABLED! This is a high security risk.")
                if service_name == "ftp":
                    print(Fore.RED + "    - Are you sure you need FTP?")
                if service_name == "telnet":
                    print(Fore.RED + "    - Account passwords can be intercepted")
                if service_name == "www":
                    print(Fore.RED + "    - Account passwords can be intercepted")
                risks_found = True

            elif service_name in moderate_risk:
                print(Fore.YELLOW + f"[!] CAUTION: {display_name} is enabled.")
                if service_name in ["api", "api-ssl"]:
                    print(Fore.YELLOW + "    - RouterOS API is vulnerable to a bruteforce attack. If you need it, make sure you have access to it.")
                elif service_name == "www-ssl":
                    print(Fore.GREEN + "    - HTTPS detected. Ensure it uses a valid certificate and strong encryption.")
                elif service_name == "winbox":
                    print(Fore.RED + "[!] CAUTION: If you're using 'Keep Password' in Winbox, your credentials may be stored in plaintext!")
                    print(Fore.YELLOW + "    - If your PC is compromised, attackers can extract saved credentials.")
                    print(Fore.YELLOW + "    - Consider disabling 'Keep Password' to improve security.")
                    
            elif service_name in safe:
                print(Fore.GREEN + f"[+] OK: {display_name} is enabled. Good!")
                print(Fore.GREEN + "    - Are you using strong passwords and SSH keys for authentication?")

    if not risks_found:
        print(Fore.GREEN + "[+] No high-risk RMI services enabled.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Check for default usernames that could be security risks
def check_default_users(connection):
    # Separator outlet
    separator("Checking Default Usernames")
    command = "/user print detail"
    output = connection.send_command(command)

    default_users = {"admin", "engineer", "user", "test", "root", "mikrotik", "routeros"}
    risks_found = False

    for line in output.split("\n\n"):
        match = re.search(r"name=\"?(\w+)\"?", line)
        if match:
            username = match.group(1).lower()
            if username in default_users:
                print(Fore.YELLOW + f"[!] CAUTION: Default username '{username}' detected! Change it to a unique one.")
                risks_found = True
    if not risks_found:
        print(Fore.GREEN + "[+] No default usernames found.")

# Verify whether critical services have restricted network access
def checking_access_to_RMI(connection):
    # Separator outlet
    separator("Checking network access to RMI")
    command = "/ip service print detail"
    output = connection.send_command(command)

    risks_found = False

    for line in output.split("\n\n"):
        service_match = re.search(r'name="([^"]+)"', line)
        address_match = re.search(r'address=([\d./,]+)', line)

        if service_match:
            service_name = service_match.group(1)

            if address_match:
                address_list = address_match.group(1).split(",")
                if not address_list or address_list == [""] or "0.0.0.0/0" in address_list:
                    print(Fore.YELLOW + f"[!] CAUTION: {service_name.upper()} is exposed to the entire network! Restrict access to trusted IP ranges.")
                    risks_found = True
                else:
                    print(Fore.GREEN + f"[+] OK! {service_name.upper()} is restricted to: {', '.join(address_list)}")
            else:
                print(Fore.RED + f"[!] CAUTION: {service_name.upper()} has no IP restriction set! Please restrict access.")
                risks_found = True

    if not risks_found:
        print(Fore.GREEN + "[+] All services have proper IP restrictions.")

# Analyze Wi-Fi security settings, including WPS and PMKID vulnerabilities
# I think this is the most unstable feature of the whole Sara, need more feedback from users to get it perfect
def check_wifi_security(connection):
    # Separator outlet
    separator("Checking WLAN Security")
    risks_found = False
    try:
        # Retrieve RouterOS version to determine supported commands
        command = "/system resource print"
        output = connection.send_command(command)
        version_match = re.search(r"version:\s*([\d.]+)", output)
        routeros_version = Version(version_match.group(1)) if version_match else Version("0.0.0")

        # Wi-Fi (ROS v6/v7)
        commands = ["/interface wifi print detail", "/interface wireless print detail"]
        found_valid_output = False

        for command in commands:
            output = connection.send_command(command)
            if "bad command name" not in output.lower() and output.strip():
                found_valid_output = True
                interfaces = output.split("\n\n")
                for interface in interfaces:
                    name_match = re.search(r'name="([^"]+)"', interface)
                    default_name_match = re.search(r'default-name="([^"]+)"', interface)
                    pmkid_match = re.search(r'disable-pmkid=(\S+)', interface)
                    wps_match = re.search(r'wps=(\S+)', interface)

                    name = name_match.group(1) if name_match else (default_name_match.group(1) if default_name_match else "Unknown")
                    pmkid = pmkid_match.group(1) if pmkid_match else "unknown"
                    wps = wps_match.group(1) if wps_match else None  # Fix: If WPS is not found, set None

                    if pmkid == "no":
                        print(Fore.RED + f"[!] ALERT: Wi-Fi '{name}' has insecure settings!")
                        print(Fore.RED + "    - PMKID attack is possible (disable-pmkid=no)")
                        risks_found = True

                    # Fix: Do not report WPS if it's completely missing in the output
                    if wps is not None and wps != "disable":
                        print(Fore.RED + f"[!] ALERT: Wi-Fi '{name}' has WPS enabled ({wps}), Risk of PIN bruteforcing and Pixie Dust attacks.")
                        risks_found = True

        if not found_valid_output:
            print(Fore.RED + "[-] ERROR: Unable to retrieve Wi-Fi interface settings. Unsupported RouterOS version or missing interface.")

        # Security profiles (ROS v6)
        security_profiles_output = connection.send_command("/interface wireless security-profiles print detail")
        if security_profiles_output.strip():
            profiles = security_profiles_output.split("\n\n")
            for profile in profiles:
                profile_name_match = re.search(r'name="([^"]+)"', profile)
                pmkid_match = re.search(r'disable-pmkid=(\S+)', profile)

                profile_name = profile_name_match.group(1) if profile_name_match else "Unknown"
                pmkid = pmkid_match.group(1) if pmkid_match else "unknown"

                if pmkid == "no":
                    print(Fore.RED + f"[!] ALERT: Security Profile '{profile_name}' allows PMKID attack! (disable-pmkid=no)")
                    risks_found = True

        # /interface wifi security print (ROS v7.10+ only)
        if routeros_version >= Version("7.10"):
            security_output = connection.send_command("/interface wifi security print")
            if security_output.strip():
                securities = security_output.split("\n\n")
                for security in securities:
                    sec_name_match = re.search(r'name="([^"]+)"', security)
                    pmkid_match = re.search(r'disable-pmkid=(\S+)', security)
                    wps_match = re.search(r'wps=(\S+)', security)

                    if sec_name_match and (pmkid_match or wps_match):
                        sec_name = sec_name_match.group(1)
                        pmkid = pmkid_match.group(1) if pmkid_match else "unknown"
                        wps = wps_match.group(1) if wps_match else None  # Fix: Avoid "WPS is enabled (unknown)"

                        if pmkid == "no":
                            print(Fore.RED + f"[!] ALERT: Wi-Fi security profile '{sec_name}' has insecure settings!")
                            print(Fore.RED + "    - PMKID attack is possible (disable-pmkid=no)")
                            risks_found = True

                        if wps is not None and wps != "disable":
                            print(Fore.RED + f"[!] ALERT: Wi-Fi security profile '{sec_name}' has WPS enabled ({wps}), Risk of PIN bruteforcing and Pixie Dust attacks.")
                            risks_found = True
            else:
                print(Fore.RED + "[-] ERROR: Unable to retrieve Wi-Fi security settings.")
        else:
            print(Fore.CYAN + "[*] Skipping `/interface wifi security print` (not supported in this version)")

    except Exception as e:
        print(Fore.RED + f"[-] ERROR: Failed to check Wi-Fi settings: {e}")

    if not risks_found:
        print(Fore.GREEN + "[+] All Wi-Fi interfaces and security profiles have secure settings.")
        print(Fore.YELLOW + "[*] If you use WPA-PSK or WPA2-PSK, take care of password strength. So that the handshake cannot be easily brute-forced.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Check if UPnP is enabled
def check_upnp_status(connection):
    # Separator outlet
    separator("Checking UPnP Status")
    command = "/ip upnp print"
    output = connection.send_command(command)

    if "enabled: yes" in output:
        print(Fore.RED + "[!] ALERT: UPnP is ENABLED! This is a very insecure protocol that automatically pushes internal hosts to the Internet. This protocol is used for automatic port forwarding and may also indicate a potential router compromise. Did you enable UPnP yourself?")
    else:
        print(Fore.GREEN + "[+] UPnP is disabled. No risk detected.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Check if the router is acting as a DNS server
def check_dns_status(connection):
    # Separator outlet
    separator("Checking DNS Settings")
    command = "/ip dns print"
    output = connection.send_command(command)

    if "allow-remote-requests: yes" in output:
        print(Fore.YELLOW + "[!] CAUTION: Router is acting as a DNS server! This is just a warning. The DNS port on your RouterOS should not be on the external interface.")
    else:
        print(Fore.GREEN + "[+] DNS remote requests are disabled. No risk detected.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Check DDNS Settings
def check_ddns_status(connection):
    # Separator outlet
    separator("Checking DDNS Settings")
    command = "/ip cloud print"
    output = connection.send_command(command)

    if "ddns-enabled: yes" in output:
        print(Fore.YELLOW + "[!] CAUTION: Dynamic DNS is enabled! Are you sure you need it?")
    else:
        print(Fore.GREEN + "[+] DDNS is disabled. No risk detected.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Detect active PoE interfaces that might pose a risk to connected devices
def check_poe_status(connection):
    # Separator outlet
    separator("Checking PoE Status")
    command = "/interface ethernet print detail"
    output = connection.send_command(command)

    risks_found = False
    interfaces = output.split("\n\n")  

    for interface in interfaces:
        name_match = re.search(r'name="([^"]+)"', interface)
        poe_match = re.search(r'poe-out=(\S+)', interface)
        name = name_match.group(1) if name_match else "Unknown"
        poe = poe_match.group(1) if poe_match else "none"

        if poe in ["auto-on", "forced-on"]:
            print(Fore.YELLOW + f"[!] CAUTION: PoE is enabled on {name}. Ensure that connected devices support PoE to prevent damage.")
            risks_found = True

    if not risks_found:
        print(Fore.GREEN + "[+] No PoE-enabled interfaces detected.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Checking RouterBOOT
def check_routerboot_protection(connection):
    # Separator outlet
    separator("Checking RouterBOOT Protection")
    command = "/system routerboard settings print"
    output = connection.send_command(command)

    if "protected-routerboot: disabled" in output:
        print(Fore.YELLOW + "[!] CAUTION: RouterBOOT protection is disabled! This can allow unauthorized firmware changes and password resets via Netinstall.")
    else:
        print(Fore.GREEN + "[+] RouterBOOT protection is enabled. No risk detected.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

def check_socks_status(connection):
    separator("Checking SOCKS Proxy Status")
    command = "/ip socks print"
    output = connection.send_command(command)

    if "enabled: yes" in output:
        print(Fore.RED + "[!] ALERT: SOCKS proxy is enabled! This may indicate a possible compromise of the device, the entry point to the internal network.")
    else:
        print(Fore.GREEN + "[+] SOCKS proxy is disabled. No risk detected.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Verify if RouterBOOT protection is enabled to prevent unauthorized firmware modifications
def check_bandwidth_server_status(connection):
    # Separator outlet
    separator("Checking Bandwidth Server Status")
    command = "/tool bandwidth-server print"
    output = connection.send_command(command)

    if "enabled: yes" in output:
        print(Fore.YELLOW + "[!] CAUTION: Bandwidth server is enabled! Possible unwanted traffic, possible CPU load.")
    else:
        print(Fore.GREEN + "[+] Bandwidth server is disabled. No risk detected.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Analyze discovery protocols (CDP, LLDP, MNDP) that might expose network information
def check_neighbor_discovery(connection):
    # Separator outlet
    separator("Checking Neighbor Discovery Protocols")
    command = "/ip neighbor discovery-settings print"
    output = connection.send_command(command)

    if "discover-interface-list: all" in output:
        print(Fore.YELLOW + "[!] CAUTION: RouterOS sends Discovery protocol packets to all interfaces. This can be used by an attacker to gather data about RouterOS.")

    protocol_match = re.search(r'protocol: ([\w,]+)', output)
    if protocol_match:
        protocols = protocol_match.group(1)
        print(Fore.YELLOW +  f"[!] Neighbor Discovery Protocols enabled: {protocols}")
    if "discover-interface-list: all" not in output and not protocol_match:
        print(Fore.GREEN + "[+] No security risks found in Neighbor Discovery Protocol settings.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Ensure a minimum password length policy is enforced
def check_password_length_policy(connection):
    # Separator outlet
    separator("Checking Password Policy")
    command = "/user settings print"
    output = connection.send_command(command)

    if "minimum-password-length: 0" in output:
        print(Fore.YELLOW + "[!] CAUTION: No minimum password length is enforced! The length of the created passwords must be taken into account.")
    if "minimum-password-length: 0" not in output:
        print(Fore.GREEN + "[+] Password policy is enforced. No risk detected.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Analyze SSH security settings, including strong encryption and port forwarding risks
def check_ssh_security(connection):
    # Separator outlet
    separator("Checking SSH Security")
    command = "/ip ssh print"
    output = connection.send_command(command)

    if "forwarding-enabled: both" in output:
        print(Fore.YELLOW + "[!] CAUTION: SSH Dynamic Port Forwarding is enabled! This could indicate a RouterOS compromise, and SSH DPF could also be used by an attacker as a pivoting technique.")
    if "strong-crypto: no" in output:
        print(Fore.YELLOW + "[!] CAUTION: strong-crypto is disabled! It is recommended to enable it to enhance security. This will:")
        print(Fore.YELLOW + "    - Use stronger encryption, HMAC algorithms, and larger DH primes;")
        print(Fore.YELLOW + "    - Prefer 256-bit encryption, disable null encryption, prefer SHA-256;")
        print(Fore.YELLOW + "    - Disable MD5, use 2048-bit prime for Diffie-Hellman exchange;")
    if "forwarding-enabled: both" not in output and "strong-crypto: no" not in output:
        print(Fore.GREEN + "[+] SSH security settings are properly configured.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Check if connection tracking is enabled, which may impact performance
def check_connection_tracking(connection):
    # Separator outlet
    separator("Checking Connection Tracking")
    command = "/ip firewall connection tracking print"
    output = connection.send_command(command)
    if "enabled: auto" in output or "enabled: on" in output:
        print(Fore.YELLOW + "[!] CAUTION: Connection Tracking is enabled! This means RouterOS is tracks connection statuses.")
        print(Fore.YELLOW + "    - If this device is a transit router and does NOT use NAT, consider disabling connection tracking to reduce CPU load.")
    
    if "enabled: auto" not in output and "enabled: on" not in output:
        print(Fore.GREEN + "[+] Connection Tracking is properly configured.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Verify if RoMON is enabled, which might expose Layer 2 management access
def check_romon_status(connection):
    # Separator outlet
    separator("Checking RoMON Status")
    command = "/tool romon print"
    output = connection.send_command(command)

    if "enabled: yes" in output:
        print(Fore.YELLOW + "[!] CAUTION: RoMON is enabled! This allows Layer 2 management access, which may expose the router to unauthorized control.")
        print(Fore.YELLOW + "    - If RoMON is not required, disable it to reduce attack surface.")
    if "enabled: yes" not in output:
        print(Fore.GREEN + "[+] RoMON is disabled. No risk detected.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Analyze MAC-based Winbox access settings
def check_mac_winbox_security(connection):
    separator("Checking Winbox MAC Server Settings")

    # MAC-Winbox Server
    try:
        command = "/tool mac-server mac-winbox print"
        output = connection.send_command(command)

        if "allowed-interface-list" in output:
            if "allowed-interface-list: all" in output:
                print(Fore.YELLOW + "[!] CAUTION: MAC Winbox access is enabled on all interfaces.")
            else:
                print(Fore.GREEN + "[+] MAC Winbox is properly restricted.")
        else:
            # Fallback for older versions: look for "INTERFACE" column and value "all"
            if re.search(r"\bINTERFACE\s*\n.*\ball\b", output, re.DOTALL | re.IGNORECASE):
                print(Fore.YELLOW + "[!] CAUTION: MAC Winbox access is enabled on all interfaces")
            else:
                print(Fore.GREEN + "[+] MAC Winbox is properly restricted (legacy format).")
    except Exception as e:
        print(Fore.RED + f"[-] ERROR while checking MAC Winbox: {e}")

    # MAC-Server
    try:
        command = "/tool mac-server print"
        output = connection.send_command(command)

        if "allowed-interface-list" in output:
            if "allowed-interface-list: all" in output:
                print(Fore.YELLOW + "[!] CAUTION: MAC Telnet access is enabled on all interfaces.")
            else:
                print(Fore.GREEN + "[+] MAC Telnet is properly restricted.")
        else:
            if re.search(r"\bINTERFACE\s*\n.*\ball\b", output, re.DOTALL | re.IGNORECASE):
                print(Fore.YELLOW + "[!] CAUTION: MAC Telnet access is enabled on all interfaces")
            else:
                print(Fore.GREEN + "[+] MAC Telnet is properly restricted (legacy format).")
    except Exception as e:
        print(Fore.RED + f"[-] ERROR while checking MAC Telnet: {e}")

    # MAC Ping
    try:
        command = "/tool mac-server ping print"
        output = connection.send_command(command)
        if "enabled: yes" in output:
            print(Fore.YELLOW + "[!] CAUTION: MAC Ping is enabled. Possible unwanted traffic.")
        else:
            print(Fore.GREEN + "[+] MAC Ping is properly restricted.")
    except Exception as e:
        print(Fore.RED + f"[-] ERROR while checking MAC Ping: {e}")

# Check for weak SNMP community strings that could be exploited
def check_snmp(connection):
    # Separator outlet
    separator("Checking SNMP Community Strings")
    command = "/snmp community print"
    output = connection.send_command(command)

    bad_names = ["public", "private", "admin", "mikrotik", "mikrotik_admin", "root", "routeros", "zabbix"]
    risks_found = False

    for line in output.splitlines():
        match = re.search(r'^\s*\d+\s+[*X]?\s*([\w-]+)', line)
        if match:
            community_name = match.group(1).lower()
            if community_name in bad_names:
                print(Fore.YELLOW + f"[!] CAUTION: Weak SNMP community string detected: '{community_name}'. Change it to a secure, unique value.")
                risks_found = True

    if not risks_found:
        print(Fore.GREEN + "[+] SNMP community strings checked. No weak values detected.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Detect and analyze firewall NAT rules that could expose internal services
def check_dst_nat_rules(connection):
    # Separator outlet
    separator("Checking Firewall NAT Rules")
    command = "/ip firewall nat print"
    output = connection.send_command(command)
    dst_nat_rules = []
    for line in output.splitlines():
        if "action=dst-nat" in line or "action=netmap" in line:
            dst_nat_rules.append(line.strip())
    if dst_nat_rules:
        print(Fore.YELLOW + "[!] CAUTION: Destination NAT (dst-nat/netmap) rules detected! Exposing devices to the internet can be dangerous.")
        print(Fore.YELLOW + "[*] Similar rules can also be created by the attacker. Did you really create these rules yourself?")
        print(Fore.YELLOW + "    - Review the following NAT rules:")
        for rule in dst_nat_rules:
            print(Fore.YELLOW + f"        {rule}")
    if not dst_nat_rules:
        print(Fore.GREEN + "[+] No Destination NAT (dst-nat/netmap) rules detected. No risks found.")
        print("[" + Fore.GREEN + "+" + Fore.WHITE + "] No issues found.")

# Identify potentially malicious scheduled tasks
def detect_malicious_schedulers(connection):
    # Separator outlet
    separator("Checking for Malicious Schedulers")
    command = "/system scheduler print detail"
    output = connection.send_command(command)

    risks_found = False
    fetch_files = set()

    for task in output.split("\n\n"):
        name_match = re.search(r'name="?([^"]+)"?', task)
        event_match = re.search(r'on-event="?([^"\n]+)"?', task)
        policy_match = re.search(r'policy=([\w,]+)', task)
        interval_match = re.search(r'interval=(\d+)([smhd])', task)

        name = name_match.group(1) if name_match else "Unknown"
        event = event_match.group(1).strip() if event_match else ""
        policy = policy_match.group(1).split(",") if policy_match else []
        interval_value, interval_unit = (int(interval_match.group(1)), interval_match.group(2)) if interval_match else (None, None)

        # DEBUG
        print(Fore.CYAN + f"[*] Checking: '{name}' → {event}")

        # Fetch detection
        fetch_match = re.search(r'dst-path=([\S]+)', event)
        if "fetch" in event and fetch_match:
            fetched_file = fetch_match.group(1).strip(";")
            fetch_files.add(fetched_file)
            print(Fore.YELLOW + f"[!] Noted fetched file: {fetched_file}")

        # Import detection (checks if imported file was fetched earlier)
        import_match = re.search(r'import\s+([\S]+)', event)
        if "import" in event and import_match:
            imported_file = import_match.group(1).strip(";")
            if imported_file in fetch_files:
                print(Fore.RED + f"[!] ALERT: '{name}' is a BACKDOOR!")
                print(Fore.RED + "    - This scheduler imports a previously fetched script.")
                print(Fore.RED + "    - Attacker can inject any command remotely via this script.")
                print(Fore.RED + f"    - Interval: {interval_value}{interval_unit}, ensuring persistence.")
                risks_found = True

        # High privileges checking
        dangerous_policies = {"password", "sensitive", "sniff", "ftp"}
        if any(p in dangerous_policies for p in policy):
            print(Fore.RED + f"[!] ALERT: '{name}' has HIGH PRIVILEGES!")
            print(Fore.RED + f"    - It has dangerous permissions: {', '.join(policy)}")
            risks_found = True

        # Reboot detection (Anti-forensics & persistence check)
        if "reboot" in event:
            if interval_value and interval_unit in ["s", "m", "h"] and interval_value < 12:
                print(Fore.RED + f"[!] ALERT: '{name}' reboots router TOO FREQUENTLY ({interval_value}{interval_unit})!")
                print(Fore.RED + "    - This may be an attempt to prevent log analysis (anti-forensics).")
                risks_found = True
            else:
                print(Fore.YELLOW + f"[!] CAUTION: '{name}' schedules a reboot.")
                print(Fore.YELLOW + "    - Ensure this is intentional and not used to hide attacks.")
            continue

        # Frequent execution detection
        if interval_value and interval_unit in ["s", "m", "h"] and interval_value < 25:
            print(Fore.RED + f"[!] ALERT: '{name}' executes TOO FREQUENTLY ({interval_value}{interval_unit})!")
            print(Fore.RED + "    - This indicates botnet-like persistence.")
            risks_found = True

    if not risks_found:
        print(Fore.GREEN + "[+] No malicious schedulers detected.")

# Checking DNS Static Entries
def check_static_dns_entries(connection):
    # Separator outlet
    separator("Checking Static DNS Entries")
    command = "/ip dns static print detail"
    output = connection.send_command(command)

    dns_entries = []
    entry_blocks = output.split("\n\n")

    for entry in entry_blocks:
        name_match = re.search(r'name="([^"]+)"', entry)
        address_match = re.search(r'address=([\d.]+)', entry)

        if name_match and address_match:
            name = name_match.group(1)
            address = address_match.group(1)
            dns_entries.append((name, address))

    if dns_entries:
        print(Fore.YELLOW + "[!] WARNING: The following static DNS entries exist:")
        for name, address in dns_entries:
            print(Fore.CYAN + f"    - {name} → {address}")

        print(Fore.YELLOW + "[*] Were you the one who created those static DNS records? Make sure.")
        print(Fore.YELLOW + "[*] Attackers during RouterOS post-exploitation like to tamper with DNS record settings, for example, for phishing purposes.")
    else:
        print(Fore.GREEN + "[+] No static DNS entries found.")


# Require user confirmation before proceeding, emphasizing legal responsibility
def confirm_legal_usage():
    print("    " + "WARNING: This tool is for security auditing of YOUR OWN RouterOS devices.")
    print("    " + "Unauthorized use may be illegal. Proceed responsibly.\n")
    response = input("    " + "Do you wish to proceed? [yes/no]: ").strip()
    
    if response.lower() != "yes":
        print("\nOperation aborted. Exiting...")
        sys.exit(0)

# Require user confirmation before proceeding, emphasizing legal responsibility
def confirm_legal_usage():
    print("    " + "WARNING: This tool is for security auditing of YOUR OWN RouterOS devices.")
    print("    " + "Unauthorized use may be illegal. Proceed responsibly.\n")

def prompt_legal_usage():
    response = input("    " + "Do you wish to proceed? [yes/no]: ").strip()
    
    if response.lower() != "yes":
        print("\nOperation aborted. Exiting...")
        sys.exit(0)

# Main func
def main():
    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", help="The address of your MikroTik router")
    parser.add_argument("--username", help="SSH username (RO account can be used)")
    parser.add_argument("--password", help="SSH password")
    parser.add_argument("--ssh-key", help="SSH key")
    parser.add_argument("--passphrase", help="SSH key passphrase")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--cve", action="store_true", help="Check RouterOS version against known CVEs")
    parser.add_argument("--skip-confirmation", action='store_true', help="Skips legal usage confirmation prompt")

    args = parser.parse_args()

    if len(sys.argv) == 2 and sys.argv[1] in ["-h", "--help"]:
        parser.print_help()
        sys.exit(0)

    if not args.ip or not args.username or (not args.password and not args.ssh_key):
        print(Fore.YELLOW + "[!] ERROR: Missing required arguments")
        print(Fore.YELLOW + "[!] Use 'sara --help' for more information")
        sys.exit(1)

    if args.password and args.ssh_key:
        print(Fore.YELLOW + "[!] ERROR: Can't use both password & ssh_key authentication")
        sys.exit(1)

    if args.passphrase and not args.ssh_key:
        print(Fore.YELLOW + "[!] ERROR: Passphrase requires --ssh-key")
        sys.exit(1)

# Legal warning (interactive only if not skipped)
    if not args.skip_confirmation:
        # disclaimer text
        confirm_legal_usage()
        # yes or no
        prompt_legal_usage()
    else:
        confirm_legal_usage()

    # Start timer
    start_time = time.time()

    # Connect to RouterOS
    connection = connect_to_router(
        args.ip,
        args.username,
        args.password,
        args.port,
        args.ssh_key,
        args.passphrase
    )

    # Run only CVE check if --cve is used
    if args.cve:
        run_cve_audit(connection)
        connection.disconnect()
        return

    # Run full audit
    check_routeros_version(connection)
    check_smb(connection)
    check_rmi_services(connection)
    check_default_users(connection)
    checking_access_to_RMI(connection)
    check_wifi_security(connection)
    check_upnp_status(connection)
    check_dns_status(connection)
    check_ddns_status(connection)
    check_poe_status(connection)
    check_routerboot_protection(connection)
    check_socks_status(connection)
    check_bandwidth_server_status(connection)
    check_neighbor_discovery(connection)
    check_password_length_policy(connection)
    check_ssh_security(connection)
    check_connection_tracking(connection)
    check_romon_status(connection)
    check_mac_winbox_security(connection)
    check_snmp(connection)
    check_dst_nat_rules(connection)
    detect_malicious_schedulers(connection)
    check_static_dns_entries(connection)

    print()

    connection.disconnect()
    print(Fore.WHITE + f"[*] Disconnected from RouterOS ({args.ip}:{args.port})")

    end_time = time.time()
    total_time = round(end_time - start_time, 2)
    print(Fore.WHITE + f"[*] All checks have been completed. Security inspection completed in {total_time} seconds\n")

if __name__ == "__main__":
    main()