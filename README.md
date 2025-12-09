# Sara: MikroTik RouterOS Security Inspector

RouterOS security analyzer for detecting misconfigurations, weak settings, and known vulnerabilities (CVE).

![](cover/saracover.png)

```bash
       _____                 
      / ___/____ __________ _
      \__ \/ __ `/ ___/ __ `/
     ___/ / /_/ / /  / /_/ / 
    /____/\__,_/_/   \__,_/                              

    Sara: MikroTik RouterOS Security Inspector
    Developer: Mahama Bazarov (Caster)
    Contact: mahamabazarov@mailbox.org
    Version: 1.3.0
    Documentation & Usage: https://github.com/caster0x00/Sara
```

# Disclaimer

**Sara** is developed for security professionals to audit their own devices. **Unauthorized use may be illegal.**

The author does not take any responsibility for the misuse of this tool, including, but not limited to:

- Use for unauthorized access, hacking, or any form of cyberattack;

- Misinterpretation of results leading to undesirable configuration changes;

- Legal repercussions arising from the misuse of **Sara** for purposes other than security auditing.

# Sara is not an attack tool

**Sara does not bypass authentication, exploit vulnerabilities, or alter RouterOS configurations.** It works in read-only mode and does not modify device configuration. A read-only RouterOS account is sufficient.

If you are unsure about the interpretation of the analysis results, consult an experienced network engineer before making any decisions!

# Legal Restrictions

Before use, ensure that your device auditing complies with your organization's local laws and policies.

- You are solely responsible for your use of Sara;
- Use it only on your devices or with the owner's permission;
- Do not use Sara on other people's networks without the owner's explicit consent - this may violate computer security laws!

# Features

**Sara** uses [netmiko](https://github.com/ktbyers/netmiko) to remotely connect via SSH to RouterOS devices. It executes RouterOS system commands to extract configuration data and analyze it for potential vulnerabilities and signs of compromise. The user connects to the hardware himself using Sara by entering his username and password. Sara executes only `print` commands and does not change RouterOS configuration in any way. You can even use a read-only (RO) account if you want to.
Sara does not use any exploits, payloads or bruteforce attacks. All RouterOS security analysis here is based on pure configuration analysis.

## Profiles

Sara uses audit profiles. Each profile covers its own audit scope.

- `system`: This profile covers RouterOS system checks. It checks the system version, account status, remote management services and their availability, IP restrictions, PoE and RouterBOOT status, SSH settings, and password policies. It also analyzes MAC Winbox/Telnet services, NAT rules, connection tracking mode, RoMON, and the scheduler, including for suspicious automatic tasks and possible persistence mechanisms.
- `protocols`: The profile focuses on network protocols and services that are commonly used as entry points for attacks. It checks SMB, UPnP, SOCKS proxies, DNS settings and static DNS records, DDNS cloud services, Neighbor Discovery settings, and SNMP. The profile's task is to identify enabled or improperly restricted network services that could increase the attack surface.
- `wifi`: This profile evaluates the security of the wireless part of RouterOS. It analyzes Wi-Fi interfaces, PMKID parameters, and WPS modes that could open up opportunities for offline attacks or unauthorized connections. The profile helps you quickly understand whether the current Wi-Fi network security configuration is weak.

# CVE Search

Sara performs a security analysis of RouterOS by checking the current firmware version and checking it against a database of known vulnerabilities (CVEs). This process identifies critical vulnerabilities that can be exploited by attackers to compromise the device.

## How does it work?

Sara uses a separate module called `cve_analyzer.py`. 
It downloads information from the NVD (National Vulnerability Database), filters it by RouterOS, and generates a local file called `routeros_cves.json`
Next, the RouterOS version is compared with the version ranges specified in CVE records, as well as with additional patterns extracted from vulnerability descriptions.

There are two ways to perform the CVE check:

1. Live Device (SSH)

Sara will determine the RouterOS version on the device and compare it with the CVE database.
```bash
~$ sara cve 192.168.88.1 admin
```

If necessary, you can specify the SSH key and port:
```bash
~$ sara cve 192.168.88.1 admin ~/.ssh/id_rsa 2222
```

> The password or key passphrase is requested interactively ([getpass](https://docs.python.org/3/library/getpass.html))

```bash
[+] CVE Audit (Live)
    [*] Target Device: 192.168.88.1
    [*] Transport: SSH (port 22)
[?] SSH password for admin@192.168.88.1: 
    [✓] SSH connection established: admin@192.168.88.1
[+] Search for CVEs for a specific version
[!] routeros_cves.json not found.
[*] Fetching CVEs from NVD...
[+] Saved 80 CVEs to routeros_cves.json

Target RouterOS Version: 7.20.5    Matched CVEs: 0
CRIT: 0 | HIGH: 0 | MED: 0 | LOW: 0 | UNK: 0

[*] No known CVEs found for this RouterOS version

[*] Disconnected from RouterOS (192.168.88.1)
```

2. Manual

If the device is unavailable, you can simply specify the desired version:
```bash
~$ sara cve version 7.13.1
```

Sara will perform a vulnerability scan for a specific version without connecting to the device.
```bash
[+] CVE Audit (Manual Version)
    [*] RouterOS Version: 7.13.1
[+] Search for CVEs for a specific version
[!] routeros_cves.json not found.
[*] Fetching CVEs from NVD...
[+] Saved 80 CVEs to routeros_cves.json

Target RouterOS Version: 7.13.1    Matched CVEs: 2
CRIT: 0 | HIGH: 1 | MED: 1 | LOW: 0 | UNK: 0

CVE ID            SEV    CVSS  PUBLISHED 
CVE-2025-6443     HIGH    7.2  2025-06-25
CVE-2024-54772    MED     5.4  2025-02-11
```

## Features of CVE verification

Sara does not determine the possibility of actual exploitation of vulnerabilities, but only analyzes the compliance of the RouterOS version with known CVEs;
A vulnerability is considered "relevant" if the device version falls within the range specified in the CVE, or if the vulnerability description contains a recognized version range;
The NVD database often contains incomplete data (`versionStartExcluding=null`, `versionEndExcluding=null`). That's why it's also a good idea to manually check the results against MikroTik's official changelog.

# How to Use

You have two ways to install Sara:

1. In Kali Linux:

```bash
caster@kali:~$ sudo apt update && sudo apt install sara
caster@kali:~$ sara -h
```

2. Manually using Git and Python:

```bash
~$ sudo apt install git python3-colorama python3-netmiko python3-packaging python3-requests
~$ git clone https://github.com/caster0x00/Sara
~$ cd Sara
~/Sara$ sudo python3 setup.py install
~$ sara -h
```

## Startup

The tool uses subcommands divided by purpose:

- `audit` - analyze the RouterOS configuration by profiles (system / protocols / wifi);
- `cve` - check RouterOS vulnerabilities based on CVE (live check or manually specified version)

```bash
~$ sara <command> [...]
```

## Authentication

Sara does not support passwords in command line arguments. Passwords/passphrases are requested securely via `getpass()`

## Audit

The RouterOS configuration audit is performed via SSH with selected profiles.
```bash
~$ sara audit <ip> <username> <profiles> [key] [port]
~$ sara audit 192.168.88.1 admin system
```

With key (SSH):
```bash
~$ sara audit 192.168.88.1 admin system,protocols ~/.ssh/id_rsa
```

With a non-standard port:
```bash
~$ sara audit 192.168.88.1 admin system,protocols ~/.ssh/id_rsa 2222
```

## Profiles

Profiles are a comma-separated list:

- `system` refers to system settings, management, users, RMI, SSH security, NAT, scheduler, etc.;
- `protocols` refers to services and network protocols (SMB, UPnP, DNS, SNMP, DDNS, Neighbor Discovery);
- `wifi` refers to security of Wi-Fi interfaces (PMKID, WPS).

You can use multiple profiles at once:
```bash
system,protocols,wifi
```

# Copyright

Copyright (c) 2026 Mahama Bazarov. This project is licensed under the Apache 2.0 License.
This project is not affiliated with or endorsed by SIA Mikrotīkls
All MikroTik trademarks and product names are the property of their respective owners.

# Outro

If you have any suggestions or find any bugs, feel free to create issues in the repository or contact me: [mahamabazarov@mailbox.org](mailto:mahamabazarov@mailbox.org)
