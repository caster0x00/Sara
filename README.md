# Sara: RouterOS Security Inspector

RouterOS configuration analyzer to find security misconfigurations and vulnerabilities.

![](/banner/banner.png)

```
RouterOS Security Inspector. For security engineers
Operates remotely using SSH, designed to evaluate RouterOS security

Author: Magama Bazarov, <magamabazarov@mailbox.org>
Alias: Caster
Version: 1.1.1
Codename: Judge
```

# Disclaimer

**Sara** is developed for security professionals to audit their own devices. **Unauthorized use may be illegal.**

The author does not take any responsibility for the misuse of this tool, including, but not limited to:

- Use for unauthorized access, hacking, or any form of cyberattack;

- Misinterpretation of results leading to undesirable configuration changes;

- Legal repercussions arising from the misuse of **Sara** for purposes other than security auditing.

# Sara is not an attack tool

**Sara does not bypass authentication, exploit vulnerabilities, or alter RouterOS configurations.** It works in **read-only mode**, requiring no administrative privileges.

If you are unsure about the interpretation of the analysis results, consult an experienced network engineer before making any decisions!

# Legal Restrictions

Before use, ensure that your device auditing complies with your organization's local laws and policies.

- You are solely responsible for your use of Sara;
- Use it only on your devices or with the owner's permission;
- Do not use Sara on other people's networks without the owner's explicit consent - this may violate computer security laws!

# Mechanism

**Sara** uses [netmiko](https://github.com/ktbyers/netmiko) to remotely connect via SSH to RouterOS devices. It executes RouterOS system commands to extract configuration data and analyze it for potential vulnerabilities and signs of compromise. The user connects to the hardware himself using Sara by entering his username and password. Sara executes exactly `print` based commands, thus not changing the configuration of your hardware in any way. So, by the way, you can even use an RO-only account if you want to.
Sara does not use any exploits, payloads or bruteforce attacks. All RouterOS security analysis here is based on pure configuration analysis.

## What exactly is Sara checking for?

1. **SMB protocol activity** – determines whether SMB is enabled, which may be vulnerable to CVE-2018-7445;

2. **Check the status of RMI interfaces** – identifies active management services (Telnet, FTP, Winbox, API, HTTP/HTTPS);

3. **Wi-Fi Security Check** – determines whether WPS and PMKID support are enabled, which can be used in WPA2-PSK attacks;

   > At the moment, this check has minor stability issues, as different versions of RouterOS have different variations of Wi-Fi configurations. Keep that in mind, but feel free to make an issue, we'll look into it;

4. **Check UPnP** – determines whether UPnP is enabled, which can automatically forward ports and threaten network security;

5. **Check DNS settings** – detects whether `allow-remote-requests`, which makes the router a DNS server, is enabled;

6. **Check DDNS** – determines whether dynamic DNS is enabled, which can reveal the real IP address of the device;

7. **PoE Test** – checks if PoE is enabled, which may cause damage to connected devices;

8. **Check RouterBOOT security** – determines if RouterBOOT bootloader protection is enabled;

9. **Check SOCKS Proxy** – identifies an active SOCKS Proxy that could be used by an attacker for pivoting, as well as indicating a potential compromise of the device.

10. **Bandwidth Server Test (BTest)** – determines whether a bandwidth server is enabled that can be used for a Flood attack by the attacker;

11. **Check discovery protocols** – determines whether CDP, LLDP, MNDP that can disclose network information are active;

12. **Check minimum password length** – determines whether the `minimum-password-length` parameter is set to prevent the use of weak passwords;

13. **SSH Check** – analyzes SSH settings, including the use of strong-crypto and Port Forwarding permission;

14. **Check Connection Tracking** – determines whether Connection Tracking is enabled, which can increase the load and open additional attack vectors;

15. **RoMON check** – detects RoMON activity, which allows you to manage devices at Layer 2;

16. **Check Winbox MAC Server** – analyzes access by MAC address via Winbox and Telnet, which can be a vulnerability on a local network;

17. **Check SNMP** – detects the use of weak SNMP community strings (`public`, `private`);

18. **Check NAT rules** – analyzes port forwarding (`dst-nat`, `netmap`) that may allow access to internal services from the outside;

19. **Check network access to RMI** – determines whether access to critical services (API, Winbox, SSH) is restricted to trusted IPs only;

20. **Check RouterOS version** – analyzes the current version of RouterOS and compares it to known vulnerable versions;

21. **RouterOS Vulnerability Check** – checks the RouterOS version against the CVE database and displays a list of known vulnerabilities;

22. **“Keep Password” in Winbox** – warns of potential use of the “Keep Password” feature

23. **Check default usernames** – defines the use of standard logins (`admin`, `engineer`, `test`, `mikrotik`);

24. **Checking the schedulers** – detects malicious tasks that can load remote scripts, perform hidden reboots, or run too often;

25. **Check static DNS records** – Analyzes static DNS records that can be used for phishing and MITM attacks.

## A breakdown of one technique

Sara analyzes MikroTik RouterOS configuration by sending commands via SSH and interpreting the results. Let's consider a basic example of checking an SMB service that may be vulnerable to CVE-2018-7445.

```python
# SMB Check
def check_smb(connection):
    separator("Checking SMB Service")
    command = "/ip smb print"
    output = connection.send_command(command)
    
    if "enabled: yes" in output:
        print(Fore.RED + Style.BRIGHT + "[*] CAUTION: SMB service is enabled! Are you sure you want it? Also, avoid CVE-2018-7445")
    else:
        print(Fore.GREEN + "[+] SMB is disabled. No risk detected.")
        print(Fore.GREEN + "[+] No issues found.")
```

1. Sending a command to the router: command = `/ip smb print` - queries the status of the SMB service;
2. `output = connection.send_command(command)` - executes the command via SSH and receives its output, writing it to the variable memory;
3. If the output contains the string `“enabled: yes”`, then SMB is enabled and the script displays a warning.

The same principle works for the other checks. Only read the configuration and then analyze it in detail.

# Vulnerability Search (CVE)

Sara performs a security analysis of RouterOS by checking the current firmware version and checking it against a database of known vulnerabilities (CVEs). This process identifies critical vulnerabilities that can be exploited by attackers to compromise the device.

## But how does it work?

1. Sara extracts the current RouterOS version from the device using the system command (`/system resource print`)

2. The check is performed using the built-in `cve_lookup.py` module, which stores a dictionary of known RouterOS vulnerabilities. This module is based on data obtained [from the MITRE CVE database](https://cve.mitre.org/data/downloads) and contains:

   - CVE ID;
   - Vulnerability Description;
   - Range of vulnerable RouterOS versions

   Sara analyzes the version of the device and determines if it falls into the list of vulnerable versions.

3. If the RouterOS version contains known vulnerabilities, Sara displays a warning indicating:

   - CVE ID;
   - Description of the vulnerability and potential risks.

## Specifics of checking

- Sara does not verify real-world exploitation of vulnerabilities. It only cross-references the RouterOS version against publicly available CVE databases;
- If the device is running an older version of RouterOS, but vulnerable services have been manually disabled, some warnings may be false positives;
- The CVE database is updated over time, so it is recommended to keep an eye out for current patches from MikroTik yourself.

# How to use

You have two ways to install Sara:

1. In Kali Linux:

```bash
caster@kali:~$ sudo apt update && sudo apt install sara
caster@kali:~$ sara -h
```

2. Manually using Git and Python:

```bash
~$ sudo apt install git python3-colorama python3-netmiko python3-packaging
~$ git clone https://github.com/casterbyte/Sara
~$ cd Sara
~/Sara$ sudo python3 setup.py install
~$ sara -h
```

## Trigger Arguments (CLI Options)

Sara supports the following command line options:

```bash
usage: sara.py [-h] [--ip IP] [--username USERNAME] [--password PASSWORD] [--ssh-key SSH_KEY] [--passphrase PASSPHRASE] [--skip-confirmation] [--port PORT]

options:
  -h, --help            show this help message and exit
  --ip IP               The address of your MikroTik router
  --username USERNAME   SSH username (RO account can be used)
  --password PASSWORD   SSH password
  --ssh-key SSH_KEY     SSH key
  --passphrase PASSPHRASE
                        SSH key passphrase
  --skip-confirmation   Skips the confirmation prompt (disclamer: ensure that your are allowed to use this tool)
  --port PORT           SSH port (default: 22)
```

1. `--ip` - this argument specifies the IP address of the MikroTik device to which Sara is connecting;

2. `--username` - the SSH username that will be used to connect. Sara supports only authorized access;

   > You can use read-only (RO) accounts. Sara does not make configuration changes, so you do not need `write` or `full` level access.

3. `--password` - password for SSH authentication;

4. `--ssh-key` - specifies the ssh key that should be used to access the RouterOS's shell

    > This is muaually exclusive with `--password`.

5. `--passphrase` - specifies the passphrase used to access the ssh-key

    > This only works when using the `--ssh-key` argument.

6. `--skip-confirmation` skips the confirmation prompt that asks if you are allowed to use this tool on the target system

    > Please do ensure the legality of what you're doing.

7. `--port` - allows you to specify a non-standard SSH port for connection. The default is **22**, but if you have changed the SSH port number, it must be specified 

# Sara's Launch

```bash
caster@kali:~$ python3 sara.py --ip 192.168.88.1 --username admin --password mypass          

    _____                 
   / ____|                
  | (___   __ _ _ __ __ _ 
   \___ \ / _` | '__/ _` |
   ____) | (_| | | | (_| |
  |_____/ \__,_|_|  \__,_|

    RouterOS Security Inspector. For security engineers
    Operates remotely using SSH, designed to evaluate RouterOS security

    Author: Magama Bazarov, <caster@exploit.org>
    Alias: Caster
    Version: 1.1
    Codename: Judge
    Documentation & Usage: https://github.com/casterbyte/Sara

    [!] DISCLAIMER: Use this tool only for auditing your own devices.
    [!] Unauthorized use on third-party systems is ILLEGAL.
    [!] The author is not responsible for misuse.

    WARNING: This tool is for security auditing of YOUR OWN RouterOS devices.
    Unauthorized use may be illegal. Proceed responsibly.

    Do you wish to proceed? [yes/no]: yes
[*] Connecting to RouterOS at 192.168.88.1:22
[*] Connection successful!
========================================
[*] Checking RouterOS Version
[+] Detected RouterOS Version: 7.15.3
[+] No known CVEs found for this version.
========================================
[*] Checking SMB Service
[+] SMB is disabled. No risk detected.
[+] No issues found.
========================================
[*] Checking RMI Services
[!] ALERT: TELNET is ENABLED! This is a high security risk.
    - Account passwords can be intercepted
[!] ALERT: FTP is ENABLED! This is a high security risk.
    - Are you sure you need FTP?
[!] ALERT: HTTP is ENABLED! This is a high security risk.
    - Account passwords can be intercepted
[+] OK: SSH is enabled. Good!
    - Are you using strong passwords and SSH keys for authentication?
[!] CAUTION: HTTP-SSL is enabled.
    - HTTPS detected. Ensure it uses a valid certificate and strong encryption.
[!] CAUTION: API is enabled.
    - RouterOS API is vulnerable to a bruteforce attack. If you need it, make sure you have access to it.
[!] CAUTION: WINBOX is enabled.
[!] CAUTION: If you're using 'Keep Password' in Winbox, your credentials may be stored in plaintext!
    - If your PC is compromised, attackers can extract saved credentials.
    - Consider disabling 'Keep Password' to improve security.
[!] CAUTION: API-SSL is enabled.
    - RouterOS API is vulnerable to a bruteforce attack. If you need it, make sure you have access to it.
========================================
[*] Checking Default Usernames
[!] CAUTION: Default username 'admin' detected! Change it to a unique one.
[!] CAUTION: Default username 'engineer' detected! Change it to a unique one.
========================================
[*] Checking network access to RMI
[!] CAUTION: TELNET has no IP restriction set! Please restrict access.
[!] CAUTION: FTP has no IP restriction set! Please restrict access.
[!] CAUTION: WWW has no IP restriction set! Please restrict access.
[+] OK! SSH is restricted to: 192.168.88.0/24
[!] CAUTION: WWW-SSL has no IP restriction set! Please restrict access.
[!] CAUTION: API has no IP restriction set! Please restrict access.
[+] OK! WINBOX is restricted to: 192.168.88.0/24
[!] CAUTION: API-SSL has no IP restriction set! Please restrict access.
========================================
[*] Checking Wi-Fi Security
[+] All Wi-Fi interfaces and security profiles have secure settings.
[*] If you use WPA-PSK or WPA2-PSK, take care of password strength. So that the handshake cannot be easily brute-forced.
[+] No issues found.
========================================
[*] Checking UPnP Status
[+] UPnP is disabled. No risk detected.
[+] No issues found.
========================================
[*] Checking DNS Settings
[!] CAUTION: Router is acting as a DNS server! This is just a warning. The DNS port on your RouterOS should not be on the external interface.
========================================
[*] Checking DDNS Settings
[+] DDNS is disabled. No risk detected.
[+] No issues found.
========================================
[*] Checking PoE Status
[!] CAUTION: PoE is enabled on ether1. Ensure that connected devices support PoE to prevent damage.
========================================
[*] Checking RouterBOOT Protection
[!] CAUTION: RouterBOOT protection is disabled! This can allow unauthorized firmware changes and password resets via Netinstall.
========================================
[*] Checking SOCKS Proxy Status
[+] SOCKS proxy is disabled. No risk detected.
[+] No issues found.
========================================
[*] Checking Bandwidth Server Status
[+] Bandwidth server is disabled. No risk detected.
[+] No issues found.
========================================
[*] Checking Neighbor Discovery Protocols
[+] No security risks found in Neighbor Discovery Protocol settings.
[+] No issues found.
========================================
[*] Checking Password Policy
[!] CAUTION: No minimum password length is enforced! The length of the created passwords must be taken into account.
========================================
[*] Checking SSH Security
[!] CAUTION: SSH Dynamic Port Forwarding is enabled! This could indicate a RouterOS compromise, and SSH DPF could also be used by an attacker as a pivoting technique.
[!] CAUTION: strong-crypto is disabled! It is recommended to enable it to enhance security. This will:
    - Use stronger encryption, HMAC algorithms, and larger DH primes;
    - Prefer 256-bit encryption, disable null encryption, prefer SHA-256;
    - Disable MD5, use 2048-bit prime for Diffie-Hellman exchange;
========================================
[*] Checking Connection Tracking
[+] Connection Tracking is properly configured.
[+] No issues found.
========================================
[*] Checking RoMON Status
[+] RoMON is disabled. No risk detected.
[+] No issues found.
========================================
[*] Checking Winbox MAC Server Settings
[+] MAC Winbox are properly restricted.
[+] MAC Telnet are properly restricted.
[+] MAC Ping are properly restricted.
========================================
[*] Checking SNMP Community Strings
[+] SNMP community strings checked. No weak values detected.
[+] No issues found.
========================================
[*] Checking Firewall NAT Rules
[+] No Destination NAT (dst-nat/netmap) rules detected. No risks found.
[+] No issues found.
========================================
[*] Checking for Malicious Schedulers
[*] Checking: 'Unknown' → 
[+] No malicious schedulers detected.
========================================
[*] Checking Static DNS Entries
[!] WARNING: The following static DNS entries exist:
    - dc01.myownsummer.org → 192.168.88.71
    - fake.example.com → 192.168.88.100
[*] Were you the one who created those static DNS records? Make sure.
[*] Attackers during RouterOS post-exploitation like to tamper with DNS record settings, for example, for phishing purposes.
========================================
[*] Checking Router Uptime
[*] Router Uptime: 64 days, 2 hours, 23 minutes

[*] Disconnected from RouterOS (192.168.88.1:22)
[*] All checks have been completed. Security inspection completed in 3.03 seconds
```

# Copyright

Copyright (c) 2025 Magama Bazarov. This project is licensed under the Apache 2.0 License

# Outro

MikroTik devices are widely used around the world. Sara is designed to help engineers improve security - use it wisely.

E-mail for contact: magamabazarov@mailbox.org
