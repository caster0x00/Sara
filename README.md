# Sara: RouterOS Security Inspector

RouterOS configuration analyzer to find security misconfigurations and vulnerabilities.

![](/banner/banner.png)

```
RouterOS Security Inspector. Designed for security engineers

Author: Mahama Bazarov, <mahamabazarov@mailbox.org>
Alias: Caster
Version: 1.2
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

## How does it work?

Sara has a special module called `cve_analyzer.py`, which creates `routeros_cves.json` based on the NVD NIST database containing information about vulnerabilities, including those in MikroTik RouterOS.
Vulnerabilities for the RouterOS version are searched for using the `--cve` argument. The results will show the total number of vulnerabilities, their categorization, as well as the CVE ID and a brief description.

```bash
caster@kali:~$ sara --ip 192.168.88.1 --username admin --password admin --cve
```

## Specifics of checking

- Sara does not verify real-world exploitation of vulnerabilities. It only cross-references the RouterOS version against publicly available CVE databases;
- If the device is running an older version of RouterOS, but vulnerable services have been manually disabled, some warnings may be false positives;
- It is recommended to manually validate your version of RouterOS after the audit to ensure there are no false positives.

## Example

```bash
[+] Detected RouterOS Version: 7.1.1
[!] routeros_cves.json not found.
[*] Fetching CVEs from NVD...
[+] Saved 74 CVEs to routeros_cves.json
[*] Total matching CVEs: 4
[*] CRITICAL: 1
[*] HIGH: 1
[*] MEDIUM: 2
[*] Vulnerability details:

→ CVE-2022-45313 [HIGH]
    Mikrotik RouterOs before stable v7.5 was discovered to contain an out-of-bounds read in the hotspot process. This vulnerability allows attackers to execute arbitrary code via a crafted nova message.
    CVSS Score: 8.8

→ CVE-2022-45315 [CRITICAL]
    Mikrotik RouterOs before stable v7.6 was discovered to contain an out-of-bounds read in the snmp process. This vulnerability allows attackers to execute arbitrary code via a crafted packet.
    CVSS Score: 9.8

→ CVE-2023-41570 [MEDIUM]
    MikroTik RouterOS v7.1 to 7.11 was discovered to contain incorrect access control mechanisms in place for the Rest API.
    CVSS Score: 5.3

→ CVE-2024-54772 [MEDIUM]
    An issue was discovered in the Winbox service of MikroTik RouterOS long-term release v6.43.13 through v6.49.13 and stable v6.43 through v7.17.2. A patch is available in the stable release v6.49.18. A discrepancy in response size between connection attempts made with a valid username and those with an invalid username allows attackers to enumerate for valid accounts.
    CVSS Score: 5.4
```

> The quality of entries in the NVD leaves much to be desired; in many cases, fields such as `versionEndExcluding` or `versionStartExcluding` have a value of “null.” Therefore, it is also important to validate your RouterOS version to ensure that a particular vulnerability exists.

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
~$ git clone https://github.com/caster0x00/Sara
~$ cd Sara
~/Sara$ sudo python3 setup.py install
~$ sara -h
```

## Trigger Arguments (CLI Options)

Sara supports the following command line options:

```bash
usage: sara.py [-h] [--ip IP] [--username USERNAME] [--password PASSWORD] [--ssh-key SSH_KEY] [--passphrase PASSPHRASE] [--port PORT] [--cve] [--skip-confirmation]

options:
  -h, --help            show this help message and exit
  --ip IP               The address of your MikroTik router
  --username USERNAME   SSH username (RO account can be used)
  --password PASSWORD   SSH password
  --ssh-key SSH_KEY     SSH key
  --passphrase PASSPHRASE
                        SSH key passphrase
  --port PORT           SSH port (default: 22)
  --cve                 Check RouterOS version against known CVEs
  --skip-confirmation   Skips legal usage confirmation prompt
```

1. `--ip` - this argument specifies the IP address of the MikroTik device to which Sara is connecting;

2. `--username` - the SSH username that will be used to connect. Sara supports only authorized access;

   > You can use read-only (RO) accounts. Sara does not make configuration changes, so you do not need `write` or `full` level access.

3. `--password` - password for SSH authentication;

4. `--ssh-key` - specifies the ssh key that should be used to access the RouterOS's shell

    > This is muaually exclusive with `--password`.

5. `--passphrase` - specifies the passphrase used to access the ssh-key

    > This only works when using the `--ssh-key` argument.

6. `--port` - allows you to specify a non-standard SSH port for connection. The default is **22**, but if you have changed the SSH port number, it must be specified manually.

7. `--cve` - launches a vulnerability search using the NIST NVD database.

8. `--skip-confirmation` - allows you to skip the audit start confirmation check. Use this if you really have permission to perform a security audit.

# Copyright

Copyright (c) 2025 Mahama Bazarov. This project is licensed under the Apache 2.0 License

# Outro

MikroTik devices are widely used around the world. Sara is designed to help engineers improve security - use it wisely.

E-mail for contact: mahamabazarov@mailbox.org
