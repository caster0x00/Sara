# Sara: RouterOS Security Inspector (A new version is on the way)

It is a autonomous RouterOS configuration analyzer for finding security issues on MikroTik hardware.

```
    _____                 
   / ____|                
  | (___   __ _ _ __ __ _ 
   \___ \ / _` | '__/ _` |
   ____) | (_| | | | (_| |
  |_____/ \__,_|_|  \__,_|  v1.0

    RouterOS Security Inspector. Designed for security professionals

    Author: Magama Bazarov, <caster@exploit.org>
```

# Mechanism

This tool is written in Python 3 and uses regular expressions to look for specific values in configurations to detect a problem. As of v1.0, the tool performs 20 security checks, including:

1. **SMB Service Detection**: Identifies if the SMB service is enabled, which may expose the device to vulnerabilities like CVE-2018-7445;

2. **RMI Services Analysis**: Examines active Remote Management Interface (RMI) services such as Telnet, FTP, SSH, and others. The tool warns about unsafe services and provides recommendations for securing them;

3. **UPnP Status Check**: Detects if Universal Plug and Play (UPnP) is enabled, which can open up the network to unauthorized access;
4. **WiFi Configuration Review**: Analyzes WiFi settings for vulnerabilities, including insecure authentication methods, enabled WPS, and PMKID exposure;
5. **DNS Configuration Review**: Checks DNS settings, looking for remote DNS requests being allowed and the absence of DNS over HTTPS (DoH);
6. **Dynamic DNS (DDNS) Status**: Identifies if DDNS is enabled, which might expose your network to unnecessary risks;
7. **Power over Ethernet (PoE) Settings Review**: Analyzes PoE configurations to ensure power management does not pose risks to connected devices;
8. **Protected RouterBOOT Check**: Ensures that Protected RouterBOOT is enabled, preventing unauthorized changes to the bootloader settings;
9. **SOCKS Proxy Detection**: Identifies if a SOCKS proxy is enabled, which could indicate a compromised device;
10. **Bandwidth Server Check**: Detects if the Bandwidth Server is enabled, which could lead to unwanted traffic on the network;
11. **OSPF Interface Analysis**: Examines OSPF interface settings for missing passive mode and authentication, both of which are crucial for securing OSPF communications;
12. **VRRP Interface Analysis**: Checks for VRRP interfaces that lack proper authentication, potentially exposing the network to Man-in-the-Middle (MITM) attacks;
13. **Discovery Protocols Configuration**: Reviews the settings for network discovery protocols, ensuring they are limited to trusted interfaces;
14. **User Password Policy Check**: Analyzes user password policies to ensure they meet security best practices;
15. **SSH Strong Crypto Detection**: Detects if SSH is configured with weak cryptography, providing advice on how to secure it;
16. **Connection Tracking Status**: Reviews the connection tracking settings, advising on when it might be beneficial to disable it;
17. **RoMON Status Check**: Detects if RoMON is enabled, highlighting the need for careful management to prevent unauthorized access to other RouterOS devices;
18. **MAC Server Settings Review**: Analyzes MAC Server and MAC Winbox settings, recommending restrictions to enhance security;
19. **SNMP Analysis**: Identifies the use of default or weak SNMP community strings, which could lead to information gathering attacks;
20. **Port Forwarding Rules Check**: Detects port forwarding rules (dst-nat), warning about potential exposure of internal services to the internet.

# Usage

To install Sara:

1. Kali Linux
```bash
caster@kali:~$ sudo apt update && sudo apt install sara
caster@kali:~$ sara -h
```
2. Via Python3
```bash
caster@kali:~$ sudo apt install python3-colorama git
caster@kali:~$ git clone https://github.com/casterbyte/Sara
caster@kali:~/Sara$ sudo python3 setup.py install
caster@kali:~$ sara                                            

    _____                 
   / ____|                
  | (___   __ _ _ __ __ _ 
   \___ \ / _` | '__/ _` |
   ____) | (_| | | | (_| |
  |_____/ \__,_|_|  \__,_|  v1.0

    RouterOS Security Inspector. Designed for security professionals

    Author: Magama Bazarov, <caster@exploit.org>

    It's recommended to provide a configuration file exported using the 'export verbose' command

usage: sara [-h] --config-file CONFIG_FILE
sara: error: the following arguments are required: --config-file
```

Sara uses just one argument, it is the name/path to the RouterOS configuration file. The tool supports `.rsc` files.

# Work Example

```bash
caster@kali:~$ sara --config-file routeros.rsc

    _____                 
   / ____|                
  | (___   __ _ _ __ __ _ 
   \___ \ / _` | '__/ _` |
   ____) | (_| | | | (_| |
  |_____/ \__,_|_|  \__,_|  v1.0

    RouterOS Security Inspector. Designed for security professionals

    Author: Magama Bazarov, <caster@exploit.org>

    It's recommended to provide a configuration file exported using the 'export verbose' command

[*] Analyzing the configuration file: forsara.rsc (34.53 KB)

[+] Device Information
    [*] RouterOS Version: X.XX.X
    [*] Model: XXXX-XXXXXXXXXX
    [*] Serial Number: XXXXXXXXXXX

[+] Checking RMI Services
    [!] Warning: The following RMI services are enabled and may be unsafe: telnet, ftp, www.
    [!] Caution: The following RMI services are enabled: ssh, www-ssl, winbox.
    [!] Note: The following RMI services are enabled and might be susceptible to brute force attacks: api, api-ssl.
    [*] Solution: Disable the above RMI services if they are not required for security.
    [*] Tip: Restrict access to enabled services to trusted subnets only.

[+] Checking UPnP
    [!] Warning: UPnP is enabled. This can expose your network to various security risks, including unauthorized access.
    [*] Solution: Disable UPnP unless absolutely necessary, and ensure your firewall is properly configured.

[+] Checking WiFi Settings
    [!] Warning: WPS is enabled on interface wifi1. WPS Pin code can be cracked, brute-forced.
    [!] Warning: PMKID is enabled on interface wifi1. PMKID is easy to bruteforce.
    [!] Warning: Interface wifi1 is using insecure authentication method 'wpa2-psk'. WPA/WPA2-PSK are long gone, use WPA2-E, WPA3.

[+] Checking DNS Settings
    [!] Warning: Router is configured to allow remote DNS requests. Close the DNS UDP/53 port from the Internet.
    [!] Note: DNS over HTTPS (DoH) is not configured. Consider configuring a DoH server for improved privacy.

[+] Checking PoE Settings
    [!] Warning: PoE is enabled on interface ether1 with setting 'auto-on'. This could supply power to connected devices and potentially damage them if not properly managed.

[+] Checking Protected RouterBOOT
    [!] Warning: Protected RouterBOOT is disabled. This may allow unauthorized changes to the bootloader settings.
    [*] Solution: Enable Protected RouterBOOT to prevent unauthorized access to the bootloader.

[+] Checking SOCKS Proxy
    [!] Warning: SOCKS Proxy is enabled. The presence of SOCKS may indicate that the device has been compromised.
    [*] Solution: Disable SOCKS Proxy if it is not required.

[+] Checking User Password Policies
    [!] Warning: Password policies are not properly configured. Both minimum password categories and minimum password length are set to 0.
    [*] Solution: Set a higher minimum password length and require at least one or more character categories (e.g., uppercase, lowercase, numbers, special characters) for better security.

[+] Checking Connection Tracking
    [!] Connection Tracking is currently set to 'auto'.
    [*] Advice: If this device is being used as a transit router, you might consider disabling Connection Tracking to improve performance. However, proceed with caution as it can affect certain network features.

[+] Checking MAC Server Settings
    [!] Warning: MAC Server is allowed on all interfaces (allowed-interface-list=all). This compromises the security of the Winbox interface.
    [!] Warning: MAC Winbox is allowed on all interfaces (allowed-interface-list=all). This compromises the security of the Winbox interface.
    [!] Warning: MAC Ping is enabled. Possible unwanted traffic.
    [*] Solution: Limit MAC server and MAC Winbox to specific trusted interfaces, and disable MAC Ping if it is not required.

[+] Checking SNMP Communities
    [!] Warning: SNMP community 'public' is in use. Possible Information Gathering attack vector by bruteforcing community string.
    [!] Warning: SNMP community 'private' is in use. Possible Information Gathering attack vector by bruteforcing community string.
    [*] Solution: Change the SNMP community names to something more secure, and restrict SNMP access to trusted IP addresses only.
```

# Outro

Tool will be maintained and updated, suggestions: caster@exploit.org



