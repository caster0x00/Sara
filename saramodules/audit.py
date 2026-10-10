# audit.py

from saramodules.api import get, get_settings
from saramodules.report import finding


# enabled static entries of /ip/service (v7 adds dynamic ones)
def active_services(api):
    services = []
    for service in get(api, "ip/service"):
        if service.get("disabled"):
            continue
        if service.get("dynamic"):
            continue
        services.append(service)
    return services


# MGMT-001: cleartext management services
def check_cleartext_services(api):
    cleartext = {"telnet", "ftp", "www", "api"}
    found = []

    for service in active_services(api):
        if service.get("name") in cleartext:
            found.append(service)

    if not found:
        return

    finding(
        "MGMT-001", "critical", "Cleartext management services enabled",
        evidence=[f"{service.get('name')}: enabled, port {service.get('port')}" for service in found],
        impact="Credentials can be intercepted by anyone on the network path",
        fix="/ip service disable " + ",".join(service.get("name") for service in found),
    )


# MGMT-002: services without source address restriction
def check_service_restrictions(api):
    found = []

    for service in active_services(api):
        if not service.get("address"):
            found.append(service)

    if not found:
        return

    finding(
        "MGMT-002", "critical", "Management services accept connections from any address",
        evidence=[f"{service.get('name')}: address=\"\"" for service in found],
        impact="Services are exposed to brute-force and exploitation from any network",
        fix="/ip service set <name> address=<management-subnet>",
    )


# MGMT-003: user accounts without source address restriction
def check_user_restrictions(api):
    found = []

    for user in get(api, "user"):
        if user.get("disabled"):
            continue
        if not user.get("address"):
            found.append(user)

    if not found:
        return

    finding(
        "MGMT-003", "medium", "User accounts accept logins from any address",
        evidence=[f"{user.get('name')}: group {user.get('group')}, address=\"\"" for user in found],
        impact="A stolen or guessed password works from any network",
        fix="/user set <name> address=<management-subnet>",
    )


# MGMT-004: default usernames present
def check_default_users(api):
    defaults = {"admin", "user", "test", "root", "mikrotik", "routeros", "engineer"}
    found = []

    for user in get(api, "user"):
        if user.get("disabled"):
            continue
        if user.get("name") in defaults:
            found.append(user)

    if not found:
        return

    finding(
        "MGMT-004", "medium", "Default usernames present",
        evidence=[f"{user.get('name')}: group {user.get('group')}" for user in found],
        impact="Attackers only need to guess the password, the username is already known",
        fix="/user set [find name=<name>] name=<unique-name>",
    )


# PROTO-001: MAC-Winbox allowed on all interfaces
def check_mac_winbox(api):
    settings = get_settings(api, "tool/mac-server/mac-winbox")
    allowed = settings.get("allowed-interface-list")

    if allowed != "all":
        return

    finding(
        "PROTO-001", "medium", "MAC-Winbox allowed on all interfaces",
        evidence=[f"allowed-interface-list: {allowed}"],
        impact="Anyone on any connected L2 segment can reach the Winbox login without an IP address",
        fix="/tool mac-server mac-winbox set allowed-interface-list=<mgmt-list>",
    )


# PROTO-002: MAC-Telnet allowed on all interfaces
def check_mac_telnet(api):
    settings = get_settings(api, "tool/mac-server")
    allowed = settings.get("allowed-interface-list")

    if allowed != "all":
        return

    finding(
        "PROTO-002", "medium", "MAC-Telnet allowed on all interfaces",
        evidence=[f"allowed-interface-list: {allowed}"],
        impact="Anyone on any connected L2 segment can open a CLI login session without an IP address",
        fix="/tool mac-server set allowed-interface-list=none",
    )


# PROTO-003: MAC ping enabled
def check_mac_ping(api):
    settings = get_settings(api, "tool/mac-server/ping")

    if not settings.get("enabled"):
        return

    finding(
        "PROTO-003", "low", "MAC ping enabled",
        evidence=["enabled: yes"],
        impact="The router answers MAC pings, which helps an attacker on the segment discover it",
        fix="/tool mac-server ping set enabled=no",
    )


# PROTO-004: neighbor discovery on all interfaces
def check_neighbor_discovery(api):
    settings = get_settings(api, "ip/neighbor/discovery-settings")
    interfaces = settings.get("discover-interface-list")

    if interfaces != "all":
        return

    evidence = [f"discover-interface-list: {interfaces}"]
    if settings.get("protocol"):
        evidence.append(f"protocol: {settings.get('protocol')}")

    finding(
        "PROTO-004", "medium", "Neighbor discovery enabled on all interfaces",
        evidence=evidence,
        impact="The router announces its identity, version and addresses to every connected segment",
        fix="/ip neighbor discovery-settings set discover-interface-list=<lan-list>",
    )


# PROTO-005: RoMON enabled
def check_romon(api):
    settings = get_settings(api, "tool/romon")

    if not settings.get("enabled"):
        return

    finding(
        "PROTO-005", "medium", "RoMON enabled",
        evidence=["enabled: yes", f"id: {settings.get('id')}"],
        impact="RoMON gives L2 management access across the RoMON network, bypassing IP firewall rules",
        fix="/tool romon set enabled=no",
    )


# PROTO-006: SSH strong crypto disabled
def check_ssh_crypto(api):
    settings = get_settings(api, "ip/ssh")

    # missing field is None, so compare with False explicitly
    if settings.get("strong-crypto") is not False:
        return

    finding(
        "PROTO-006", "medium", "SSH strong crypto disabled",
        evidence=["strong-crypto: no"],
        impact="SSH accepts weaker ciphers, sha1 MACs and small DH groups",
        fix="/ip ssh set strong-crypto=yes",
    )


# PROTO-007: SMB server enabled
def check_smb(api):
    settings = get_settings(api, "ip/smb")
    enabled = settings.get("enabled")

    # yes -> True, no -> False, auto stays a string
    if not enabled:
        return
    if enabled is True:
        enabled = "yes"

    finding(
        "PROTO-007", "high", "SMB server enabled",
        evidence=[f"enabled: {enabled}", f"interfaces: {settings.get('interfaces')}"],
        impact="RouterOS SMB has a history of remote code execution bugs and exposes router storage to the network",
        fix="/ip smb set enabled=no",
    )


# PROTO-008: UPnP enabled
def check_upnp(api):
    settings = get_settings(api, "ip/upnp")

    if not settings.get("enabled"):
        return

    finding(
        "PROTO-008", "high", "UPnP enabled",
        evidence=["enabled: yes"],
        impact="Any LAN host, including malware, can open inbound port forwards without authentication",
        fix="/ip upnp set enabled=no",
    )


# PROTO-009: bandwidth test server enabled
def check_bandwidth_server(api):
    settings = get_settings(api, "tool/bandwidth-server")

    if not settings.get("enabled"):
        return

    # without authentication anyone can start a test
    severity = "low"
    authenticate = "yes"
    if settings.get("authenticate") is False:
        severity = "medium"
        authenticate = "no"

    finding(
        "PROTO-009", severity, "Bandwidth test server enabled",
        evidence=["enabled: yes", f"authenticate: {authenticate}"],
        impact="Anyone who reaches the router can generate heavy traffic and load the CPU",
        fix="/tool bandwidth-server set enabled=no",
    )


# PROTO-010: DDNS enabled
def check_ddns(api):
    settings = get_settings(api, "ip/cloud")
    enabled = settings.get("ddns-enabled")

    if not enabled:
        return
    # auto counts only when a name was actually issued
    if enabled == "auto" and not settings.get("dns-name"):
        return
    if enabled is True:
        enabled = "yes"

    finding(
        "PROTO-010", "low", "DDNS enabled",
        evidence=[f"ddns-enabled: {enabled}", f"dns-name: {settings.get('dns-name')}"],
        impact="The router publishes its public IP under a predictable name, which makes it easy to find",
        fix="/ip cloud set ddns-enabled=no",
    )


# PROTO-011: SNMP enabled with default community
def check_snmp_community(api):
    defaults = {"public", "private", "admin", "mikrotik", "snmp"}
    found = []

    # communities do not matter while SNMP itself is off
    if not get_settings(api, "snmp").get("enabled"):
        return

    for community in get(api, "snmp/community"):
        if community.get("disabled"):
            continue
        if community.get("name") in defaults:
            found.append(community)

    if not found:
        return

    finding(
        "PROTO-011", "high", "SNMP enabled with default community",
        evidence=[f"{community.get('name')}: addresses {community.get('addresses')}" for community in found],
        impact="Anyone who reaches UDP 161 can read interfaces, routes, ARP table and device details",
        fix="/snmp community set [find name=<name>] name=<random> addresses=<nms>",
    )


# PROTO-012: SNMP community with write access
def check_snmp_write(api):
    found = []

    if not get_settings(api, "snmp").get("enabled"):
        return

    for community in get(api, "snmp/community"):
        if community.get("disabled"):
            continue
        if community.get("write-access"):
            found.append(community)

    if not found:
        return

    finding(
        "PROTO-012", "high", "SNMP community with write access",
        evidence=[f"{community.get('name')}: write-access yes, addresses {community.get('addresses')}" for community in found],
        impact="Anyone who knows the community string can change router settings over SNMP",
        fix="/snmp community set [find name=<name>] write-access=no",
    )


# PROTO-013: router answers remote DNS requests
def check_dns_remote(api):
    settings = get_settings(api, "ip/dns")

    if not settings.get("allow-remote-requests"):
        return

    finding(
        "PROTO-013", "medium", "Router answers remote DNS requests",
        evidence=["allow-remote-requests: yes", f"servers: {settings.get('servers')}"],
        impact="If port 53 is reachable from WAN, the router becomes an open resolver for DNS amplification",
        fix="Block 53/udp and 53/tcp on input from WAN",
    )


# USER-002: no minimum password length (v7 only)
def check_password_length(api):
    settings = get_settings(api, "user/settings")
    length = settings.get("minimum-password-length")

    if length != 0:
        return

    finding(
        "USER-002", "medium", "No minimum password length",
        evidence=[f"minimum-password-length: {length}"],
        impact="Users can set short or empty passwords that fall to brute-force in minutes",
        fix="/user settings set minimum-password-length=N",
    )


# SYS-001: RouterBOOT protection disabled
def check_routerboot(api):
    board_name = get_settings(api, "system/resource").get("board-name", "")

    # CHR has no RouterBOOT
    if "CHR" in board_name:
        return

    settings = get_settings(api, "system/routerboard/settings")
    protection = settings.get("protected-routerboot")

    if protection != "disabled":
        return

    finding(
        "SYS-001", "high", "RouterBOOT protection disabled",
        evidence=[f"protected-routerboot: {protection}"],
        impact="Anyone with physical access can reset the configuration or boot another system with the reset button",
        fix="/system routerboard settings set protected-routerboot=enabled",
    )


# HW-001: PoE forced on without device detection
def check_poe(api):
    found = []

    # v7 keeps PoE in its own menu, v6 in /interface/ethernet. The other one is empty
    ports = get(api, "interface/ethernet/poe") + get(api, "interface/ethernet")

    for port in ports:
        if port.get("poe-out") == "forced-on":
            found.append(port)

    if not found:
        return

    finding(
        "HW-001", "low", "PoE forced on without device detection",
        evidence=[f"{port.get('name')}: poe-out=forced-on" for port in found],
        impact="Power is pushed into whatever is plugged in, which can damage a non-PoE device",
        fix="/interface ethernet poe set <name> poe-out=auto-on",
    )


# WIFI-001: PMKID enabled
def check_wifi_pmkid(api):
    found = []

    # wifi package (v7): security profiles and settings written on the interface
    for profile in get(api, "interface/wifi/security"):
        if profile.get("disable-pmkid") is False:
            found.append(f"wifi security {profile.get('name')}: disable-pmkid=no")

    for interface in get(api, "interface/wifi"):
        if interface.get("disabled"):
            continue
        if interface.get("security.disable-pmkid") is False:
            found.append(f"wifi {interface.get('name')}: security.disable-pmkid=no")

    # wireless package (legacy)
    for profile in get(api, "interface/wireless/security-profiles"):
        if profile.get("disable-pmkid") is False:
            found.append(f"wireless security-profile {profile.get('name')}: disable-pmkid=no")

    if not found:
        return

    finding(
        "WIFI-001", "medium", "PMKID enabled",
        evidence=found,
        impact="An attacker can grab a crackable WPA2 hash without waiting for any client to connect",
        fix="/interface wifi security set <name> disable-pmkid=yes "
            "(wireless: /interface wireless security-profiles set <name> disable-pmkid=yes)",
    )


# WIFI-002: WPS enabled
def check_wifi_wps(api):
    found = []

    # wifi package (v7): wps=push-button or wps=disable
    for profile in get(api, "interface/wifi/security"):
        if profile.get("wps") == "push-button":
            found.append(f"wifi security {profile.get('name')}: wps=push-button")

    for interface in get(api, "interface/wifi"):
        if interface.get("disabled"):
            continue
        if interface.get("security.wps") == "push-button":
            found.append(f"wifi {interface.get('name')}: security.wps=push-button")

    # wireless package (legacy): wps-mode=push-button, push-button-virtual-only or disabled
    for interface in get(api, "interface/wireless"):
        if interface.get("disabled"):
            continue
        wps_mode = interface.get("wps-mode")
        if wps_mode and wps_mode != "disabled":
            found.append(f"wireless {interface.get('name')}: wps-mode={wps_mode}")

    if not found:
        return

    finding(
        "WIFI-002", "medium", "WPS enabled",
        evidence=found,
        impact="A nearby device can join the network without the passphrase while the WPS window is open",
        fix="/interface wifi security set <name> wps=disable "
            "(wireless: /interface wireless set <name> wps-mode=disabled)",
    )


# run all audit checks
def run(api):
    # MGMT: 001-004
    check_cleartext_services(api)
    check_service_restrictions(api)
    check_user_restrictions(api)
    check_default_users(api)
    # PROTO: 001-013
    check_mac_winbox(api)
    check_mac_telnet(api)
    check_mac_ping(api)
    check_neighbor_discovery(api)
    check_romon(api)
    check_ssh_crypto(api)
    check_smb(api)
    check_upnp(api)
    check_bandwidth_server(api)
    check_ddns(api)
    check_snmp_community(api)
    check_snmp_write(api)
    check_dns_remote(api)
    # USER, SYS
    check_password_length(api)
    check_routerboot(api)
    # HW, WIFI
    check_poe(api)
    check_wifi_pmkid(api)
    check_wifi_wps(api)
