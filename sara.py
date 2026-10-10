#!/usr/bin/env python3

# sara.py

import argparse
import sys
from getpass import getpass
from saramodules import audit, cve
from saramodules.api import open_api, get_settings
from saramodules.report import header, error

INDENT = "    "

# print banner
def banner():
    print(r"""
     _____
    /  ___|
    \ `--.  __ _ _ __ __ _
     `--. \/ _` | '__/ _` |
    /\__/ / (_| | | | (_| |
    \____/ \__,_|_|  \__,_| v1.4.0
""")
    print(INDENT + "Sara: RouterOS Security Assessment Toolkit")
    print(INDENT + "Author: Ifrit")
    print(INDENT + "Contact: contact@ifritnoises.org\n")

# connect, print device info, run the module picked by the subcommand
def run_module(args):
    # pick default port
    port = args.port
    if port is None:
        port = 8728 if args.plaintext else 8729

    if args.plaintext:
        error("Plaintext API: credentials are sent unencrypted")

    password = getpass(f"[?] Password for {args.username}@{args.ip}: ")
    api = open_api(args.ip, args.username, password, port, args.plaintext)

    resource = get_settings(api, "system/resource")
    identity = get_settings(api, "system/identity")

    header([
        ("Target:", f"{args.ip}:{port}"),
        ("User:", args.username),
        ("Identity:", identity.get("name")),
        ("RouterOS:", resource.get("version")),
        ("Board:", resource.get("board-name")),
        ("Mode:", args.command),
    ])

    if args.command == "audit":
        audit.run(api)
    if args.command == "cve":
        cve.run(resource.get("version"))

    api.close()
    print(f"\n[*] Disconnected from RouterOS ({args.ip})")


# cve mode: a given --version needs no router, otherwise read the version from the router
def run_cve(args):
    if args.version:
        header([
            ("RouterOS:", args.version),
            ("Mode:", "cve"),
        ])
        cve.run(args.version)
        return

    if not args.ip or not args.username:
        error("Give ip and username, or --version")
        sys.exit(1)

    run_module(args)


def main():
    # banner first, so it shows before -h and the password prompt
    banner()

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    # audit mode
    mode = sub.add_parser("audit", help="Run RouterOS security configuration audit")
    mode.add_argument("ip", help="Specify RouterOS IP Address ")
    mode.add_argument("username", help="RouterOS API Username")
    mode.add_argument("--port", type=int, default=None, help="API port (default: 8729, or 8728 with --plaintext)")
    mode.add_argument("--plaintext", action="store_true", help="Use unencrypted API (port 8728)")
    mode.set_defaults(func=run_module)

    # cve mode
    mode = sub.add_parser("cve", help="Search NVD for CVEs that affect the RouterOS version")
    mode.add_argument("ip", nargs="?", help="RouterOS IP address (not needed with --version)")
    mode.add_argument("username", nargs="?", help="RouterOS username (not needed with --version)")
    mode.add_argument("--version", help="Check this RouterOS version without connecting, e.g. 7.13.1")
    mode.add_argument("--port", type=int, default=None, help="API port (default: 8729, or 8728 with --plaintext)")
    mode.add_argument("--plaintext", action="store_true", help="Use unencrypted API (port 8728)")
    mode.set_defaults(func=run_cve)

    try:
        args = parser.parse_args()
        args.func(args)
    except KeyboardInterrupt:
        print()
        error("Interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()
