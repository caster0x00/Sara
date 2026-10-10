# api.py

import ssl
import sys
from librouteros import connect
from librouteros.exceptions import TrapError, MultiTrapError
from saramodules.report import error


# open API session
def open_api(ip, user, password, port, plaintext):
    try:
        if plaintext:
            api = connect(host=ip, username=user, password=password, port=port)
        else:
            # routers usually have self-signed certificates
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            api = connect(host=ip, username=user, password=password, port=port, ssl_wrapper=ctx.wrap_socket)
    except Exception as e:
        error(f"API connection failed: {e}")
        sys.exit(1)

    return api


# all entries of a menu, [] if the menu does not exist on this device
def get(api, path):
    try:
        return list(api.path(*path.split("/")))
    except (TrapError, MultiTrapError):
        return []


# the only entry of a settings menu, {} if the menu does not exist
def get_settings(api, path):
    entries = get(api, path)
    if not entries:
        return {}
    return entries[0]
