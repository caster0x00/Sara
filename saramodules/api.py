# api.py

import ssl
import sys
from librouteros import connect
from librouteros.exceptions import TrapError, MultiTrapError
from saramodules.report import error, warning


# TLS context for api-ssl; routers usually have self-signed certificates, so they are not verified
def tls_context(anonymous):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if anonymous:
        # api-ssl without a certificate offers only anonymous DH ciphers, and only up to TLS 1.2.
        # Most distributions disable them by default, SECLEVEL=0 turns them back on
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ADH:@SECLEVEL=0")
    return ctx


# open API session
def open_api(ip, user, password, port, plaintext):
    try:
        if plaintext:
            return connect(host=ip, username=user, password=password, port=port)

        try:
            return connect(host=ip, username=user, password=password, port=port,
                           ssl_wrapper=tls_context(False).wrap_socket)
        except ssl.SSLError:
            warning("api-ssl has no certificate on the router, retrying with anonymous TLS ciphers")
            warning("The channel is still encrypted, but the router identity cannot be verified")
            return connect(host=ip, username=user, password=password, port=port,
                           ssl_wrapper=tls_context(True).wrap_socket)
    except Exception as exception:
        error(f"API connection failed: {exception}")
        sys.exit(1)


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
