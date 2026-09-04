"""Turning `TLS_ENABLED=1` into an actual TLS listener.

This module exists because the setting did not do anything. `TLS_ENABLED`,
`TLS_CERT` and `TLS_KEY` were in `.env.example`, in the production guide, and
in the instructions `certs/generate_certs.py` prints when it finishes — and no
line of code read any of them. An operator who set `TLS_ENABLED=1`, restarted,
and saw the console come up had every reason to believe the console was served
over HTTPS. It was served over plain HTTP on 0.0.0.0:8000, with the session
cookie and every credential posted to the login form travelling in clear text
across whatever network sat in front of it.

That is the worst shape a security control can have: not missing, but
*documented*. A missing feature gets noticed the first time someone looks for
it. A documented one gets trusted and never looked at again.

Two rules follow from that, and they are the whole design here:

**Asking for TLS and not getting it is a startup failure, never a fallback.**
If the certificate cannot be read, the server must refuse to start rather than
listen on plain HTTP. Falling back is how the original problem would come
back wearing an error message nobody reads in a container log.

**A cert nobody configured is generated, not assumed.** `certs.generate_certs`
already produces a per-deployment key that never leaves the machine. Wiring it
in here means the lab case works with one setting, and the honest warning
about a self-signed CA is printed rather than implied.
"""
from __future__ import annotations

import os
import ssl


TRUTHY = ("1", "true", "yes", "on")


class TLSConfigError(RuntimeError):
    """TLS was asked for and cannot be delivered.

    Raised rather than handled: see the module docstring. The one behaviour
    this must never have is continuing on plain HTTP.
    """


def tls_enabled(env=None) -> bool:
    env = os.environ if env is None else env
    return str(env.get("TLS_ENABLED", "")).strip().lower() in TRUTHY


def resolve(env=None, generate=True, log=print) -> dict | None:
    """The `ssl` argument for `app.run()`, or None to serve plain HTTP.

    `generate=False` is for callers that only want to know what is configured
    without creating key material as a side effect — the boot-time report and
    the tests both need that.
    """
    env = os.environ if env is None else env
    if not tls_enabled(env):
        return None

    cert = (env.get("TLS_CERT") or "").strip()
    key = (env.get("TLS_KEY") or "").strip()

    # Half a configuration is the dangerous case: it looks deliberate, and
    # whichever half is missing would otherwise be filled in from a generated
    # certificate the operator did not ask for and will not know is in use.
    if bool(cert) != bool(key):
        missing = "TLS_KEY" if cert else "TLS_CERT"
        raise TLSConfigError(
            f"TLS_ENABLED=1 with only one half of the pair set; {missing} is "
            f"empty. Set both, or neither to use a generated certificate."
        )

    if not cert:
        if not generate:
            return {"cert": None, "key": None, "generated": True}
        cert, key = _generate(env, log)

    for label, path in (("TLS_CERT", cert), ("TLS_KEY", key)):
        if not os.path.exists(path):
            raise TLSConfigError(
                f"{label}={path!r} does not exist. TLS was requested and "
                f"cannot be served; refusing to fall back to plain HTTP."
            )
        # Existing-but-unreadable is its own case. In a container it usually
        # means the key was mounted with the host's ownership, and the error
        # from the TLS layer further down is a bare PermissionError with no
        # path in it.
        try:
            with open(path, "rb") as handle:
                handle.read(1)
        except OSError as e:
            raise TLSConfigError(f"{label}={path!r} cannot be read: {e}") from e

    # Load it here rather than leaving it to the server. A malformed PEM, or a
    # key that does not match its certificate, is a clear message at startup
    # instead of a handshake that fails per-connection once traffic arrives.
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=cert, keyfile=key)
    except ssl.SSLError as e:
        raise TLSConfigError(
            f"TLS_CERT={cert!r} and TLS_KEY={key!r} were found but do not form "
            f"a usable pair: {e}"
        ) from e

    return {"cert": cert, "key": key}


def _generate(env, log) -> tuple[str, str]:
    """Fall back to a self-signed certificate for this deployment.

    Deliberately noisy. A generated certificate is the right default for a lab
    and the wrong one for anything an operator has to trust, and the only
    moment they will read about the difference is here.
    """
    try:
        from certs.generate_certs import ensure_certs
    except ImportError as e:
        raise TLSConfigError(
            f"TLS_ENABLED=1, no TLS_CERT/TLS_KEY set, and the certificate "
            f"generator is unavailable ({e}). Install `cryptography` or point "
            f"TLS_CERT/TLS_KEY at a real certificate."
        ) from e

    cn = (env.get("TLS_CN") or "").strip() or "localhost"
    try:
        paths = ensure_certs(cn=cn, log=log)
    except Exception as e:
        raise TLSConfigError(f"could not generate a certificate: {e}") from e

    log("[tls] Serving HTTPS with a self-signed certificate. Browsers will "
        "warn, because nothing trusts this CA - that warning is accurate. "
        "Point TLS_CERT/TLS_KEY at a real certificate for anything reachable "
        "beyond your own network.")
    log(f"[tls] Agents need certs/rootCA.crt to verify this server; see "
        f"SENTORA_CA_CERT in the agent configuration.")
    return paths["crt"], paths["key"]


def existing(env=None) -> dict | None:
    """The certificate pair that is already on disk, without creating one.

    For the second process. `app` owns generation the way it owns the Fernet
    key, and `ingest` mounts the same directory read-only - so `ingest` has to
    be able to ask "is it there yet" without the answer being "it is now,
    because I made a different one". Two processes generating independently
    would each hold a certificate the other does not, and an agent that
    verified the console would fail against ingest for no visible reason.
    """
    env = os.environ if env is None else env
    if not tls_enabled(env):
        return None

    cert = (env.get("TLS_CERT") or "").strip()
    key = (env.get("TLS_KEY") or "").strip()
    if not cert or not key:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cert = os.path.join(here, "certs", "server.crt")
        key = os.path.join(here, "certs", "server.key")

    if not (os.path.exists(cert) and os.path.exists(key)):
        return None
    return {"cert": cert, "key": key}


def describe(env=None) -> str:
    """One line for the boot banner, so the transport is visible at a glance.

    The reason this is worth a line: an operator who believed they had TLS had
    nothing on screen that would have told them otherwise.
    """
    env = os.environ if env is None else env
    if not tls_enabled(env):
        return ("HTTP (no TLS in this process - correct only if something in "
                "front of it terminates TLS)")
    if (env.get("TLS_CERT") or "").strip():
        return f"HTTPS (TLS_CERT={env.get('TLS_CERT')})"
    return "HTTPS (self-signed, generated for this deployment)"


def cookie_should_be_secure(env=None) -> bool:
    """Whether the session cookie may carry `Secure`.

    Both directions of this are a real outage, which is why it is derived
    rather than left to a second setting that has to agree with the first:

    `Secure` on a plain-HTTP deployment means the browser drops the cookie and
    nobody can log in. No `Secure` on an HTTPS deployment means the cookie that
    authenticates an operator will travel on any plain-HTTP request that can be
    provoked.

    `SESSION_COOKIE_SECURE` still wins when it is set, because TLS terminating
    at a proxy is invisible from in here - that deployment serves HTTP from
    this process and still needs the flag.
    """
    env = os.environ if env is None else env
    explicit = str(env.get("SESSION_COOKIE_SECURE", "")).strip().lower()
    if explicit:
        return explicit in TRUTHY
    return tls_enabled(env)
