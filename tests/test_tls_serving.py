"""`TLS_ENABLED=1` has to produce TLS, or refuse to start.

The setting was in `.env.example`, in `docs/production-deployment.md`, and in
the closing instructions of `certs/generate_certs.py`. It was read by nothing.
An operator who set it saw the console come up and had no way, short of
opening a packet capture, to learn that the login form and the session cookie
were crossing the network in clear text.

A missing control gets noticed the first time somebody looks for it. A
documented one gets trusted. These tests are about the second kind: the
configuration and the transport have to be the same thing.
"""
from __future__ import annotations

import pathlib
import ssl

import pytest

from core import tls

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_off_by_default():
    assert tls.resolve(env={}) is None
    assert tls.tls_enabled(env={}) is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_the_spellings_operators_actually_use(value):
    """`TLS_ENABLED=true` silently meaning off is the same failure as the one
    this module exists to fix."""
    assert tls.tls_enabled(env={"TLS_ENABLED": value}) is True


def test_a_missing_certificate_refuses_to_start(tmp_path):
    """The one behaviour that must never exist: asking for TLS, not getting
    it, and serving plain HTTP anyway."""
    with pytest.raises(tls.TLSConfigError) as excinfo:
        tls.resolve(env={
            "TLS_ENABLED": "1",
            "TLS_CERT": str(tmp_path / "nope.crt"),
            "TLS_KEY": str(tmp_path / "nope.key"),
        })
    assert "plain HTTP" in str(excinfo.value)


def test_half_a_configuration_is_refused(tmp_path):
    """Setting only one of the pair looks deliberate. Filling the other half
    from a generated certificate would serve TLS the operator did not
    configure and would not know was in use."""
    with pytest.raises(tls.TLSConfigError) as excinfo:
        tls.resolve(env={"TLS_ENABLED": "1", "TLS_CERT": str(tmp_path / "a.crt")})
    assert "TLS_KEY" in str(excinfo.value)


def test_a_mismatched_pair_fails_at_startup_not_per_connection(tmp_path):
    """A key that does not match its certificate handshakes fine until the
    first client arrives, and then fails once per connection in a log nobody
    is reading."""
    from certs.generate_certs import ensure_certs

    a = ensure_certs(outdir=str(tmp_path / "a"), cn="a.local", days=30, log=lambda *_: None)
    b = ensure_certs(outdir=str(tmp_path / "b"), cn="b.local", days=30, log=lambda *_: None)

    with pytest.raises(tls.TLSConfigError) as excinfo:
        tls.resolve(env={"TLS_ENABLED": "1", "TLS_CERT": a["crt"], "TLS_KEY": b["key"]})
    assert "usable pair" in str(excinfo.value)


def test_a_real_pair_is_accepted(tmp_path):
    from certs.generate_certs import ensure_certs

    paths = ensure_certs(outdir=str(tmp_path), cn="soc.local", days=30, log=lambda *_: None)
    config = tls.resolve(env={
        "TLS_ENABLED": "1", "TLS_CERT": paths["crt"], "TLS_KEY": paths["key"],
    })
    assert config == {"cert": paths["crt"], "key": paths["key"]}

    # The shape Sanic wants. Asserted because getting it wrong produces a
    # server that starts and then serves nothing.
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=config["cert"], keyfile=config["key"])


# --------------------------------------------------------------------------
# The cookie and the transport have to agree
# --------------------------------------------------------------------------

def test_the_cookie_follows_tls_when_nobody_said_otherwise():
    """These were two independent settings that had to match, and nothing
    made them. TLS on with the flag left alone gave an HTTPS console whose
    session cookie was still allowed onto plain HTTP."""
    assert tls.cookie_should_be_secure(env={"TLS_ENABLED": "1"}) is True
    assert tls.cookie_should_be_secure(env={}) is False


def test_an_explicit_setting_still_wins():
    """TLS terminating at a proxy is invisible from inside this process, and
    that deployment serves HTTP here and still needs the flag."""
    assert tls.cookie_should_be_secure(env={"SESSION_COOKIE_SECURE": "1"}) is True
    assert tls.cookie_should_be_secure(
        env={"TLS_ENABLED": "1", "SESSION_COOKIE_SECURE": "0"}) is False


# --------------------------------------------------------------------------
# The wiring, not just the helper
# --------------------------------------------------------------------------

def test_app_actually_passes_ssl_to_run():
    """`core/tls.py` being correct is worth nothing if `app.run()` never
    receives what it returns - which is precisely the bug this replaces."""
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    run = source[source.index("    app.run("):]
    # To the closing paren of the call, not the first paren in it - the first
    # is inside `single_process=(num_workers == 1)`, and slicing there made
    # this test read an empty argument list and fail on a correct file.
    run = run[:run.index(chr(10) + "    )")]
    assert "ssl=ssl_config" in run, "app.run() does not receive the TLS config"


def test_the_documented_settings_are_the_implemented_ones():
    """The drift that caused this: `.env.example` and the production guide
    named three variables, and the code read none of them. Whatever the docs
    promise has to appear in the module that delivers it."""
    source = (ROOT / "core" / "tls.py").read_text(encoding="utf-8")
    for name in ("TLS_ENABLED", "TLS_CERT", "TLS_KEY"):
        assert f'"{name}"' in source or f"get(\"{name}\"" in source, name

    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "production-deployment.md").read_text(encoding="utf-8")
    for name in ("TLS_ENABLED", "TLS_CERT", "TLS_KEY"):
        assert name in env_example, f"{name} is implemented but undocumented"
        assert name in guide, f"{name} is implemented but not in the guide"
