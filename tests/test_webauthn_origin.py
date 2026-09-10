"""Where a security key can be used, and where it cannot.

This is the whole of the configuration story for WebAuthn on this platform, so
it is the part worth pinning hardest. There is no setting: the relying-party ID
is derived from the request, which means it is right by construction on a
laptop and on an estate with a real hostname, and it means some origins simply
cannot host a key at all.

The ones that cannot are the point. A console opened at `https://10.0.0.5`
looks completely normal and a security key can never be registered from it -
browsers refuse an IP address as a relying-party ID. Without this check the
operator meets that as a `SecurityError` in a browser console, naming neither
the cause nor the fix.
"""
from __future__ import annotations

import pytest

from security import webauthn as wa


# --------------------------------------------------------------------------
# Origins that work
# --------------------------------------------------------------------------

@pytest.mark.parametrize("host,scheme,rp_id", [
    ("sentora.corp.local", "https", "sentora.corp.local"),
    ("sentora.corp.local:8443", "https", "sentora.corp.local"),
    ("soc.example.com", "https", "soc.example.com"),
    # Secure by definition, whatever the scheme. This is the case that makes a
    # single-machine install work with nothing configured at all.
    ("localhost", "http", "localhost"),
    ("localhost:8000", "https", "localhost"),
])
def test_an_origin_that_can_host_a_key(host, scheme, rp_id):
    ok, reason = wa.usability(host, scheme)
    assert ok, reason
    assert wa.relying_party(host, scheme)[0] == rp_id


def test_the_port_is_kept_in_the_origin_and_dropped_from_the_rp_id():
    """Both halves matter and they are not the same string. Verification
    compares the response against the full origin; the RP ID is the bare host,
    and `localhost:8000` as an RP ID is refused by the browser with an error
    that names neither."""
    rp_id, origin = wa.relying_party("sentora.corp.local:8443", "https")
    assert rp_id == "sentora.corp.local"
    assert origin == "https://sentora.corp.local:8443"


def test_a_default_port_leaves_the_origin_clean():
    assert wa.relying_party("soc.example.com", "https")[1] == "https://soc.example.com"


# --------------------------------------------------------------------------
# Origins that cannot, and what they say about it
# --------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["192.168.1.26:8000", "10.0.0.5", "127.0.0.1:8000"])
def test_an_address_can_never_host_a_key(host):
    """Even over https, and even on the loopback address. The relying-party ID
    must be a domain; `127.0.0.1` is a secure context and still not a domain,
    which is exactly the pairing that makes this confusing to meet in the
    wild."""
    ok, reason = wa.usability(host, "https")
    assert not ok
    assert "address" in reason
    assert "hostname" in reason


def test_the_address_message_says_codes_still_work():
    """Otherwise the operator reads it as "two-factor is unavailable here" and
    turns the whole thing off."""
    _, reason = wa.usability("10.0.0.5", "https")
    assert "codes work" in reason.lower() or "one-time codes" in reason.lower()


def test_plain_http_is_refused_and_named_as_such():
    ok, reason = wa.usability("sentora.corp.local", "http")
    assert not ok
    assert "secure context" in reason
    assert "TLS_ENABLED" in reason, "say which setting turns it on"


def test_ipv6_literals_are_addresses_too():
    """`[::1]:8000` has to survive the port split before it can be recognised
    as an address at all - the bracket form is the one a naive `split(':')`
    turns into nonsense."""
    ok, _ = wa.usability("[::1]:8000", "https")
    assert not ok
    assert wa.split_host("[::1]:8000") == ("::1", "8000")


def test_nothing_is_returned_for_an_origin_that_cannot_be_used():
    """`relying_party` raises rather than handing back an RP ID that the
    browser will reject. A ceremony started on a bad RP ID fails inside the
    browser, where the server never learns it happened."""
    with pytest.raises(wa.Unusable):
        wa.relying_party("10.0.0.5", "https")


def test_an_empty_host_is_not_silently_accepted():
    ok, reason = wa.usability("", "https")
    assert not ok
    assert reason


# --------------------------------------------------------------------------
# Host parsing
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("localhost:8000", ("localhost", "8000")),
    ("localhost", ("localhost", None)),
    ("[fe80::1]:443", ("fe80::1", "443")),
    ("[::1]", ("::1", None)),
    # A bare IPv6 address with no brackets and no port. Splitting on the last
    # colon would take `:1` for a port number and leave a broken address.
    ("fe80::1", ("fe80::1", None)),
])
def test_host_and_port_come_apart_correctly(raw, expected):
    assert wa.split_host(raw) == expected


# --------------------------------------------------------------------------
# Clone detection
# --------------------------------------------------------------------------

def test_a_counter_going_backwards_is_a_clone():
    """The one thing the sign counter is for: a copy of a key does not know
    how many times the original has been used."""
    assert wa.counter_regressed(stored=42, presented=7)
    assert wa.counter_regressed(stored=42, presented=42), "replay of the same assertion"


def test_a_counter_moving_forward_is_fine():
    assert not wa.counter_regressed(stored=42, presented=43)


def test_zero_means_not_implemented_and_is_not_a_clone():
    """Most platform passkeys, and every credential that syncs between
    devices, report zero for ever. Refusing those would switch the control off
    for the hardware people actually have."""
    assert not wa.counter_regressed(stored=0, presented=0)
    assert not wa.counter_regressed(stored=17, presented=0)
    assert not wa.counter_regressed(stored=0, presented=17)


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

def test_a_credential_records_the_rp_id_it_was_made_for():
    """A key registered at `localhost` is not offered at a hostname and vice
    versa - the browser scopes it to the origin. Without the column, the
    console lists a key the browser will never produce, and the login step
    shows a prompt that times out with no explanation."""
    assert "rp_id" in wa.DDL_CREDENTIALS


def test_the_challenge_is_server_side_and_expires():
    """A challenge the browser chooses is not a challenge."""
    assert "webauthn_challenges" in wa.DDL_CHALLENGES
    assert "expires_at" in wa.DDL_CHALLENGES
    assert wa.CHALLENGE_TTL_SECONDS <= 300


def test_the_challenge_records_both_the_rp_id_and_the_origin():
    """Verification checks both, and checking a response against the origin
    the response itself claims is not a check."""
    assert "rp_id" in wa.DDL_CHALLENGES
    assert "origin" in wa.DDL_CHALLENGES


def test_challenges_are_not_guessable():
    a, b = wa.new_challenge(), wa.new_challenge()
    assert a != b
    assert len(a) >= 32


# --------------------------------------------------------------------------
# The console has to ask, not guess
# --------------------------------------------------------------------------

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend" / "src"
APP = ROOT / "app.py"


def test_the_page_asks_the_server_whether_a_key_can_be_used():
    """The browser cannot answer this. Whether the relying-party ID is valid
    for this origin, and whether the server even has the library, are both
    server facts - a page that decided for itself would show a button that
    fails, which is what the capability endpoint exists to prevent."""
    page = (FRONTEND / "pages" / "AccountSecurity.tsx").read_text(encoding="utf-8")
    assert "webauthnCapability" in page
    assert "capability.reason" in page, \
        "the page must show why, not merely hide the button"


def test_the_reason_is_shown_rather_than_a_disabled_control():
    page = (FRONTEND / "pages" / "AccountSecurity.tsx").read_text(encoding="utf-8")
    # A disabled button with a tooltip is the version of this that gets
    # reported as "the button does nothing".
    assert "One-time codes above are unaffected" in page, \
        "an operator reading 'unavailable' must not conclude 2FA is off here"


def test_the_login_page_offers_the_key_beside_the_code():
    """Not instead of it. A key that is lost, forgotten at home, or registered
    at a different origin leaves the code as the way in, and a login page that
    only offers the key strands that operator."""
    page = (FRONTEND / "pages" / "Login.tsx").read_text(encoding="utf-8")
    assert "webauthnLoginBegin" in page
    assert "handleSecondFactor" in page, "the code path is still there"


def test_the_key_is_not_attempted_automatically():
    """Calling `navigator.credentials.get` on arrival throws a browser dialog
    at somebody who was reaching for their phone, and cancelling it counts as a
    failed attempt against the pending token."""
    page = (FRONTEND / "pages" / "Login.tsx").read_text(encoding="utf-8")
    assert "onClick={handleSecurityKey}" in page, "it has to be a press"
    assert "useEffect(() => { handleSecurityKey" not in page


def test_the_registration_and_login_ceremonies_are_two_calls_each():
    """The challenge has to come from the server. A single-call ceremony means
    the browser chose the challenge, which is the replay this is meant to
    stop."""
    api = (FRONTEND / "services" / "api.ts").read_text(encoding="utf-8")
    for name in ("webauthnRegisterBegin", "webauthnRegisterFinish",
                 "webauthnLoginBegin", "webauthnLoginFinish"):
        assert name in api, name


def test_the_server_never_takes_the_origin_from_the_response():
    """Verifying a response against the origin the response itself claims is
    not a check. Both the expected origin and the expected RP ID are read back
    from the challenge row the server wrote."""
    import ast

    tree = ast.parse(APP.read_text(encoding="utf-8"))
    for name in ("webauthn_register_finish", "webauthn_login_finish"):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.AsyncFunctionDef) and n.name == name)
        body = ast.unparse(fn)
        assert "expected_origin=origin" in body, name
        assert "expected_rp_id=rp_id" in body, name
        assert "FROM webauthn_challenges" in body, \
            f"{name} does not read the challenge it is verifying against"


def test_a_challenge_is_deleted_once_it_has_been_answered():
    """Single use, verified or not. A challenge left behind is one a captured
    response can be presented against twice."""
    import ast

    tree = ast.parse(APP.read_text(encoding="utf-8"))
    for name in ("webauthn_register_finish", "webauthn_login_finish"):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.AsyncFunctionDef) and n.name == name)
        assert "DELETE FROM webauthn_challenges" in ast.unparse(fn), name


def test_a_key_alone_still_demands_a_second_factor():
    """The bypass this would otherwise be. If `_totp_required` read only the
    TOTP table, an operator who registered a key and never set up an
    authenticator would sign in with a password alone - and could arrange it
    deliberately by opening the console at an address, where no key can be
    offered. Whether a factor is required is a property of the account."""
    import ast

    tree = ast.parse(APP.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "_totp_required")
    assert "_has_security_key" in ast.unparse(fn)

    checker = next(n for n in ast.walk(tree)
                   if isinstance(n, ast.AsyncFunctionDef) and n.name == "_has_security_key")
    body = ast.unparse(checker)
    assert "rp_id" not in body, (
        "scoping this to the current origin turns the origin binding into a "
        "way around the second factor"
    )
