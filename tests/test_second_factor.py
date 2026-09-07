"""A second factor, and the five ways one gets built wrong.

The console has been protected by a password and a lockout. That is enough
against guessing and nothing at all against a password that has been reused,
phished, or read out of a browser - and this console can isolate a host, run a
command as SYSTEM on every endpoint, and read every log the fleet produced.

The mechanism is the easy part; RFC 4226 is eleven lines. What this file pins
is the surrounding design, because each of these is a way to ship something
that looks like two-factor and is not:

    a session issued before the second factor, then "upgraded"
    a code that can be used twice inside its thirty-second step
    recovery codes stored so they can be shown again
    a secret readable from a database dump
    one login path gated and another not
"""
from __future__ import annotations

import ast
import base64
import pathlib
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"

from security import totp  # noqa: E402


def _function(name: str):
    return next(n for n in ast.walk(ast.parse(APP.read_text(encoding="utf-8")))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


# --------------------------------------------------------------------------
# The mechanism
# --------------------------------------------------------------------------

def test_rfc4226_vectors():
    """The published test vectors. Written out rather than depending on a
    library, so this is the only thing standing between an arithmetic slip and
    codes that nobody's authenticator agrees with."""
    secret = base64.b32encode(b"12345678901234567890").decode()
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    assert [totp._hotp(secret, c) for c in range(10)] == expected


def test_a_secret_is_key_material():
    a, b = totp.new_secret(), totp.new_secret()
    assert a != b
    assert len(a) >= 32
    assert set(a) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def test_padding_stripped_secrets_still_work():
    """Authenticator apps hand out secrets without `=` padding and
    `b32decode` insists on it. A user pasting one from anywhere has to work."""
    secret = totp.new_secret().rstrip("=")
    assert totp.verify(secret, totp._hotp(secret, totp.current_step())) is not None


def test_the_drift_window_is_narrow():
    """One step either side. Zero rejects honest users on ordinary clock
    drift; three hands an attacker ninety seconds to reuse a code they saw."""
    assert totp.ALLOWED_DRIFT_STEPS == 1
    now = time.time()
    assert len(totp.codes_in_window("A" * 32, now)) == 3

    secret = totp.new_secret()
    stale = totp._hotp(secret, totp.current_step(now) - 2)
    assert totp.verify(secret, stale, now) is None


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 34 5",
                                 None, "٠١٢٣٤٥"])
def test_a_malformed_code_is_refused_without_raising(bad):
    """The login path must not turn a typo into a 500."""
    assert totp.verify(totp.new_secret(), bad) is None


def test_the_comparison_is_constant_time():
    """Six digits is a small space, and `==` on a string leaks how much of it
    was right through timing. Not worth helping."""
    source = (ROOT / "security" / "totp.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(source).body
              if isinstance(n, ast.FunctionDef) and n.name == "verify")
    assert "compare_digest" in ast.unparse(fn)


# --------------------------------------------------------------------------
# The design
# --------------------------------------------------------------------------

def test_no_session_exists_until_both_factors_pass():
    """The mistake that makes two-factor decorative: issue a session on the
    password, then upgrade it when a code arrives. Every bug in that window is
    a bypass."""
    login = ast.unparse(_function("login"))
    gate = login.index("needs_second")
    issue = login.index("_issue_session")
    assert gate < issue, "a session is created before the second factor is asked for"


def test_both_login_paths_are_gated():
    """A factor that protects one path and not the other protects nothing -
    an attacker with a password picks the path without it."""
    login = ast.unparse(_function("login"))
    assert login.count("_totp_required") >= 2, \
        "only one of the local and LDAP branches checks for a second factor"
    assert login.count("second_factor_required") >= 2


def test_a_code_cannot_be_used_twice():
    """TOTP is a shared secret and a clock: the same six digits stay valid for
    the whole step. Without this, watching one code being typed buys thirty
    seconds to use it."""
    body = ast.unparse(_function("complete_second_factor"))
    assert "last_step" in body
    assert "last_step < %s" in body or "last_step <" in body, \
        "nothing stops a code from earlier in the accepted window being replayed"
    assert "TOTP_CODE_REPLAYED" in body, "a replay is not reported"


def test_a_pending_login_is_not_an_unlimited_oracle():
    body = ast.unparse(_function("complete_second_factor"))
    assert "MAX_PENDING_ATTEMPTS" in body
    assert totp.MAX_PENDING_ATTEMPTS <= 10


def test_the_pending_token_is_stored_hashed():
    """Like a session token, and for the same reason: a dump of this table
    must not let anybody finish a login somebody else started."""
    body = ast.unparse(_function("complete_second_factor"))
    assert "hash_pending" in body
    assert "token_hash" in body


def test_the_pending_token_expires():
    assert 0 < totp.PENDING_TTL_SECONDS <= 900
    assert "expires_at > NOW()" in ast.unparse(_function("complete_second_factor"))


def test_expired_spent_and_invalid_are_one_message():
    """Telling them apart tells an attacker which half of a captured pair is
    still good."""
    body = ast.unparse(_function("complete_second_factor"))
    assert body.count("This login has expired. Sign in again.") == 1


# --------------------------------------------------------------------------
# Recovery codes are credentials
# --------------------------------------------------------------------------

def test_recovery_codes_are_stored_as_hashes():
    body = ast.unparse(_function("second_factor_confirm"))
    assert "hash_recovery" in body
    assert "code_hash" in body


def test_they_are_shown_once_and_only_once():
    """Storing them so the console can show them again is the same mistake as
    storing a password, made for a friendlier reason."""
    # The values, not the words. The first version matched any handler
    # mentioning "recovery_codes", which `second_factor_disable` does because
    # it deletes them - so the test failed on a route that leaks nothing.
    source = APP.read_text(encoding="utf-8")
    leaking = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = ast.unparse(node)
        if "'recovery_codes': codes" in body or '"recovery_codes": codes' in body:
            leaking.append(node.name)
    assert leaking == ["second_factor_confirm"], (
        f"the generated codes are returned from {leaking}; they may leave the "
        f"server exactly once"
    )

    status = ast.unparse(_function("second_factor_status"))
    assert "recovery_codes_remaining" in status
    assert "code_hash" not in status, "the status route can leak the stored hashes"


def test_a_recovery_code_is_burnt_on_use():
    body = ast.unparse(_function("complete_second_factor"))
    assert "used_at = NOW()" in body
    assert "used_at IS NULL" in body, "a spent recovery code can be replayed"
    assert "RECOVERY_CODE_USED" in body, \
        "signing in with a recovery code is not reported"


def test_recovery_hashing_is_not_stretched():
    """Deliberate, and the opposite of the rule for passwords: these are 80
    bits of machine-chosen entropy, so there is no dictionary to slow down. A
    cost factor would only make the login path slower."""
    source = (ROOT / "security" / "totp.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(source).body
              if isinstance(n, ast.FunctionDef) and n.name == "hash_recovery")
    # Statements only. The docstring explains why *not* bcrypt, so matching
    # the whole function finds the explanation and reads it as the code -
    # the eighth time that has happened in this suite.
    statements = [n for n in fn.body
                  if not (isinstance(n, ast.Expr)
                          and isinstance(n.value, ast.Constant))]
    body = "\n".join(ast.unparse(n) for n in statements)
    assert "sha256" in body
    assert "bcrypt" not in body


# --------------------------------------------------------------------------
# The secret at rest
# --------------------------------------------------------------------------

def test_the_secret_is_encrypted_in_the_database():
    """A TOTP seed mints codes for ever. A dump of `userdb` alone must not
    hand over everybody's second factor."""
    enrol = ast.unparse(_function("second_factor_enrol"))
    assert "fernet.encrypt" in enrol

    read = ast.unparse(_function("_totp_secret_for"))
    assert "fernet.decrypt" in read


def test_the_column_is_sized_for_ciphertext():
    """Fernet output is a hundred-odd characters whatever the plaintext.
    Sizing a column for the value a human would read is how this codebase
    already lost a day of telemetry to "Data too long"."""
    source = (ROOT / "security" / "totp.py").read_text(encoding="utf-8")
    secrets_ddl = source[source.index("DDL_SECRETS"):source.index("DDL_RECOVERY")]
    assert "VARCHAR(512)" in secrets_ddl


def test_an_unreadable_secret_does_not_lock_the_account():
    """A changed Fernet key should mean "enrol again", not "you can never log
    in". Reported loudly, treated as absent."""
    body = ast.unparse(_function("_totp_secret_for"))
    assert "except Exception" in body
    assert "return (None, False)" in body or "return None, False" in body


# --------------------------------------------------------------------------
# Enrolment and removal
# --------------------------------------------------------------------------

def test_enrolment_is_not_complete_until_a_code_is_proved():
    """A secret written when the QR code is shown, with nothing confirming it,
    locks out everybody who scans it into an app they then delete."""
    enrol = ast.unparse(_function("second_factor_enrol"))
    assert "confirmed_at" in enrol and "NULL" in enrol

    confirm = ast.unparse(_function("second_factor_confirm"))
    assert "verify" in confirm
    assert "confirmed_at = NOW()" in confirm

    required = ast.unparse(_function("_totp_required"))
    assert "confirmed" in required, \
        "an unconfirmed enrolment would be enforced at the next login"


def test_re_enrolling_cannot_silently_replace_a_working_factor():
    enrol = ast.unparse(_function("second_factor_enrol"))
    assert "status=409" in enrol


def test_turning_it_off_needs_the_password():
    """A hijacked session must not be able to remove the control that would
    have stopped it."""
    body = ast.unparse(_function("second_factor_disable"))
    assert "bcrypt.checkpw" in body
    assert "TOTP_DISABLE_REFUSED" in body, "a failed attempt to disable is not reported"


def test_disabling_clears_the_recovery_codes_too():
    """Leaving them behind means the next enrolment inherits a list the user
    thinks is gone."""
    body = ast.unparse(_function("second_factor_disable"))
    assert "DELETE FROM user_recovery_codes" in body


# --------------------------------------------------------------------------
# It has to actually be importable
# --------------------------------------------------------------------------

def test_the_module_is_imported():
    """Every other test in this file reads the AST, which does not care
    whether a name resolves. The routes were spliced in without their import
    and every one of them passed while the live server answered

        [!] Unhandled Exception: name 'totp_store' is not defined

    with a 500 on the second half of every login. A test suite that parses
    but never runs the thing it is checking needs one assertion that closes
    that gap.
    """
    source = APP.read_text(encoding="utf-8")
    assert "import totp as totp_store" in source, \
        "app.py uses totp_store and never imports it"


def test_every_name_the_routes_use_is_defined():
    """The general form of the above, since the same splice could drop any
    helper. Compares what the 2FA handlers reference against what app.py
    defines and imports at module level."""
    import builtins

    tree = ast.parse(APP.read_text(encoding="utf-8"))
    defined = set(dir(builtins))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            defined.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            defined.update(a.asname or a.name.split(".")[0] for a in node.names)

    handlers = ("complete_second_factor", "second_factor_status",
                "second_factor_enrol", "second_factor_confirm",
                "second_factor_disable", "_begin_second_factor",
                "_totp_secret_for", "_totp_required", "_totp_tables")
    missing = set()
    for name in handlers:
        fn = _function(name)
        local = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
        for inner in ast.walk(fn):
            if isinstance(inner, ast.Name) and isinstance(inner.ctx, ast.Store):
                local.add(inner.id)
            elif isinstance(inner, (ast.AsyncWith, ast.With)):
                for item in inner.items:
                    if isinstance(item.optional_vars, ast.Name):
                        local.add(item.optional_vars.id)
            elif isinstance(inner, ast.comprehension) and isinstance(inner.target, ast.Name):
                local.add(inner.target.id)
            elif isinstance(inner, ast.ExceptHandler) and inner.name:
                # `except Exception as e` binds a name too. Missing it made
                # the scan report `e` as undefined - a gap in the detector
                # rather than in the code it was checking.
                local.add(inner.name)
        for inner in ast.walk(fn):
            if (isinstance(inner, ast.Name) and isinstance(inner.ctx, ast.Load)
                    and inner.id not in local and inner.id not in defined):
                missing.add(f"{name}: {inner.id}")

    assert not missing, f"names used and never defined: {sorted(missing)}"


# --------------------------------------------------------------------------
# Enrolment has to be usable
# --------------------------------------------------------------------------

FRONTEND = ROOT / "frontend" / "src"


def test_the_secret_is_offered_as_a_qr_code():
    """Typing a 32-character base32 key by hand is the kind of friction that
    decides whether a security control gets turned on at all. The first
    version skipped the dependency and made every operator do it."""
    page = (FRONTEND / "pages" / "AccountSecurity.tsx").read_text(encoding="utf-8")
    assert "QRCodeSVG" in page
    assert "enrolling.uri" in page, "the QR encodes something other than the otpauth URI"

    package = (ROOT / "frontend" / "package.json").read_text(encoding="utf-8")
    assert "qrcode.react" in package, "the component is imported and not declared"


def test_the_qr_is_drawn_on_a_light_ground():
    """A scanner needs dark modules on a light background. A code drawn in
    theme colours on a dark card reads perfectly to a human and not at all to
    a phone - and it fails silently, which is the worst way for this to be
    wrong."""
    page = (FRONTEND / "pages" / "AccountSecurity.tsx").read_text(encoding="utf-8")
    # Anchored on the element, not the name: the first occurrence of
    # "QRCodeSVG" is the import at the top of the file, so slicing back from
    # it found nothing and the test failed against correct markup.
    at = page.index("<QRCodeSVG")
    qr = page[max(0, at - 700):at + 260]
    assert "#ffffff" in qr or "#fff" in qr, \
        "the QR has no light plate behind it"


def test_manual_entry_survives_alongside_it():
    """A QR is useless on the machine you are already sitting at, and on a
    host with no camera. The key stays."""
    page = (FRONTEND / "pages" / "AccountSecurity.tsx").read_text(encoding="utf-8")
    assert "enrolling.secret" in page
    assert "TYPE THIS KEY" in page.upper()


# --------------------------------------------------------------------------
# Shipped and undocumented is the same drift, pointed the other way
# --------------------------------------------------------------------------

GUIDE = ROOT / "docs" / "production-deployment.md"


def _identity_section() -> str:
    text = GUIDE.read_text(encoding="utf-8")
    return text[text.index("## 6. Identity"):text.index("\n## 7.")]


def test_two_factor_is_in_the_operations_guide():
    """This whole body of work started from a guide describing three settings
    the code never read. A shipped feature the guide never mentions is the
    same drift with the sign flipped - and it is the one an operator hits when
    they need it at three in the morning."""
    section = _identity_section()
    assert "Two-factor" in section
    assert "My Security" in section, "the guide never says where to turn it on"


def test_the_guide_says_what_happens_when_recovery_codes_are_lost():
    """The question every operator eventually asks, and the one with no happy
    answer - any mechanism letting an administrator bypass somebody's second
    factor is a mechanism an attacker can use. Better said than discovered."""
    section = _identity_section()
    assert "cannot sign in" in section or "no support path" in section
    assert "user_totp" in section, "no documented way back at all"


def test_the_guide_warns_about_the_fernet_key():
    """Losing it takes every enrolled second factor with it. That is
    survivable and has to be planned for, not found out."""
    section = _identity_section()
    assert "Fernet" in section


def test_the_platform_event_kinds_are_documented():
    """A severity in a table nobody has a key for is a severity nobody acts
    on."""
    from core import self_defence

    section = _identity_section()
    for kind in self_defence.KINDS:
        assert kind in section, f"{kind} is raised and never explained in the guide"


def test_every_section_reference_resolves():
    """The renumbering that adding these sections required silently broke a
    forward reference the first time. A guide that points at a section that
    does not exist is worse than one that points at nothing."""
    import re

    text = GUIDE.read_text(encoding="utf-8")
    headings = set(re.findall(r"^#{2,3} (\d+(?:\.\d+)*)", text, re.M))
    referenced = set(re.findall(r"§(\d+(?:\.\d+)*)", text))
    dangling = sorted(r for r in referenced if r not in headings)
    assert not dangling, f"references to sections that do not exist: {dangling}"
