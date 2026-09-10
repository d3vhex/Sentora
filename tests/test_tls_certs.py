"""TLS material must be generated, never shipped.

A working `certs/server.key` and `certs/rootCA.key` were committed. That gives
every deployment the same TLS identity and publishes it: anyone who has ever
cloned the repository holds the private key, so the certificate proves nothing
about who is on the other end of the connection.

Generating on first boot gives each install its own key, and the key never
exists anywhere except the machine that made it.
"""
from __future__ import annotations

import hashlib
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_generation_is_idempotent(tmp_path):
    """Regenerating on every boot would invalidate live sessions."""
    from certs.generate_certs import ensure_certs

    first = ensure_certs(outdir=str(tmp_path), cn="test.local", days=30, log=lambda *_: None)
    digest = hashlib.sha256(pathlib.Path(first["key"]).read_bytes()).hexdigest()

    second = ensure_certs(outdir=str(tmp_path), cn="test.local", days=30, log=lambda *_: None)
    assert hashlib.sha256(pathlib.Path(second["key"]).read_bytes()).hexdigest() == digest


def test_force_replaces_the_key(tmp_path):
    from certs.generate_certs import ensure_certs

    first = ensure_certs(outdir=str(tmp_path), cn="test.local", days=30, log=lambda *_: None)
    digest = hashlib.sha256(pathlib.Path(first["key"]).read_bytes()).hexdigest()

    second = ensure_certs(outdir=str(tmp_path), cn="test.local", days=30,
                          force=True, log=lambda *_: None)
    assert hashlib.sha256(pathlib.Path(second["key"]).read_bytes()).hexdigest() != digest


def test_two_deployments_do_not_share_a_key(tmp_path):
    """The whole point. Same inputs, different key material."""
    from certs.generate_certs import ensure_certs

    a = ensure_certs(outdir=str(tmp_path / "a"), cn="same.local", days=30, log=lambda *_: None)
    b = ensure_certs(outdir=str(tmp_path / "b"), cn="same.local", days=30, log=lambda *_: None)
    assert pathlib.Path(a["key"]).read_bytes() != pathlib.Path(b["key"]).read_bytes()


def test_the_certificate_is_usable(tmp_path):
    from cryptography import x509

    from certs.generate_certs import ensure_certs

    paths = ensure_certs(outdir=str(tmp_path), cn="sentora.example", days=30,
                         log=lambda *_: None)
    cert = x509.load_pem_x509_certificate(pathlib.Path(paths["crt"]).read_bytes())

    assert "sentora.example" in cert.subject.rfc4514_string()
    assert "Sentora-Local-RootCA" in cert.issuer.rfc4514_string()

    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert "sentora.example" in san
    # Without this the local console warns on every page load.
    assert "localhost" in san


def test_gitignore_covers_generated_material():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in ("certs/*.key", "certs/*.crt"):
        assert pattern in text, f"{pattern} is not ignored"


def test_no_private_key_is_tracked():
    """The check that actually matters, run against git rather than the disk.

    Ignoring a path does nothing to a file that is already tracked, which is
    the trap: adding the .gitignore entry feels like the fix and changes
    nothing until `git rm --cached` follows it.
    """
    out = subprocess.run(["git", "ls-files", "certs/"],
                         cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        pytest.skip("not a git checkout")

    tracked = [f for f in out.stdout.split() if f.endswith((".key", ".pem"))]
    assert not tracked, (
        "private keys are still tracked: " + ", ".join(tracked)
        + "\nRun: git rm --cached " + " ".join(tracked)
    )


# --------------------------------------------------------------------------
# Which names the certificate answers to
# --------------------------------------------------------------------------

def _names(path):
    from cryptography import x509

    from certs.generate_certs import certificate_names

    return certificate_names(x509.load_pem_x509_certificate(pathlib.Path(path).read_bytes()))


def test_localhost_is_always_covered(tmp_path):
    """The first login and every health check happen on the machine itself."""
    from certs.generate_certs import ensure_certs

    paths = ensure_certs(outdir=str(tmp_path), cn="sentora.example.local",
                         days=30, log=lambda *_: None)
    covered = _names(paths["crt"])
    assert "localhost" in covered
    assert "127.0.0.1" in covered
    assert "sentora.example.local" in covered


def test_an_address_becomes_an_ip_san_not_a_dns_name(tmp_path):
    """A hostname entry holding an address produces a certificate that matches
    nothing: clients compare IP SANs against the address they dialled and DNS
    SANs against the name, and never one against the other."""
    from cryptography import x509

    from certs.generate_certs import ensure_certs

    paths = ensure_certs(outdir=str(tmp_path), cn="sentora.example.local", days=30,
                         log=lambda *_: None, extra_names=["192.168.1.26"])
    cert = x509.load_pem_x509_certificate(pathlib.Path(paths["crt"]).read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value

    assert "192.168.1.26" not in san.get_values_for_type(x509.DNSName)
    assert "192.168.1.26" in {str(i) for i in san.get_values_for_type(x509.IPAddress)}


def test_a_name_is_never_listed_twice(tmp_path):
    """`DNS:localhost, DNS:localhost` is what the shipped certificate carried:
    the SAN was `[cn, "localhost"]` and the default cn is `localhost`."""
    from cryptography import x509

    from certs.generate_certs import ensure_certs

    paths = ensure_certs(outdir=str(tmp_path), cn="localhost", days=30,
                         log=lambda *_: None, extra_names=["localhost", "127.0.0.1"])
    cert = x509.load_pem_x509_certificate(pathlib.Path(paths["crt"]).read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = san.get_values_for_type(x509.DNSName)
    assert len(dns) == len(set(dns)), dns


def test_a_hostname_can_be_added_at_all(tmp_path):
    """The point of the exercise. WebAuthn's RP ID must be a domain - browsers
    reject an IP address - so a console reachable only at an address is a
    console no security key can ever be registered against."""
    from certs.generate_certs import ensure_certs

    paths = ensure_certs(outdir=str(tmp_path), cn="localhost", days=30,
                         log=lambda *_: None, extra_names=["sentora.corp.local"])
    assert "sentora.corp.local" in _names(paths["crt"])


def test_a_stale_certificate_is_reported_rather_than_regenerated(tmp_path, capsys):
    """Generation is idempotent, so changing TLS_CN on a deployment that
    already has a certificate does nothing at all. That is the correct
    behaviour - a new identity on every restart would break every agent that
    pinned the CA - but it used to happen in silence, and the operator was left
    with a name mismatch and no explanation."""
    from certs.generate_certs import ensure_certs
    from core import tls

    ensure_certs(outdir=str(tmp_path), cn="localhost", days=30, log=lambda *_: None)

    lines: list[str] = []
    tls._warn_if_names_are_stale(str(tmp_path / "server.crt"),
                                 "sentora.corp.local", ["10.0.0.5"], lines.append)
    said = " ".join(lines)
    assert "sentora.corp.local" in said
    assert "10.0.0.5" in said
    assert "--force" in said, "the message has to say how to fix it"


def test_nothing_is_said_when_the_names_already_match(tmp_path):
    from certs.generate_certs import ensure_certs
    from core import tls

    ensure_certs(outdir=str(tmp_path), cn="sentora.corp.local", days=30,
                 log=lambda *_: None, extra_names=["10.0.0.5"])

    lines: list[str] = []
    tls._warn_if_names_are_stale(str(tmp_path / "server.crt"),
                                 "sentora.corp.local", ["10.0.0.5"], lines.append)
    assert lines == []


def test_the_generator_takes_the_names_from_the_environment():
    """`TLS_SAN` has to reach the generator, or setting it is a no-op that
    looks like a setting."""
    import ast

    src = (ROOT / "core" / "tls.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == "_generate")
    body = ast.unparse(fn)
    assert "TLS_SAN" in body
    assert "extra_names" in body, "read but never passed on"


def test_a_check_that_cannot_run_says_so(tmp_path):
    """The first version of this returned on any exception, so an unreadable
    certificate produced exactly the same output as a certificate whose names
    all matched: nothing. A check that silently does nothing is worse than no
    check, because it reads as a pass."""
    from core import tls

    lines: list[str] = []
    tls._warn_if_names_are_stale(str(tmp_path / "absent.crt"),
                                 "sentora.corp.local", [], lines.append)
    said = " ".join(lines)
    assert said, "the check vanished without a word"
    assert "absent.crt" in said
