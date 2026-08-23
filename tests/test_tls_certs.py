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
