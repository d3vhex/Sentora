
import argparse
import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def write_pem(path: str, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def generate_root_ca(common_name: str, days: int):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Sentora Dev"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert


def generate_server_cert(cn: str, days: int, ca_key, ca_cert):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Sentora Dev"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    now = datetime.utcnow()

    san = x509.SubjectAlternativeName([
        x509.DNSName(cn),
        x509.DNSName("localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(san, critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    return key, cert


def main():
    parser = argparse.ArgumentParser(description="Generate a Root CA and a server certificate (beginner style)")
    parser.add_argument("--cn", default="localhost", help="Server certificate Common Name (default: localhost)")
    parser.add_argument("--days", type=int, default=365, help="Validity in days (default: 365)")
    parser.add_argument("--out", default=os.path.dirname(__file__) or ".", help="Output directory (default: certs folder)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files if present")
    args = parser.parse_args()

    outdir = args.out
    os.makedirs(outdir, exist_ok=True)

    root_key_path = os.path.join(outdir, "rootCA.key")
    root_crt_path = os.path.join(outdir, "rootCA.crt")
    srv_key_path = os.path.join(outdir, "server.key")
    srv_crt_path = os.path.join(outdir, "server.crt")
    fullchain_path = os.path.join(outdir, "server-fullchain.crt")

    if not args.force and all(os.path.exists(p) for p in [root_key_path, root_crt_path, srv_key_path, srv_crt_path]):
        print("[i] All certificate files already exist. Use --force to overwrite.")
        print(f"    {root_key_path}\n    {root_crt_path}\n    {srv_key_path}\n    {srv_crt_path}")
        return

    print("[i] Generating Root CA …")
    ca_key, ca_cert = generate_root_ca(common_name="Sentora-Local-RootCA", days=args.days * 5)

    write_pem(
        root_key_path,
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    write_pem(root_crt_path, ca_cert.public_bytes(serialization.Encoding.PEM))

    print("[i] Generating server certificate …")
    srv_key, srv_cert = generate_server_cert(args.cn, args.days, ca_key, ca_cert)
    write_pem(
        srv_key_path,
        srv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    write_pem(srv_crt_path, srv_cert.public_bytes(serialization.Encoding.PEM))

    write_pem(
        fullchain_path,
        srv_cert.public_bytes(serialization.Encoding.PEM) + b"\n" + ca_cert.public_bytes(serialization.Encoding.PEM),
    )

    print("[+] Done.")
    print(f"    Root CA:   {root_crt_path} (key: {root_key_path})")
    print(f"    Server:    {srv_crt_path} (key: {srv_key_path})")
    print(f"    Fullchain: {fullchain_path}")
    print("\nNext steps (PowerShell):")
    print("  $env:TLS_ENABLED=\"1\"")
    print(f"  $env:TLS_CERT=\"{srv_crt_path}\"")
    print(f"  $env:TLS_KEY=\"{srv_key_path}\"")
    print("  python app.py   # listens on 8443 by default when TLS is on")


if __name__ == "__main__":
    main()
