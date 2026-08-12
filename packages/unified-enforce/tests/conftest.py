"""Shared test fixtures for unified-enforce.

The PKI helpers live here because both the unit mTLS tests and the real-Envoy
integration suite need the same throwaway certificate chain. Certificates are
generated per-run rather than checked in: fixtures with embedded private keys
age into secret-scanner noise, and a one-day validity window keeps a stray copy
useless.
"""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _window() -> tuple[datetime.datetime, datetime.datetime]:
    now = datetime.datetime.now(datetime.UTC)
    return now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=1)


def make_ca(cn: str = "unified-test-ca"):
    """Returns (key, cert) for a self-signed CA."""
    key = ec.generate_private_key(ec.SECP256R1())
    start, end = _window()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue(ca_key, ca_cert, cn: str, *, dns: str | list[str] | None = None) -> tuple[bytes, bytes]:
    """Issue a leaf cert from `ca_key`. Returns (key_pem, cert_pem)."""
    key = ec.generate_private_key(ec.SECP256R1())
    start, end = _window()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if dns:
        names = [dns] if isinstance(dns, str) else dns
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key_pem, cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="session")
def pki() -> dict[str, object]:
    """A CA, a server cert, a client cert, and a cert from an untrusted CA.

    The server SAN covers both the name Envoy's template pins (`unified-enforce`)
    and `localhost`, so the same material serves the in-process gRPC tests and
    the containerised Envoy.
    """
    ca_key, ca_cert = make_ca()
    rogue_ca_key, rogue_ca_cert = make_ca("rogue-ca")
    return {
        "ca": ca_cert.public_bytes(serialization.Encoding.PEM),
        "server": issue(ca_key, ca_cert, "unified-enforce", dns=["unified-enforce", "localhost"]),
        "client": issue(ca_key, ca_cert, "envoy-sidecar", dns="localhost"),
        # A perfectly valid certificate issued by someone we never trusted —
        # the realistic attack, rather than a malformed cert.
        "rogue": issue(rogue_ca_key, rogue_ca_cert, "rogue", dns="localhost"),
    }
