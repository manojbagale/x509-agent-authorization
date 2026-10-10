from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

# Lab-only OID used for this prototype. It is not claimed as an assigned enterprise OID.
AGENT_AUTHZ_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")
TRUST_DOMAIN = "seminar.fisk.edu"
AGENT_URI = f"spiffe://{TRUST_DOMAIN}/agent/research-agent-01"


def _der_utf8_string(value: str) -> bytes:
    """Encode a short UTF-8 string as DER UTF8String for the lab extension."""
    data = value.encode("utf-8")
    n = len(data)
    if n < 128:
        length = bytes([n])
    elif n < 256:
        length = b"\x81" + bytes([n])
    else:
        length = b"\x82" + n.to_bytes(2, "big")
    return b"\x0c" + length + data


def _decode_der_utf8_string(data: bytes) -> str:
    """Decode exactly one minimally encoded DER UTF8String."""
    if not isinstance(data, bytes) or len(data) < 2 or data[0] != 0x0C:
        raise ValueError("custom extension is not a DER UTF8String")
    first = data[1]
    if first < 128:
        length, offset = first, 2
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or len(data) < 2 + count:
            raise ValueError("invalid DER length")
        encoded_length = data[2:2 + count]
        if encoded_length[0] == 0:
            raise ValueError("non-minimal DER length")
        length = int.from_bytes(encoded_length, "big")
        if length < 128:
            raise ValueError("non-minimal DER length")
        offset = 2 + count
    if len(data) != offset + length:
        raise ValueError("truncated DER UTF8String or trailing data")
    try:
        return data[offset:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 extension") from exc


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def encode_agent_extension(payload: dict[str, Any]) -> bytes:
    # This lab encoding is deliberately simple. A production profile would
    # define and version a proper interoperable ASN.1/CBOR/other schema.
    return _der_utf8_string(canonical_json(payload))


def decode_agent_extension(raw: bytes) -> dict[str, Any]:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    payload = json.loads(_decode_der_utf8_string(raw), object_pairs_hook=unique_object)
    if not isinstance(payload, dict):
        raise ValueError("authorization extension must contain a JSON object")
    return payload


@dataclass
class IssuedCertificate:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


@dataclass
class ResearchCA:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @classmethod
    def create(cls) -> "ResearchCA":
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Senior Seminar Research Root CA")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        return cls(cert=cert, key=key)

    def issue_agent(
        self,
        *,
        mode: str,
        permissions: list[dict[str, Any]] | None = None,
        policy_id: str | None = None,
        max_permissions: list[dict[str, Any]] | None = None,
        lifetime_minutes: int = 15,
        backdate_minutes: int = 1,
        extension_critical: bool = False,
        agent_uri: str = AGENT_URI,
        extra_uri_sans: list[str] | None = None,
    ) -> IssuedCertificate:
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc)
        uri_sans = [x509.UniformResourceIdentifier(agent_uri)]
        for value in extra_uri_sans or []:
            uri_sans.append(x509.UniformResourceIdentifier(value))

        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=backdate_minutes))
            .not_valid_after(now + dt.timedelta(minutes=lifetime_minutes))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
            # RFC 5280 requires SAN to be critical when the Subject is empty.
            .add_extension(x509.SubjectAlternativeName(uri_sans), critical=True)
        )

        if mode == "certificate":
            payload = {"version": 1, "mode": "certificate", "permissions": permissions or []}
            builder = builder.add_extension(
                x509.UnrecognizedExtension(AGENT_AUTHZ_OID, encode_agent_extension(payload)),
                critical=extension_critical,
            )
        elif mode == "hybrid":
            payload = {"version": 1, "mode": "hybrid", "policy_id": policy_id or "research-policy-v1"}
            builder = builder.add_extension(
                x509.UnrecognizedExtension(AGENT_AUTHZ_OID, encode_agent_extension(payload)),
                critical=extension_critical,
            )
        elif mode == "hybrid_ceiling":
            payload = {
                "version": 1,
                "mode": "hybrid_ceiling",
                "policy_id": policy_id or "research-policy-v1",
                "max_permissions": max_permissions if max_permissions is not None else (
                    permissions if permissions is not None else []
                ),
            }
            builder = builder.add_extension(
                x509.UnrecognizedExtension(AGENT_AUTHZ_OID, encode_agent_extension(payload)),
                critical=extension_critical,
            )
        elif mode != "external":
            raise ValueError(f"unknown mode: {mode}")

        cert = builder.sign(self.key, hashes.SHA256())
        return IssuedCertificate(cert=cert, key=key)

    def issue_server(self, *, dns_name: str = "localhost", lifetime_minutes: int = 60) -> IssuedCertificate:
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(minutes=lifetime_minutes))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        return IssuedCertificate(cert=cert, key=key)
