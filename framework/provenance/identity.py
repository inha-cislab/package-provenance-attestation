from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

ISSUER_OID_V1 = "1.3.6.1.4.1.57264.1.1"
ISSUER_OID_V2 = "1.3.6.1.4.1.57264.1.8"

BUILD_OIDS = {
    "1.3.6.1.4.1.57264.1.12": "source_repository",
    "1.3.6.1.4.1.57264.1.13": "source_digest",
    "1.3.6.1.4.1.57264.1.14": "source_ref",
    "1.3.6.1.4.1.57264.1.18": "build_config",
    "1.3.6.1.4.1.57264.1.11": "runner",
    "1.3.6.1.4.1.57264.1.21": "run_invocation",
}

GITHUB_ACTIONS = "https://token.actions.githubusercontent.com"
GITLAB_CI = "https://gitlab.com"
GOOGLE = "https://accounts.google.com"

PEM_KEY_PREFIX = b"-----BEGIN PUBLIC KEY"
PEM_CERT_PREFIX = b"-----BEGIN CERTIFICATE"

@dataclass(frozen=True)
class Identity:
    subject: str = ""
    issuer: str = ""
    key_fingerprint: str = ""
    build: Dict[str, str] = field(default_factory=dict)

    @property
    def describes_build(self) -> bool:
        return bool(self.build.get("source_repository")
                    or self.build.get("build_config"))

    @property
    def is_certificate(self) -> bool:
        return bool(self.subject or self.issuer)

    @property
    def repository(self) -> str:
        return repository_in(self.subject)

    @property
    def owner(self) -> str:
        repository = self.repository
        return repository.split("/")[0].lower() if repository else ""

def parse(material: str) -> Identity:
    try:
        raw = base64.b64decode(material)
    except Exception:
        return Identity()

    if raw.lstrip().startswith(PEM_KEY_PREFIX):
        return Identity(key_fingerprint=fingerprint(raw))

    certificate = _load_certificate(raw)
    if certificate is None:
        return Identity()
    return Identity(subject=_subject_of(certificate),
                    issuer=_issuer_of(certificate),
                    build=_build_of(certificate))

def repository_in(value: str) -> str:
    match = re.search(r"(?:github|gitlab)\.com[:/]+([^/]+)/([^/#?@]+)",
                      str(value or ""))
    if not match:
        return ""
    name = match.group(2)
    return f"{match.group(1)}/{name[:-4] if name.endswith('.git') else name}"

def fingerprint(raw: bytes) -> str:
    der = normalise_public_key(raw)
    if der is None:
        return ""
    import hashlib

    return hashlib.sha256(der).hexdigest()[:16]

def normalise_public_key(raw: bytes) -> Optional[bytes]:
    if not raw.lstrip().startswith(PEM_KEY_PREFIX):
        return None
    try:
        key = load_pem_public_key(raw)
    except Exception:
        return None
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def matches_known_key(material: str, known: Dict[bytes, str]) -> Optional[str]:
    try:
        raw = base64.b64decode(material)
    except Exception:
        return None
    der = normalise_public_key(raw)
    return known.get(der) if der is not None else None

DER_STRING_TAGS = (0x0C, 0x16, 0x13, 0x1E)

def _der_string(raw: bytes) -> bytes:
    if len(raw) < 2 or raw[0] not in DER_STRING_TAGS:
        return raw
    length, body = raw[1], raw[2:]
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or len(body) < count:
            return raw
        length = int.from_bytes(body[:count], "big")
        body = body[count:]
    return body[:length] if len(body) >= length else raw

def _build_of(certificate: x509.Certificate) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for oid, name in BUILD_OIDS.items():
        try:
            raw = certificate.extensions.get_extension_for_oid(
                x509.ObjectIdentifier(oid)).value.value
        except Exception:
            continue
        found[name] = _der_string(raw).decode("utf-8", "replace").strip()
    return found

def _load_certificate(raw: bytes) -> Optional[x509.Certificate]:
    try:
        if raw.lstrip().startswith(PEM_CERT_PREFIX):
            return x509.load_pem_x509_certificate(raw)
        return x509.load_der_x509_certificate(raw)
    except Exception:
        return None

def _subject_of(certificate: x509.Certificate) -> str:
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except Exception:
        return ""
    names = extension.get_values_for_type(x509.UniformResourceIdentifier)
    names += extension.get_values_for_type(x509.RFC822Name)
    return names[0] if names else ""

def _issuer_of(certificate: x509.Certificate) -> str:
    for oid in (ISSUER_OID_V2, ISSUER_OID_V1):
        try:
            raw = certificate.extensions.get_extension_for_oid(
                x509.ObjectIdentifier(oid)
            ).value.value
        except Exception:
            continue
        text = raw.decode("utf-8", "replace")
        start = text.find("https://")
        return text[start:] if start >= 0 else text.strip()
    return ""
