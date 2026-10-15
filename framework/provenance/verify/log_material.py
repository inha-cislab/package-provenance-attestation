from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"

DIGEST_ALGORITHMS = {
    "sha256": "SHA2_256",
    "sha384": "SHA2_384",
    "sha512": "SHA2_512",
}

STATEMENT_KINDS = ("intoto", "dsse")

@dataclass
class Material:

    bundle: Optional[dict] = None
    statement: Optional[dict] = None
    signed_digest: Dict[str, str] = field(default_factory=dict)
    certified: bool = False
    missing: str = ""

    @property
    def usable(self) -> bool:
        return self.bundle is not None

def _b64_of_hex(value: str) -> str:
    return base64.b64encode(bytes.fromhex(value)).decode()

def _decode(value: Optional[str]) -> bytes:
    text = value or ""
    return base64.b64decode(text + "=" * (-len(text) % 4))

def _certificate_der(material: bytes):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    text = material.lstrip()
    if text.startswith(b"-----BEGIN CERTIFICATE"):
        certificate = x509.load_pem_x509_certificate(material)
    elif text.startswith(b"-----BEGIN"):
        return None
    else:
        try:
            certificate = x509.load_der_x509_certificate(material)
        except Exception:
            return None
    return certificate.public_bytes(Encoding.DER)

def _tlog_entry(entry) -> Optional[dict]:
    raw = entry.raw or {}
    verification = raw.get("verification") or {}
    proof = verification.get("inclusionProof") or {}
    if not proof.get("checkpoint") or not proof.get("rootHash"):
        return None
    if raw.get("logIndex") is None or not raw.get("logID"):
        return None

    record = {
        "logIndex": str(raw["logIndex"]),
        "logId": {"keyId": _b64_of_hex(raw["logID"])},
        "kindVersion": {"kind": entry.kind, "version": entry.api_version},
        "integratedTime": str(raw.get("integratedTime") or 0),
        "inclusionProof": {
            "logIndex": str(proof.get("logIndex", raw["logIndex"])),
            "rootHash": _b64_of_hex(proof["rootHash"]),
            "treeSize": str(proof.get("treeSize", 0)),
            "hashes": [_b64_of_hex(h) for h in proof.get("hashes") or []],
            "checkpoint": {"envelope": proof["checkpoint"]},
        },
        "canonicalizedBody": raw.get("body", ""),
    }
    promise = verification.get("signedEntryTimestamp")
    if promise:
        record["inclusionPromise"] = {"signedEntryTimestamp": promise}
    return record

def _signing_material(entry) -> Optional[bytes]:
    spec = entry.spec
    holder = (spec.get("signature") or {}).get("publicKey") or spec.get("publicKey")
    if isinstance(holder, dict) and holder.get("content"):
        return _decode(holder["content"])
    if isinstance(holder, str) and holder:
        return _decode(holder)

    envelope = (spec.get("content") or {}).get("envelope") or {}
    for signature in envelope.get("signatures") or []:
        for key in ("publicKey", "verifier"):
            if signature.get(key):
                return _decode(signature[key])
    for signature in spec.get("signatures") or []:
        if signature.get("verifier"):
            return _decode(signature["verifier"])
    return None

def _hashedrekord(entry, tlog, der) -> Material:
    spec = entry.spec
    recorded = (spec.get("data") or {}).get("hash") or {}
    algorithm = str(recorded.get("algorithm", "")).lower()
    value = recorded.get("value")
    signature = (spec.get("signature") or {}).get("content")
    if not (algorithm in DIGEST_ALGORITHMS and value and signature):
        return Material(missing="entry body records no signed digest")

    bundle = {
        "mediaType": BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(der).decode()},
            "tlogEntries": [tlog],
        },
        "messageSignature": {
            "messageDigest": {"algorithm": DIGEST_ALGORITHMS[algorithm],
                              "digest": _b64_of_hex(str(value))},
            "signature": signature,
        },
    }
    return Material(bundle=bundle, signed_digest={algorithm: str(value).lower()},
                    certified=True)

def _statement_bytes(entry) -> Optional[bytes]:
    attestation = (entry.raw or {}).get("attestation") or {}
    data = attestation.get("data")
    if not data:
        return None
    if isinstance(data, str):
        try:
            return _decode(data)
        except Exception:
            return data.encode()
    return None

def _envelope(entry, payload: bytes) -> Optional[dict]:
    spec = entry.spec
    content = (spec.get("content") or {}).get("envelope") or {}
    signatures = content.get("signatures") or spec.get("signatures") or []
    rebuilt = []
    for signature in signatures:
        sig = signature.get("sig") or signature.get("signature")
        if not sig:
            return None
        rebuilt.append({"sig": sig})
    if not rebuilt:
        return None
    payload_type = content.get("payloadType") or "application/vnd.in-toto+json"
    return {"payload": base64.b64encode(payload).decode(),
            "payloadType": payload_type, "signatures": rebuilt}

def _statement_entry(entry, tlog, der) -> Material:
    payload = _statement_bytes(entry)
    if payload is None:
        return Material(
            missing="the log stores this entry's payload hash and not its "
                    "payload, so the statement cannot be recovered from the log")
    envelope = _envelope(entry, payload)
    if envelope is None:
        return Material(missing="entry body records no envelope signature")
    try:
        statement = json.loads(payload)
    except ValueError:
        return Material(missing="the stored payload is not a JSON statement")

    bundle = {
        "mediaType": BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(der).decode()},
            "tlogEntries": [tlog],
        },
        "dsseEnvelope": envelope,
    }
    return Material(bundle=bundle, statement=statement, certified=True)

def material_for(entry) -> Material:
    if entry.kind not in ("hashedrekord",) + STATEMENT_KINDS:
        return Material(missing=f"unsupported entry kind {entry.kind}")

    tlog = _tlog_entry(entry)
    if tlog is None:
        return Material(missing="the entry carries no checkpointed inclusion proof")

    signing = _signing_material(entry)
    if signing is None:
        return Material(missing="the entry carries no signing material")
    der = _certificate_der(signing)
    if der is None:
        return Material(
            missing="the entry is signed with a bare key rather than a "
                    "certificate, so no identity can be established")

    if entry.kind == "hashedrekord":
        return _hashedrekord(entry, tlog, der)
    return _statement_entry(entry, tlog, der)

def carries_certificate(bundle: Any) -> bool:
    material = (bundle or {}).get("verificationMaterial") or {}
    if material.get("certificate") or material.get("x509CertificateChain"):
        return True
    return False

def index_bundles(bundles: List[dict]) -> Dict[int, dict]:
    indexed: Dict[int, dict] = {}
    for bundle in bundles or []:
        material = (bundle or {}).get("verificationMaterial") or {}
        for tlog in material.get("tlogEntries") or []:
            try:
                indexed[int(tlog["logIndex"])] = bundle
            except (KeyError, TypeError, ValueError):
                continue
    return indexed

def bundle_from_registry(bundle_json: Any) -> Material:
    if not isinstance(bundle_json, dict):
        return Material(missing="the registry returned no bundle")
    statement = None
    envelope = bundle_json.get("dsseEnvelope") or {}
    payload = envelope.get("payload")
    if payload:
        try:
            statement = json.loads(_decode(payload))
        except Exception:
            statement = None
    return Material(bundle=bundle_json, statement=statement, certified=True)
