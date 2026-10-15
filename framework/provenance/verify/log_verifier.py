from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

INTOTO_KIND = "intoto"
INTOTO_VERSION = "0.0.2"

@dataclass
class BundleVerification:
    verified: bool
    subject_matches: bool
    outcome: str
    entry_kind: str = ""
    subject_digests: Dict[str, List[str]] = field(default_factory=dict)
    subjects: int = 0
    detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)

class LogVerifier:
    def __init__(self, *, allow_intoto: bool = True) -> None:
        self._allow_intoto = allow_intoto
        self._verifier = None

    def verify_bundle(
        self,
        bundle_json: Any,
        *,
        artifact_digests: Dict[str, str],
        expected_repository: str = "",
    ) -> BundleVerification:
        from sigstore.models import Bundle
        from sigstore.verify import policy

        try:
            bundle = Bundle.from_json(json.dumps(bundle_json).encode())
        except Exception as error:
            return BundleVerification(False, False, "unreadable bundle", detail=str(error))

        kind = _kind_of(bundle)
        signed = _message_digest(bundle_json)
        if signed:
            return self._verify_signed_digest(
                bundle, bundle_json, signed, kind, artifact_digests,
                expected_repository)

        try:
            _, payload = self._verifier_for(kind).verify_dsse(
                bundle, policy.UnsafeNoOp()
            )
        except Exception as error:
            return BundleVerification(
                False, False, "verification failed", entry_kind=kind, detail=str(error)
            )

        statement = json.loads(payload)
        subjects = _subject_digests(statement)
        matches = any(
            value.lower() in subjects.get(algorithm, [])
            for algorithm, value in artifact_digests.items()
        )
        if not matches:
            return BundleVerification(
                True, False, "subject mismatch", entry_kind=kind,
                subject_digests=subjects,
                subjects=sum(len(v) for v in subjects.values()),
                detail="the bundle verifies but describes different bytes",
            )

        if expected_repository:
            if not self._policy_holds(bundle, expected_repository, kind):
                return BundleVerification(
                    True, True, "policy refused", entry_kind=kind,
                    subject_digests=subjects,
                    subjects=sum(len(v) for v in subjects.values()),
                    detail=f"certificate does not name {expected_repository}",
                )

        return BundleVerification(
            True, True, "verified", entry_kind=kind, subject_digests=subjects,
            subjects=sum(len(v) for v in subjects.values()),
        )

    def _verify_signed_digest(self, bundle, bundle_json, signed, kind,
                              artifact_digests, expected_repository):
        from sigstore.hashes import Hashed

        algorithm, value = signed
        try:
            self._verifier_for(kind).verify_artifact(
                Hashed(digest=bytes.fromhex(value),
                       algorithm=_hash_algorithm(algorithm)),
                bundle, _no_op_policy())
        except Exception as error:
            return BundleVerification(
                False, False, "verification failed", entry_kind=kind,
                detail=str(error))

        subjects = {algorithm: [value]}
        matches = any(str(other).lower() == value
                      for name, other in artifact_digests.items()
                      if name == algorithm)
        if not matches:
            return BundleVerification(
                True, False, "subject mismatch", entry_kind=kind,
                subject_digests=subjects, subjects=1,
                detail="the signature verifies over a different digest")

        outcome = "verified"
        if expected_repository and not self._policy_holds(
                bundle, expected_repository, kind, signed=signed):
            outcome = "policy refused"
        return BundleVerification(
            True, True, outcome, entry_kind=kind, subject_digests=subjects,
            subjects=1,
            detail="" if outcome == "verified"
            else f"certificate does not name {expected_repository}")

    def _policy_holds(self, bundle, repository: str, kind: str, signed=None) -> bool:
        from sigstore.verify import policy
        from ..identity import GITHUB_ACTIONS

        candidate = policy.AllOf(
            [
                policy.OIDCIssuer(GITHUB_ACTIONS),
                policy.GitHubWorkflowRepository(repository),
            ]
        )
        try:
            if signed:
                from sigstore.hashes import Hashed

                algorithm, value = signed
                self._verifier_for(kind).verify_artifact(
                    Hashed(digest=bytes.fromhex(value),
                           algorithm=_hash_algorithm(algorithm)),
                    bundle, candidate)
            else:
                self._verifier_for(kind).verify_dsse(bundle, candidate)
            return True
        except Exception:
            return False

    def _verifier_for(self, kind: str):
        if self._verifier is None:
            self._verifier = _build_verifier(self._allow_intoto)
        return self._verifier

def _no_op_policy():
    from sigstore.verify import policy

    return policy.UnsafeNoOp()

def _hash_algorithm(name: str):
    from sigstore.hashes import HashAlgorithm

    return {"sha256": HashAlgorithm.SHA2_256,
            "sha384": HashAlgorithm.SHA2_384,
            "sha512": HashAlgorithm.SHA2_512}[name]

NAMED_DIGESTS = {"SHA2_256": "sha256", "SHA2_384": "sha384",
                 "SHA2_512": "sha512"}

def _message_digest(bundle_json):
    if not isinstance(bundle_json, dict):
        return None
    recorded = ((bundle_json.get("messageSignature") or {})
                .get("messageDigest") or {})
    algorithm = NAMED_DIGESTS.get(recorded.get("algorithm", ""))
    raw = recorded.get("digest")
    if not algorithm or not raw:
        return None
    import base64

    return algorithm, base64.b64decode(raw).hex()

def _kind_of(bundle) -> str:
    inner = getattr(bundle.log_entry, "_inner", None)
    version = getattr(inner, "kind_version", None)
    if version is None:
        return ""
    return f"{version.kind}/{version.version}"

def _subject_digests(statement: Dict[str, Any]) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {}
    for subject in statement.get("subject") or []:
        for algorithm, value in (subject.get("digest") or {}).items():
            found.setdefault(algorithm, []).append(str(value).lower())
    return found

def _build_verifier(allow_intoto: bool):
    import base64
    import hashlib
    from datetime import datetime, timezone

    from cryptography import x509
    from sigstore import dsse
    from sigstore.verify import Verifier
    from sigstore.verify.verifier import (
        TimestampSource,
        TimestampVerificationResult,
    )

    def production():
        try:
            return Verifier.production()
        except Exception:
            return Verifier.production(offline=True)

    if not allow_intoto:
        return production()

    class ExtendedVerifier(Verifier):
        def _establish_time(self, bundle):
            inner = bundle.log_entry._inner
            version = inner.kind_version
            supported = version and (
                version.kind in ("dsse", "hashedrekord") and version.version == "0.0.1"
            )
            if supported or not inner.integrated_time or not inner.inclusion_promise:
                return super()._establish_time(bundle)

            proof = inner.inclusion_proof
            if not proof or not proof.checkpoint or not proof.checkpoint.envelope:
                raise ValueError(
                    "integrated time offered without a checkpointed inclusion proof"
                )

            results = []
            if bundle.verification_material.timestamp_verification_data:
                results.extend(self._verify_timestamp_authority(bundle))
            results.append(
                TimestampVerificationResult(
                    source=TimestampSource.TRANSPARENCY_SERVICE,
                    time=datetime.fromtimestamp(
                        inner.integrated_time, tz=timezone.utc
                    ),
                )
            )
            return results

        def verify_dsse(self, bundle, verification_policy):
            inner = bundle.log_entry._inner
            version = inner.kind_version
            if not (
                version
                and version.kind == INTOTO_KIND
                and version.version == INTOTO_VERSION
            ):
                return super().verify_dsse(bundle, verification_policy)

            self._verify_common_signing_cert(bundle, verification_policy)

            envelope = bundle._dsse_envelope
            if envelope is None:
                raise ValueError("bundle carries no DSSE envelope")
            dsse._verify(bundle.signing_certificate.public_key(), envelope)
            _check_intoto_body(bundle, x509, base64, hashlib)
            inner_envelope = envelope._inner
            return inner_envelope.payload_type, inner_envelope.payload

    try:
        return ExtendedVerifier.production()
    except Exception:
        return ExtendedVerifier.production(offline=True)

def _check_intoto_body(bundle, x509, base64, hashlib) -> None:
    inner = bundle.log_entry._inner
    envelope_inner = bundle._dsse_envelope._inner
    raw = inner.canonicalized_body
    body = json.loads(raw if isinstance(raw, (bytes, bytearray, str))
                      else base64.b64decode(raw))
    content = (body.get("spec") or {}).get("content") or {}

    recorded = content.get("payloadHash") or {}
    if recorded.get("algorithm") != "sha256":
        raise ValueError("entry body records no sha256 payload hash")
    if recorded.get("value") != hashlib.sha256(envelope_inner.payload).hexdigest():
        raise ValueError("entry body payload hash does not match the envelope")

    recorded_envelope = content.get("envelope") or {}
    if recorded_envelope.get("payloadType") != envelope_inner.payload_type:
        raise ValueError("entry body payload type does not match the envelope")

    recorded_signatures = recorded_envelope.get("signatures") or []
    if len(recorded_signatures) != len(envelope_inner.signatures):
        raise ValueError("entry body signature count does not match the envelope")

    for recorded_signature, actual in zip(
        recorded_signatures, envelope_inner.signatures
    ):
        signature = _b64(recorded_signature.get("sig"), base64)
        if signature not in (actual.sig, base64.b64encode(actual.sig)):
            raise ValueError("entry body signature does not match the envelope")

        material = _b64(recorded_signature.get("publicKey"), base64)
        certificate = (
            x509.load_pem_x509_certificate(material)
            if material.lstrip().startswith(b"-----BEGIN")
            else x509.load_der_x509_certificate(material)
        )
        if certificate != bundle.signing_certificate:
            raise ValueError("entry body certificate does not match the signature")

def _b64(value: Optional[str], base64_module) -> bytes:
    text = value or ""
    return base64_module.b64decode(text + "=" * (-len(text) % 4))
