from __future__ import annotations

import base64
import json

from ...attestor import classify
from ...digest import digest_artifact
from ...ecosystems.npm import PROVENANCE_PREDICATES, _build_repository
from ...identity import GITHUB_ACTIONS
from ...rekor import Entry
from ..npm_verifier import NpmLogVerifier


def verify_release(ecosystem, release) -> dict:
    url = str(release.metadata.get("attestations_url") or "")
    if not url:
        return {"outcome": "no attestation", "detail": "no dist.attestations.url"}
    try:
        response = ecosystem.client.request(url)
        if not response.ok:
            return {"outcome": "error", "detail": f"attestation request returned HTTP {response.status}"}
        document = response.json()
        items = document.get("attestations")
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ValueError("invalid attestation response")
        items = [item for item in items if item.get("predicateType") in PROVENANCE_PREDICATES]
        if not items:
            return {"outcome": "no attestation", "detail": "no provenance attestation"}
        artifact_url = ecosystem.artifact_url(release)
        if not artifact_url:
            return {"outcome": "artifact unavailable", "detail": "no artifact URL"}
        computed = digest_artifact(ecosystem.client, artifact_url)
        expected = ecosystem.published_digest(release, "sha512")
        if expected and computed.get("sha512") != expected.lower():
            return {"outcome": "digest mismatch", "detail": "artifact does not match registry SHA-512"}
        verifier = NpmLogVerifier(client=ecosystem.client, artifact_url=artifact_url)
        attempts = []
        for index, item in enumerate(items):
            try:
                bundle = item.get("bundle")
                if not isinstance(bundle, dict):
                    raise ValueError("missing attestation bundle")
                result = verifier.verify_bundle(bundle, artifact_digests=computed.values)
                record = {"index": index, **result.as_dict(), "registry_authorized": False}
                if result.outcome == "verified" and result.verified and result.subject_matches:
                    statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"], validate=True))
                    if statement.get("predicateType") != item["predicateType"]:
                        record["outcome"] = "predicate mismatch"
                    else:
                        material = bundle.get("verificationMaterial") or {}
                        certificate = material.get("certificate") or next(iter(
                            (material.get("x509CertificateChain") or {}).get("certificates") or []), {})
                        entry = Entry("", None, None, "dsse", "0.0.1", {
                            "spec": {"signatures": [{"verifier": certificate.get("rawBytes", "")}]}})
                        attribution = classify(entry, expected_repository=_build_repository(statement),
                                               expected_issuer=GITHUB_ACTIONS,
                                               registry_authorizes=True, registry_answers=True)
                        record.update(role=str(attribution.role),
                                      registry_authorized=attribution.registry_authorized)
                        if not attribution.registry_authorized:
                            record["outcome"] = "publisher mismatch"
                            record["detail"] = attribution.detail
                elif result.outcome == "verified":
                    record["outcome"] = "verification failed"
                attempts.append(record)
            except Exception as error:
                attempts.append({"index": index, "outcome": "unreadable bundle", "detail": str(error)})
        failed = next((record for record in attempts if record["outcome"] != "verified"), None)
        return {"outcome": failed["outcome"] if failed else "verified",
                "detail": failed.get("detail", "") if failed else "JavaScript sigstore.verify",
                "attempts": attempts}
    except Exception as error:
        return {"outcome": "error", "detail": f"{type(error).__name__}: {error}"}
