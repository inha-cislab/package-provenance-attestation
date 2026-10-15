from __future__ import annotations

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from provenance.collect import log_path
from provenance.rekor import Entry, EntryUnavailable
from provenance.verify import log_check, log_material
from provenance.verify.log_verifier import BundleVerification

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

ARTIFACT = "9d9d2cfd681fd9271f6cf3e1e0b7a1b3a1e4bd6c4b4b1c8b0e0a9d6f2c3b4a5d"

def entry_from(name: str) -> Entry:
    import base64

    record = json.load(io.open(os.path.join(FIXTURES, f"{name}.json"),
                               encoding="utf-8"))
    payload = record["payload"]
    body = json.loads(base64.b64decode(payload["body"]))
    return Entry(
        uuid=record["uuid"],
        log_index=payload.get("logIndex"),
        integrated_at=None,
        kind=body.get("kind", ""),
        api_version=body.get("apiVersion", ""),
        body=body,
        raw=payload,
    )

def signed_digest_of(entry) -> str:
    return ((entry.spec.get("data") or {}).get("hash") or {}).get("value", "")

class StubVerifier:

    def __init__(self, result: BundleVerification, record_calls=None):
        self.result = result
        self.calls = record_calls if record_calls is not None else []

    def verify_bundle(self, bundle_json, *, artifact_digests,
                      expected_repository=""):
        self.calls.append((bundle_json, artifact_digests, expected_repository))
        return self.result

def verified(subjects=None):
    return BundleVerification(True, True, "verified", entry_kind="dsse/0.0.1",
                              subject_digests=subjects or {})

def make_entry(kind="dsse", version="0.0.1", spec=None, raw=None) -> Entry:
    body = {"kind": kind, "apiVersion": version, "spec": spec or {}}
    return Entry(uuid="u1", log_index=1, integrated_at=None, kind=kind,
                 api_version=version, body=body, raw=raw or {})

class CryptographicOutcome(unittest.TestCase):
    def entry(self):
        return entry_from("hashedrekord_certificate")

    def test_a_valid_bundle_covering_the_artifact_verifies(self):
        entry = self.entry()
        digest = signed_digest_of(entry)
        result = log_check.verify_entry(
            entry, {"sha256": digest},
            verifier=StubVerifier(verified({"sha256": [digest]})))
        self.assertEqual(result.outcome, log_check.VERIFIED)
        self.assertTrue(result.verified)
        self.assertTrue(result.binds_artifact)
        self.assertTrue(result.succeeded)

    def test_a_valid_bundle_describing_other_bytes_is_a_subject_mismatch(self):
        entry = self.entry()
        result = log_check.verify_entry(
            entry, {"sha256": "ff" * 32},
            verifier=StubVerifier(verified({"sha256": [signed_digest_of(entry)]})))
        self.assertEqual(result.outcome, log_check.SUBJECT_MISMATCH)
        self.assertTrue(result.verified)
        self.assertFalse(result.binds_artifact)
        self.assertFalse(result.succeeded)

    def test_a_tampered_signature_is_an_invalid_signature(self):
        entry = self.entry()
        result = log_check.verify_entry(
            entry, {"sha256": signed_digest_of(entry)},
            verifier=StubVerifier(BundleVerification(
                False, False, "verification failed",
                detail="signature does not verify")))
        self.assertEqual(result.outcome, log_check.INVALID)
        self.assertFalse(result.verified)
        self.assertFalse(result.succeeded)

    def test_an_unreadable_bundle_is_reported_as_malformed(self):
        result = log_check.verify_entry(
            self.entry(), {"sha256": "aa" * 32},
            verifier=StubVerifier(BundleVerification(
                False, False, "unreadable bundle")))
        self.assertEqual(result.outcome, log_check.MALFORMED)

    def test_a_verifier_that_raises_is_not_a_negative_result(self):
        class Exploding:
            def verify_bundle(self, *args, **kwargs):
                raise RuntimeError("trust root could not be loaded")

        result = log_check.verify_entry(
            self.entry(), {"sha256": "aa" * 32}, verifier=Exploding())
        self.assertEqual(result.outcome, log_check.TRUST_ROOT)
        self.assertFalse(result.verified)

class MissingMaterial(unittest.TestCase):
    def test_a_dsse_entry_has_no_payload_in_the_log(self):
        material = log_material.material_for(entry_from("dsse_payload_absent"))
        self.assertFalse(material.usable)
        self.assertIn("payload", material.missing)

    def test_that_shortfall_is_reported_as_no_material_not_as_failure(self):
        result = log_check.verify_entry(
            entry_from("dsse_payload_absent"), {"sha256": "aa" * 32},
            verifier=StubVerifier(verified()))
        self.assertEqual(result.outcome, log_check.NO_MATERIAL)
        self.assertFalse(result.verified)

    def test_a_bare_key_cannot_establish_an_identity(self):
        result = log_check.verify_entry(
            entry_from("hashedrekord_bare_key"), {"sha256": "aa" * 32},
            verifier=StubVerifier(verified()))
        self.assertEqual(result.outcome, log_check.UNCERTIFIED)
        self.assertIn("bare key", result.detail)

    def test_an_entry_without_an_inclusion_proof_has_no_material(self):
        entry = make_entry(kind="hashedrekord", raw={"logIndex": 1, "logID": "ab"})
        material = log_material.material_for(entry)
        self.assertFalse(material.usable)
        self.assertIn("inclusion proof", material.missing)

    def test_an_entry_with_no_signing_material_says_so(self):
        entry = make_entry(kind="hashedrekord", spec={}, raw={
            "logIndex": 1, "logID": "ab", "body": "",
            "verification": {"inclusionProof": {
                "checkpoint": "c", "rootHash": "ab", "hashes": [],
                "treeSize": 2, "logIndex": 1}}})
        material = log_material.material_for(entry)
        self.assertFalse(material.usable)
        self.assertIn("signing material", material.missing)

    def test_an_entry_the_log_will_not_return_is_its_own_outcome(self):
        observation = log_path.LogObservation(
            "maven", "a:b", "1", "found",
            digests={"sha256": "aa" * 32}, entries={"sha256": ["missing"]})

        class Refusing:
            def entry(self, uuid):
                raise EntryUnavailable(f"{uuid}: log returned 500")

        log_path.verify(_Ecosystem(), Refusing(), observation)
        outcomes = observation.verification["outcomes"]
        self.assertEqual(outcomes, {log_check.UNAVAILABLE: 1})
        self.assertFalse(observation.verified)

class UnsupportedKind(unittest.TestCase):
    def test_a_rekord_entry_is_unsupported_rather_than_invalid(self):
        result = log_check.verify_entry(
            entry_from("rekord_unsupported"), {"sha256": "aa" * 32},
            verifier=StubVerifier(verified()))
        self.assertEqual(result.outcome, log_check.UNSUPPORTED)
        self.assertIn("rekord", result.detail)

    def test_an_unsupported_kind_is_never_counted_as_verified(self):
        summary = log_check.summarise([log_check.verify_entry(
            entry_from("rekord_unsupported"), {"sha256": "aa" * 32},
            verifier=StubVerifier(verified()))])
        self.assertEqual(summary.verified_and_bound, 0)
        self.assertEqual(summary.unverified, 1)

class _Ecosystem:

    name = "test"

    def __init__(self, bundles=None):
        self._bundles = bundles or []

    def resolve(self, package, version=None):
        class Release:
            declared_repository = ""

        return Release()

    def registry_bundles(self, release):
        return self._bundles

class RegistryHint(unittest.TestCase):
    def test_a_hinted_entry_is_verified_and_labelled_as_hinted(self):
        entry = entry_from("hashedrekord_certificate")
        digest = signed_digest_of(entry)
        observation = log_path.LogObservation(
            "maven", "a:b", "1", "found",
            digests={"sha256": digest}, hinted=[entry.uuid],
            detail="recovered by log index")

        log_path.verify(
            _Ecosystem(), _Log({entry.uuid: entry}), observation,
            verifier=StubVerifier(verified({"sha256": [digest]})))

        record = observation.verification["records"][0]
        self.assertEqual(record["source"], "log index hint")
        self.assertEqual(record["outcome"], log_check.VERIFIED)
        self.assertTrue(observation.verified)

    def bundle_for(self, entry, log_index=None):
        return {"dsseEnvelope": {}, "verificationMaterial": {"tlogEntries": [
            {"logIndex": str(entry.log_index if log_index is None else log_index)}]}}

    def observation_for(self, entry):
        return log_path.LogObservation(
            "pypi", "a", "1", "found",
            digests={"sha256": "aa" * 32}, entries={"sha256": [entry.uuid]})

    def test_a_registry_bundle_rescues_an_entry_the_log_cannot_supply(self):
        entry = entry_from("dsse_payload_absent")
        observation = self.observation_for(entry)

        log_path.verify(
            _Ecosystem(bundles=[self.bundle_for(entry)]),
            _Log({entry.uuid: entry}), observation,
            verifier=StubVerifier(verified({"sha256": ["aa" * 32]})))

        record = observation.verification["records"][0]
        self.assertEqual(record["source"], "registry-served bundle")
        self.assertEqual(record["outcome"], log_check.VERIFIED)

    def test_a_bundle_for_another_entry_is_never_used_for_this_one(self):
        entry = entry_from("dsse_payload_absent")
        observation = self.observation_for(entry)

        log_path.verify(
            _Ecosystem(bundles=[self.bundle_for(entry, log_index=999999999)]),
            _Log({entry.uuid: entry}), observation,
            verifier=StubVerifier(verified({"sha256": ["aa" * 32]})))

        record = observation.verification["records"][0]
        self.assertEqual(record["outcome"], log_check.NO_MATERIAL)
        self.assertEqual(record["source"], "digest query")
        self.assertFalse(observation.verified)

    def test_a_bundle_naming_no_entry_at_all_is_never_used(self):
        entry = entry_from("dsse_payload_absent")
        observation = self.observation_for(entry)

        log_path.verify(
            _Ecosystem(bundles=[{"dsseEnvelope": {}}]),
            _Log({entry.uuid: entry}), observation,
            verifier=StubVerifier(verified({"sha256": ["aa" * 32]})))

        self.assertEqual(observation.verification["records"][0]["outcome"],
                         log_check.NO_MATERIAL)

    def test_without_registry_bundles_the_same_entry_has_no_material(self):
        entry = entry_from("dsse_payload_absent")
        observation = self.observation_for(entry)

        log_path.verify(
            _Ecosystem(bundles=[self.bundle_for(entry)]),
            _Log({entry.uuid: entry}), observation,
            verifier=StubVerifier(verified()), use_registry_bundles=False)

        self.assertEqual(observation.verification["records"][0]["outcome"],
                         log_check.NO_MATERIAL)

class _Log:
    def __init__(self, entries):
        self._entries = entries

    def entry(self, uuid):
        if uuid not in self._entries:
            raise EntryUnavailable(f"{uuid}: not held")
        return self._entries[uuid]

class MixedOutcomes(unittest.TestCase):
    def records(self):
        good = log_check.EntryVerification(
            "a", log_check.VERIFIED, verified=True, binds_artifact=True,
            asserts_build=True, role="publisher")
        other = log_check.EntryVerification(
            "b", log_check.VERIFIED, verified=True, binds_artifact=True,
            role="observer")
        stale = log_check.EntryVerification(
            "c", log_check.SUBJECT_MISMATCH, verified=True, role="observer")
        broken = log_check.EntryVerification("d", log_check.INVALID)
        absent = log_check.EntryVerification("e", log_check.NO_MATERIAL)
        return [good, other, stale, broken, absent]

    def test_each_outcome_is_counted_under_its_own_name(self):
        summary = log_check.summarise(self.records())
        self.assertEqual(summary.outcomes, {
            log_check.VERIFIED: 2, log_check.SUBJECT_MISMATCH: 1,
            log_check.INVALID: 1, log_check.NO_MATERIAL: 1})

    def test_only_records_that_verify_and_bind_are_counted_as_verified(self):
        summary = log_check.summarise(self.records())
        self.assertEqual(summary.entries, 5)
        self.assertEqual(summary.verified_records, 3)
        self.assertEqual(summary.verified_and_bound, 2)
        self.assertEqual(summary.unverified, 3)

    def test_a_mismatched_record_does_not_make_the_package_verified(self):
        summary = log_check.summarise([self.records()[2]])
        self.assertFalse(summary.any_verified)

    def test_publisher_and_build_provenance_are_counted_separately(self):
        summary = log_check.summarise(self.records())
        self.assertEqual(summary.verified_publisher, 1)
        self.assertEqual(summary.verified_build_provenance, 1)
        self.assertEqual(summary.observer_records, 2)

class ClassificationIsSeparate(unittest.TestCase):
    def test_calling_a_failed_record_the_publisher_does_not_verify_it(self):
        failed = log_check.EntryVerification(
            "a", log_check.INVALID, role="publisher")
        summary = log_check.summarise([failed])
        self.assertEqual(summary.verified_and_bound, 0)
        self.assertEqual(summary.verified_publisher, 0)
        self.assertEqual(summary.unverified, 1)

    def test_a_bare_key_record_is_counted_but_never_verified(self):
        record = log_check.EntryVerification(
            "a", log_check.UNCERTIFIED, role="bare key")
        summary = log_check.summarise([record])
        self.assertEqual(summary.bare_key_records, 1)
        self.assertEqual(summary.verified_and_bound, 0)

    def test_the_classifier_cannot_change_a_verification_outcome(self):
        entry = entry_from("rekord_unsupported")
        observation = log_path.LogObservation(
            "maven", "a:b", "1", "found",
            digests={"sha256": "aa" * 32}, entries={"sha256": [entry.uuid]})

        from types import SimpleNamespace

        attribution = SimpleNamespace(
            role="publisher",
            identity=SimpleNamespace(repository="someone/else", subject=""))

        log_path.verify(
            _Ecosystem(), _Log({entry.uuid: entry}), observation,
            verifier=StubVerifier(verified()),
            classifier=lambda entry: attribution)

        record = observation.verification["records"][0]
        self.assertEqual(record["outcome"], log_check.UNSUPPORTED)
        self.assertEqual(record["role"], "publisher")
        self.assertFalse(record["binds_artifact"])
        self.assertEqual(observation.verification["verified_publisher"], 0)

class Wiring(unittest.TestCase):
    def test_found_does_not_imply_verified_on_the_observation(self):
        observation = log_path.LogObservation(
            "maven", "a:b", "1", "found", entries={"sha256": ["u"]})
        self.assertTrue(observation.present)
        self.assertFalse(observation.verified)

    def test_a_record_written_without_verification_keeps_its_old_shape(self):
        record = log_path.LogObservation(
            "maven", "a:b", "1", "found", entries={"sha256": ["u"]}).as_dict()
        self.assertNotIn("verification", record)
        self.assertEqual(record["schema"], log_path.SCHEMA)

    def test_log_path_invokes_the_verifier_when_verification_is_requested(self):
        calls = []

        class Recording(StubVerifier):
            pass

        entry = entry_from("hashedrekord_certificate")
        digest = signed_digest_of(entry)
        observation = log_path.LogObservation(
            "maven", "a:b", "1", "found",
            digests={"sha256": digest}, entries={"sha256": [entry.uuid]})

        log_path.verify(
            _Ecosystem(), _Log({entry.uuid: entry}), observation,
            verifier=Recording(verified({"sha256": [digest]}), calls))

        self.assertEqual(len(calls), 1, "the verifier was never called")
        self.assertIn("verification", observation.as_dict())
        self.assertTrue(observation.verified)

    def test_the_cli_passes_the_verify_flag_through_to_the_pass(self):
        from provenance import cli

        parsed = cli._build_parser().parse_args(
            ["log-path", "--ecosystem", "maven", "--package", "a:b", "--verify"])
        self.assertTrue(parsed.verify)
        self.assertFalse(parsed.no_registry_bundles)

        default = cli._build_parser().parse_args(
            ["log-path", "--ecosystem", "maven", "--package", "a:b"])
        self.assertFalse(default.verify,
                         "verification must be opt-in, not silently default")

    def test_a_package_with_no_entries_verifies_nothing(self):
        observation = log_path.LogObservation("maven", "a:b", "1", "not found")
        log_path.verify(_Ecosystem(), _Log({}), observation)
        self.assertEqual(observation.verification["entries"], 0)
        self.assertFalse(observation.verified)

class AssembledMaterial(unittest.TestCase):
    def test_a_hashedrekord_yields_a_bundle_carrying_the_signed_digest(self):
        entry = entry_from("hashedrekord_certificate")
        material = log_material.material_for(entry)
        self.assertTrue(material.usable)
        self.assertEqual(material.signed_digest,
                         {"sha256": signed_digest_of(entry)})
        self.assertTrue(material.certified)

    def test_the_bundle_carries_the_inclusion_proof_and_the_body(self):
        material = log_material.material_for(entry_from("hashedrekord_certificate"))
        tlog = material.bundle["verificationMaterial"]["tlogEntries"][0]
        self.assertTrue(tlog["inclusionProof"]["checkpoint"]["envelope"])
        self.assertTrue(tlog["canonicalizedBody"])
        self.assertEqual(tlog["kindVersion"],
                         {"kind": "hashedrekord", "version": "0.0.1"})

    def test_the_bundle_is_the_shape_sigstore_reads(self):
        material = log_material.material_for(entry_from("hashedrekord_certificate"))
        self.assertEqual(material.bundle["mediaType"],
                         log_material.BUNDLE_MEDIA_TYPE)
        self.assertIn("messageSignature", material.bundle)
        self.assertIn("rawBytes",
                      material.bundle["verificationMaterial"]["certificate"])

class SyntheticFixtures(unittest.TestCase):
    names = ("dsse_payload_absent", "hashedrekord_bare_key",
             "hashedrekord_certificate", "rekord_unsupported")

    def test_log_records_use_synthetic_checkpoints_and_merkle_paths(self):
        import base64
        import hashlib

        for name in self.names:
            entry = entry_from(name)
            leaf = hashlib.sha256(b"\x00" + base64.b64decode(entry.raw["body"])).digest()
            proof = entry.raw["verification"]["inclusionProof"]
            sibling = bytes.fromhex(proof["hashes"][0])
            root = hashlib.sha256(b"\x01" + leaf + sibling).hexdigest()
            self.assertEqual(entry.uuid, "0" * 16 + leaf.hex())
            self.assertEqual(proof["rootHash"], root)
            self.assertEqual(proof["treeSize"], 2)
            self.assertEqual(proof["logIndex"], 0)
            self.assertTrue(proof["checkpoint"].startswith("log.example.invalid - 1\n"))

    def test_certificates_are_self_signed_with_example_identities(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec

        for name in self.names:
            if name == "hashedrekord_bare_key":
                continue
            material = log_material._signing_material(entry_from(name))
            certificate = x509.load_pem_x509_certificate(material)
            self.assertEqual(certificate.issuer, certificate.subject)
            certificate.public_key().verify(
                certificate.signature, certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm))
            san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual(san.get_values_for_type(x509.UniformResourceIdentifier),
                ["https://example.invalid/owner/project/.github/workflows/release.yml"])

    def test_hashedrekord_signatures_cover_the_synthetic_artifact(self):
        import base64
        import hashlib
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        artifact = b"Synthetic package artifact for unit tests\n"
        for name in ("hashedrekord_certificate", "hashedrekord_bare_key"):
            entry = entry_from(name)
            material = log_material._signing_material(entry)
            public_key = (serialization.load_pem_public_key(material)
                          if name == "hashedrekord_bare_key"
                          else x509.load_pem_x509_certificate(material).public_key())
            public_key.verify(base64.b64decode(entry.spec["signature"]["content"]),
                              artifact, ec.ECDSA(hashes.SHA256()))
            self.assertEqual(signed_digest_of(entry), hashlib.sha256(artifact).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
