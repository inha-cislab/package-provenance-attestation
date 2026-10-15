import json
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from provenance.collect import log_path
from provenance.verify import log_check, log_material, npm_verifier
from provenance.verify.log_verifier import BundleVerification


@pytest.mark.parametrize("ecosystem_name,custom", [("npm", False), ("pypi", False), ("npm", True)])
def test_log_path_backend_selection(monkeypatch, ecosystem_name, custom):
    backend = Mock()
    factory = Mock(return_value=backend)
    monkeypatch.setattr(npm_verifier, "NpmLogVerifier", factory)
    verify_entry = Mock(return_value=log_check.EntryVerification("entry", "verified"))
    monkeypatch.setattr(log_check, "verify_entry", verify_entry)
    ecosystem = SimpleNamespace(name=ecosystem_name, client=object(),
        resolve=lambda *args: object(), artifact_url=lambda release: "https://example.org/artifact",
        registry_bundles=lambda release: [])
    observation = log_path.LogObservation(ecosystem_name, "example", "1.0", "found",
        digests={"sha512": "ab"}, entries={"sha512": ["entry"]})
    override = object() if custom else None
    log_path.verify(ecosystem, SimpleNamespace(entry=lambda uuid: SimpleNamespace(log_index=1)),
                    observation, verifier=override)
    selected = verify_entry.call_args.kwargs["verifier"]
    assert selected is (override if custom else backend if ecosystem_name == "npm" else None)
    assert factory.call_count == (1 if ecosystem_name == "npm" and not custom else 0)


def test_missing_node_is_not_an_invalid_signature(monkeypatch):
    monkeypatch.delenv("PROVENANCE_NODE", raising=False)
    monkeypatch.setattr(npm_verifier.shutil, "which", lambda name: None)
    result = npm_verifier.NpmLogVerifier().verify_bundle({}, artifact_digests={})
    assert result.outcome == "verifier unavailable"
    assert not result.verified


@pytest.mark.parametrize("failure", [
    subprocess.CompletedProcess([], 1, "", "Cannot find module sigstore"),
    subprocess.CompletedProcess([], 0, "not json", ""),
    subprocess.CompletedProcess([], 0, '{"verified":"yes"}', ""),
    subprocess.TimeoutExpired("node", 300),
])
def test_process_failure_cannot_verify(monkeypatch, failure):
    monkeypatch.setenv("PROVENANCE_NODE", "node")
    def run(*args, **kwargs):
        if isinstance(failure, Exception):
            raise failure
        return failure
    monkeypatch.setattr(npm_verifier.subprocess, "run", run)
    result = npm_verifier.NpmLogVerifier().verify_bundle({}, artifact_digests={})
    assert result.outcome == "verifier unavailable"
    assert not result.verified


def test_bridge_passes_bundle_hashes_and_policy(monkeypatch):
    monkeypatch.setenv("PROVENANCE_NODE", "node")
    run = Mock(return_value=subprocess.CompletedProcess([], 0,
        json.dumps(BundleVerification(True, True, "verified").as_dict()), ""))
    monkeypatch.setattr(npm_verifier.subprocess, "run", run)
    result = npm_verifier.NpmLogVerifier().verify_bundle({"dsseEnvelope": {}},
        artifact_digests={"sha512": "ab"}, expected_repository="owner/project")
    request = json.loads(run.call_args.kwargs["input"])
    assert request["artifact_digests"] == {"sha512": "ab"}
    assert request["expected_repository"] == "owner/project"
    assert "dsseEnvelope" in request["bundle"]
    assert result.verified


@pytest.mark.parametrize("outcome", ["subject mismatch", "verifier unavailable", "trust root unavailable", "artifact unavailable", "uncertified key"])
def test_log_check_respects_backend_failure(monkeypatch, outcome):
    monkeypatch.setattr(log_material, "material_for", lambda entry: SimpleNamespace(
        usable=True, bundle={}, statement=True, signed_digest={}))
    entry = SimpleNamespace(uuid="entry", kind="dsse", api_version="0.0.1", log_index=1)
    verifier = Mock()
    verifier.verify_bundle.return_value = BundleVerification(outcome == "subject mismatch",
        False, outcome, subject_digests={"sha512": ["ab"]})
    record = log_check.verify_entry(entry, {"sha512": "ab"}, verifier=verifier)
    assert record.outcome == outcome
    assert not record.succeeded


def test_message_signature_download_failure_is_explicit(monkeypatch):
    monkeypatch.setenv("PROVENANCE_NODE", "node")
    client = Mock()
    client.request.return_value = SimpleNamespace(ok=False)
    result = npm_verifier.NpmLogVerifier(client=client, artifact_url="https://example.org/a").verify_bundle(
        {"messageSignature": {"messageDigest": {}}}, artifact_digests={})
    assert result.outcome == "artifact unavailable"
