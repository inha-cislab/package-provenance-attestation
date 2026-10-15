import base64
import copy
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier
import pytest

from provenance import cli
from provenance.digest import Digests
from provenance.ecosystems.base import Release
from provenance.http import Response
from provenance.verify.log_verifier import BundleVerification
from provenance.verify.registry import npm
from provenance.verify.registry_verifier import verify


def certificate(repository="owner/project", issuer=npm.GITHUB_ACTIONS):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic signer")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2024, 1, 2, tzinfo=timezone.utc))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(
                f"https://github.com/{repository}/.github/workflows/release.yml@refs/heads/main")]), False)
            .add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.57264.1.1"),
                                                     issuer.encode()), False)
            .sign(key, hashes.SHA256()))
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


@pytest.fixture
def setup(monkeypatch):
    predicate = "https://slsa.dev/provenance/v1"
    statement = {"_type": "https://in-toto.io/Statement/v1", "predicateType": predicate,
                 "subject": [{"name": "example", "digest": {"sha512": "b" * 128}}],
                 "predicate": {"buildDefinition": {"externalParameters": {
                     "workflow": {"repository": "https://github.com/owner/project"}}}}}
    bundle = {"dsseEnvelope": {"payload": base64.b64encode(json.dumps(statement).encode()).decode()},
              "verificationMaterial": {"certificate": {"rawBytes": certificate()}}}
    document = {"attestations": [{"predicateType": predicate, "bundle": bundle}]}
    adapter = Mock(name="adapter")
    adapter.name = "npm"
    adapter.verifier_requires_project = True
    release = Release("example", "1.0.0", "https://example.invalid/artifact.tgz",
                      metadata={"attestations_url": "https://example.invalid/attestations"})
    adapter.resolve.return_value = release
    adapter.artifact_url.return_value = release.artifact_url
    adapter.published_digest.return_value = "b" * 128
    adapter.client.request.side_effect = lambda url: Response(200, json.dumps(document).encode())
    digest = Mock(return_value=Digests({"sha256": "a" * 64, "sha512": "b" * 128}, 12))
    monkeypatch.setattr(npm, "digest_artifact", digest)
    engine = Mock()
    engine.verify_bundle.return_value = BundleVerification(True, True, "verified")
    factory = Mock(return_value=engine)
    monkeypatch.setattr(npm, "NpmLogVerifier", factory)
    return SimpleNamespace(adapter=adapter, release=release, document=document, bundle=bundle,
                           engine=engine, factory=factory, digest=digest)


def test_registry_uses_js_and_classifies_publisher(setup):
    result = verify(setup.adapter, "example", "1.0.0")
    assert result.succeeded
    assert result.attempts[0]["role"] == "publisher"
    assert result.attempts[0]["registry_authorized"] is True
    assert result.command == []
    setup.adapter.verifier_commands.assert_not_called()
    setup.adapter.client.request.assert_called_once_with("https://example.invalid/attestations")
    assert setup.engine.verify_bundle.call_args.kwargs["artifact_digests"]["sha512"] == "b" * 128


@pytest.mark.parametrize("result", [
    BundleVerification(False, False, "invalid signature"),
    BundleVerification(True, False, "subject mismatch"),
    BundleVerification(False, False, "verifier unavailable"),
    BundleVerification(False, False, "trust root unavailable"),
    BundleVerification(False, False, "uncertified key"),
])
def test_verifier_failure_is_preserved(setup, result):
    setup.engine.verify_bundle.return_value = result
    assert verify(setup.adapter, "example", "1.0.0").outcome == result.outcome


@pytest.mark.parametrize("repository,issuer", [
    ("other/project", npm.GITHUB_ACTIONS), ("owner/project", "https://issuer.example.invalid"),
])
def test_wrong_publisher_is_not_verified(setup, repository, issuer):
    setup.bundle["verificationMaterial"]["certificate"]["rawBytes"] = certificate(repository, issuer)
    result = verify(setup.adapter, "example", "1.0.0")
    assert result.outcome == "publisher mismatch"
    assert not result.attempts[0]["registry_authorized"]


def test_certificate_chain_format(setup):
    material = setup.bundle["verificationMaterial"]
    material["x509CertificateChain"] = {"certificates": [material.pop("certificate")]}
    assert verify(setup.adapter, "example", "1.0.0").succeeded


def test_no_attestation_does_not_succeed(setup):
    setup.document["attestations"] = []
    assert verify(setup.adapter, "example", "1.0.0").outcome == "no attestation"
    setup.digest.assert_not_called()


def test_http_failure_is_not_missing_attestation(setup):
    setup.adapter.client.request.side_effect = None
    setup.adapter.client.request.return_value = Response(503, b"")
    assert verify(setup.adapter, "example", "1.0.0").outcome == "error"


def test_downloaded_bytes_must_match_registry_sha512(setup):
    setup.adapter.published_digest.return_value = "c" * 128
    assert verify(setup.adapter, "example", "1.0.0").outcome == "digest mismatch"
    setup.engine.verify_bundle.assert_not_called()


def test_signed_predicate_must_match_registry_type(setup):
    statement = json.loads(base64.b64decode(setup.bundle["dsseEnvelope"]["payload"]))
    statement["predicateType"] = "https://example.invalid/other"
    setup.bundle["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    assert verify(setup.adapter, "example", "1.0.0").outcome == "predicate mismatch"


def test_one_valid_bundle_does_not_hide_an_invalid_bundle(setup):
    setup.document["attestations"].append(copy.deepcopy(setup.document["attestations"][0]))
    setup.engine.verify_bundle.side_effect = [BundleVerification(True, True, "verified"),
                                             BundleVerification(False, False, "invalid signature")]
    result = verify(setup.adapter, "example", "1.0.0")
    assert result.outcome == "invalid signature"
    assert len(result.attempts) == 2


def test_consumer_path_removed():
    with pytest.raises(SystemExit):
        cli._build_parser().parse_args(["verify-evidence", "--ecosystem", "npm",
                                       "--path", "consumer", "--package", "example"])
