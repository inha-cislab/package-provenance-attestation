import pytest

from provenance import attestor
from provenance.attestor import Role
from provenance.ecosystems.base import Release
from provenance.ecosystems.pypi import PyPI
from provenance.identity import GITHUB_ACTIONS, GOOGLE, Identity
from provenance.verify import log_check
from provenance.verify.log_verifier import BundleVerification
from test_framework import make_entry
from test_log_verification import StubVerifier, entry_from, signed_digest_of


def classify_identity(monkeypatch, identity, **kwargs):
    monkeypatch.setattr(attestor.identity_module, "parse", lambda _: identity)
    entry = make_entry({"signatures": [{"verifier": "x"}]})
    return attestor.classify(entry, **kwargs)


@pytest.mark.parametrize("repository,issuer,expected", [
    ("owner/project", GITHUB_ACTIONS, Role.PUBLISHER),
    ("owner/project-release", GITHUB_ACTIONS, Role.OBSERVER),
    ("another/project", GITHUB_ACTIONS, Role.OBSERVER),
    ("owner/project", GOOGLE, Role.OBSERVER),
    ("owner/project", "", Role.OBSERVER),
])
def test_authorized_repository_requires_exact_repository_and_issuer(
        monkeypatch, repository, issuer, expected):
    result = classify_identity(
        monkeypatch,
        Identity(subject=f"https://github.com/{repository}/.github/workflows/release.yml",
                 issuer=issuer),
        expected_repository="owner/project", expected_issuer=GITHUB_ACTIONS,
        registry_authorizes=True, registry_answers=True)
    assert result.role is expected


@pytest.mark.parametrize("subject,issuer,expected", [
    ("service@example.com", GOOGLE, Role.PUBLISHER),
    ("other-service@example.com", GOOGLE, Role.OBSERVER),
    ("service@example.com", GITHUB_ACTIONS, Role.OBSERVER),
])
def test_service_account_requires_exact_subject_and_issuer(
        monkeypatch, subject, issuer, expected):
    assert classify_identity(
        monkeypatch, Identity(subject=subject, issuer=issuer),
        expected_identity="service@example.com", expected_issuer=GOOGLE,
    ).role is expected


def test_missing_expected_issuer_cannot_authorize_publisher(monkeypatch):
    result = classify_identity(
        monkeypatch, Identity(subject="service@example.com", issuer=GOOGLE),
        expected_identity="service@example.com")
    assert not result.registry_authorized


def test_reusable_workflow_uses_certified_source_repository(monkeypatch):
    result = classify_identity(
        monkeypatch,
        Identity(subject="https://github.com/build/workflows/.github/workflows/release.yml",
                 issuer=GITHUB_ACTIONS,
                 build={"source_repository": "https://github.com/owner/project"}),
        expected_repository="owner/project", expected_issuer=GITHUB_ACTIONS,
        registry_authorizes=True)
    assert result.role is Role.PUBLISHER


def test_release_classification_checks_all_registry_publisher_records(monkeypatch):
    class Client:
        def get_json(self, url):
            return {"attestation_bundles": [
                {"publisher": {"kind": "GitHub", "repository": "owner/previous"}},
                {"publisher": {"kind": "Google", "email": "service@example.com"}},
            ]}

    monkeypatch.setattr(attestor.identity_module, "parse", lambda _: Identity(
        subject="service@example.com", issuer=GOOGLE))
    result = attestor.classify_for_release(
        make_entry({"signatures": [{"verifier": "x"}]}), PyPI(Client()),
        Release("example", "1", metadata={"filename": "example.whl"}))
    assert result.role is Role.PUBLISHER


def test_metadata_repository_without_registry_authorization_is_not_publisher(monkeypatch):
    class Client:
        def get_json(self, url):
            return {}

    monkeypatch.setattr(attestor.identity_module, "parse", lambda _: Identity(
        subject="https://github.com/owner/project/.github/workflows/release.yml",
        issuer=GITHUB_ACTIONS))
    result = attestor.classify_for_release(
        make_entry({"signatures": [{"verifier": "x"}]}), PyPI(Client()),
        Release("example", "1", declared_repository="owner/project",
                metadata={"filename": "example.whl"}))
    assert result.role is Role.OBSERVER


def test_policy_refusal_preserves_crypto_but_excludes_authorized_success():
    entry = entry_from("hashedrekord_certificate")
    digest = signed_digest_of(entry)
    record = log_check.verify_entry(
        entry, {"sha256": digest}, expected_repository="owner/project",
        verifier=StubVerifier(BundleVerification(
            True, True, "policy refused", subject_digests={"sha256": [digest]})))
    record.role = "publisher"
    record.asserts_build = True
    assert record.outcome == log_check.POLICY_REFUSED
    assert record.identity_policy == "refused"
    assert record.verified and record.binds_artifact
    assert not record.succeeded
    summary = log_check.summarise([record])
    assert summary.verified_records == 1
    assert summary.verified_and_bound == 1
    assert summary.verified_publisher == 0
    assert summary.verified_build_provenance == 0
    assert summary.unverified == 1


def test_matching_policy_still_counts_as_verified_publisher():
    record = log_check.EntryVerification(
        uuid="test", outcome=log_check.VERIFIED, verified=True,
        binds_artifact=True, identity_policy="matches", role="publisher")
    assert record.succeeded
    assert log_check.summarise([record]).verified_publisher == 1
