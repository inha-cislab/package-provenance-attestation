from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from provenance.attestor import Role, classify
from provenance.digest import decode_subresource_integrity, digest_bytes
from provenance.ecosystems import GROUPS, group_of, names
from provenance.ecosystems.crates import index_path
from provenance.ecosystems.golang import escape
from provenance.identity import Identity
from provenance.rekor import Entry

def make_entry(spec: dict, kind: str = "dsse", version: str = "0.0.1") -> Entry:
    return Entry(
        uuid="0" * 64,
        log_index=1,
        integrated_at=None,
        kind=kind,
        api_version=version,
        body={"kind": kind, "apiVersion": version, "spec": spec},
    )

class TestEntryShapes:
    def test_reads_dsse_signatures(self):
        entry = make_entry({"signatures": [{"verifier": "AAAA"}]})
        assert entry.materials == ["AAAA"]

    def test_reads_intoto_envelope(self):
        entry = make_entry(
            {"content": {"envelope": {"signatures": [{"publicKey": "BBBB"}]}}},
            kind="intoto",
            version="0.0.2",
        )
        assert entry.materials == ["BBBB"]

    def test_reads_hashedrekord_public_key(self):
        entry = make_entry({"signature": {"publicKey": {"content": "CCCC"}}})
        assert entry.materials == ["CCCC"]

    def test_entry_with_no_material_is_empty_not_an_error(self):
        assert make_entry({}).materials == []

class TestAttribution:
    def test_project_signer_when_the_certificate_names_the_claimed_repository(
            self, monkeypatch):
        _stub_identity(
            monkeypatch,
            Identity(
                subject="https://github.com/owner/project/.github/workflows/release.yml",
                issuer="https://token.actions.githubusercontent.com",
            ),
        )
        result = classify(
            make_entry({"signatures": [{"verifier": "x"}]}),
            expected_repository="owner/project",
        )
        assert result.role is Role.PROJECT_SIGNER

    def test_observer_when_a_different_owner_signed(self, monkeypatch):
        _stub_identity(
            monkeypatch,
            Identity(
                subject="https://github.com/someone-else/project/.github/workflows/a.yml",
                issuer="https://token.actions.githubusercontent.com",
            ),
        )
        result = classify(
            make_entry({"signatures": [{"verifier": "x"}]}),
            expected_repository="owner/project",
        )
        assert result.role is Role.OBSERVER

    def test_release_repository_under_the_same_owner_is_still_the_publisher(
        self, monkeypatch
    ):
        _stub_identity(
            monkeypatch,
            Identity(
                subject="https://github.com/owner/project-release/.github/workflows/a.yml",
                issuer="https://token.actions.githubusercontent.com",
            ),
        )
        result = classify(
            make_entry({"signatures": [{"verifier": "x"}]}),
            expected_repository="owner/project",
        )
        assert result.role is Role.PROJECT_SIGNER

    def test_hosted_issuer_is_an_observer_whatever_it_names(self, monkeypatch):
        _stub_identity(
            monkeypatch,
            Identity(subject="https://issuer.enforce.dev/abc/def",
                     issuer="https://issuer.enforce.dev"),
        )
        result = classify(
            make_entry({"signatures": [{"verifier": "x"}]}),
            expected_repository="owner/project",
        )
        assert result.role is Role.OBSERVER

    def test_a_published_registry_key_is_not_anonymous(self, monkeypatch):
        key = _rsa_public_key_pem()
        material = base64.b64encode(key).decode()
        from provenance import identity as identity_module

        known = {identity_module.normalise_public_key(key): "npm"}
        result = classify(
            make_entry({"signatures": [{"verifier": material}]}),
            registry_keys=known,
        )
        assert result.role is Role.REGISTRY

    def test_an_unpublished_key_is_a_bare_key(self):
        material = base64.b64encode(_rsa_public_key_pem()).decode()
        result = classify(make_entry({"signatures": [{"verifier": material}]}))
        assert result.role is Role.BARE_KEY

class TestIdentity:
    def test_strips_a_git_suffix_from_the_repository(self):
        signer = Identity(subject="https://github.com/owner/project.git")
        assert signer.repository == "owner/project"

    def test_owner_is_lowercased(self):
        signer = Identity(subject="https://github.com/Owner/Project/wf.yml")
        assert signer.owner == "owner"

class TestDigests:
    def test_one_read_produces_every_algorithm(self):
        digests = digest_bytes(b"payload", ("sha256", "sha512"))
        assert set(digests.values) == {"sha256", "sha512"}
        assert digests.size == len(b"payload")

    def test_decodes_an_integrity_string(self):
        raw = bytes(range(64))
        integrity = "sha512-" + base64.b64encode(raw).decode()
        assert decode_subresource_integrity(integrity) == raw.hex()

    def test_a_malformed_integrity_string_is_none_not_an_exception(self):
        assert decode_subresource_integrity("sha512-not-base64!!") is None

class TestEcosystemPaths:
    def test_go_escapes_upper_case(self):
        assert escape("github.com/Masterminds/semver") == "github.com/!masterminds/semver"

    @pytest.mark.parametrize(
        "name,expected",
        [("a", "1/a"), ("ab", "2/ab"), ("abc", "3/a/abc"), ("serde", "se/rd/serde")],
    )
    def test_crates_index_sharding(self, name, expected):
        assert index_path(name) == expected

    def test_every_ecosystem_belongs_to_a_group(self):
        grouped = {name for members in GROUPS.values() for name in members}
        assert grouped == set(names())
        assert all(group_of(name) in GROUPS for name in names())

def _stub_identity(monkeypatch, signer: Identity) -> None:
    from provenance import attestor

    monkeypatch.setattr(attestor.identity_module, "parse", lambda material: signer)
    monkeypatch.setattr(
        attestor.identity_module, "matches_known_key", lambda material, known: None
    )

def _rsa_public_key_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

class TestHintRecovery:
    def test_a_hint_is_accepted_only_when_it_covers_the_artifact(self):
        from provenance.collect.log_path import _covers

        entry = make_entry({"data": {"hash": {"algorithm": "sha256", "value": "AB"}}},
                           kind="hashedrekord")
        assert _covers(entry, {"sha256": "ab"})
        assert not _covers(entry, {"sha256": "cd"})

    def test_a_hint_with_no_digest_is_refused(self):
        from provenance.collect.log_path import _covers

        assert not _covers(make_entry({}), {"sha256": "ab"})

class TestPublicKeyShapes:
    def test_public_key_as_a_mapping(self):
        entry = make_entry({"publicKey": {"content": "DDDD"}}, kind="rekord")
        assert entry.materials == ["DDDD"]

    def test_public_key_as_a_bare_string(self):
        entry = make_entry({"publicKey": "EEEE"}, kind="rekord")
        assert entry.materials == ["EEEE"]

    def test_public_key_of_an_unexpected_type_is_ignored(self):
        entry = make_entry({"publicKey": 7}, kind="rekord")
        assert entry.materials == []

class TestMultiSubjectStatements:
    def test_every_subject_is_kept(self):
        from provenance.verify.log_verifier import _subject_digests

        statement = {"subject": [
            {"name": "a.whl", "digest": {"sha256": "AA"}},
            {"name": "b.whl", "digest": {"sha256": "BB"}},
            {"name": "c.whl", "digest": {"sha256": "CC"}},
        ]}
        assert _subject_digests(statement) == {"sha256": ["aa", "bb", "cc"]}

    def test_a_bundle_over_many_files_still_matches_the_first(self):
        from provenance.verify.log_verifier import _subject_digests

        statement = {"subject": [{"digest": {"sha256": h}} for h in ("AA", "BB")]}
        digests = _subject_digests(statement)
        assert "aa" in digests["sha256"] and "bb" in digests["sha256"]

WORKFLOW = "https://github.com/owner/project/.github/workflows/a.yml"
ACTIONS = "https://token.actions.githubusercontent.com"

class TestAssertionFollowsContent:
    def test_a_certificate_recording_the_build_carries_provenance(self, monkeypatch):
        from provenance.attestor import Assertion

        _stub_identity(monkeypatch, Identity(
            subject=WORKFLOW, issuer=ACTIONS,
            build={"source_repository": "https://github.com/owner/project",
                   "build_config": WORKFLOW}))
        result = classify(
            make_entry({"signature": {"publicKey": {"content": "x"}}},
                       kind="hashedrekord"),
            expected_repository="owner/project",
        )
        assert result.assertion is Assertion.PROVENANCE
        assert result.could_be_provenance

    def test_a_certificate_without_build_extensions_is_attribution(self, monkeypatch):
        from provenance.attestor import Assertion

        _stub_identity(monkeypatch, Identity(subject=WORKFLOW, issuer=ACTIONS))
        result = classify(
            make_entry({"signature": {"publicKey": {"content": "x"}}},
                       kind="hashedrekord"),
            expected_repository="owner/project",
        )
        assert result.role is Role.PROJECT_SIGNER
        assert result.assertion is Assertion.ATTRIBUTION
        assert not result.could_be_provenance

    def test_a_statement_carries_provenance_whatever_the_certificate_says(
        self, monkeypatch
    ):
        _stub_identity(monkeypatch, Identity(subject=WORKFLOW, issuer=ACTIONS))
        result = classify(
            make_entry({"signatures": [{"verifier": "x"}]}, kind="dsse"),
            expected_repository="owner/project",
        )
        assert result.could_be_provenance

class TestBuildExtensionDecoding:
    def test_a_der_utf8_string_loses_its_tag_and_length(self):
        from provenance.identity import _der_string

        commit = b'ba0784ba0095eb4cea6f7f1e8e3201f6ff6f3404'
        assert _der_string(bytes([0x0C, 0x28]) + commit) == commit
        assert _der_string(bytes([0x0C, 0x10]) + b'refs/tags/8.12.0') == (
            b'refs/tags/8.12.0')

    def test_a_long_form_length_is_read_as_a_whole(self):
        from provenance.identity import _der_string

        body = b'x' * 200
        assert _der_string(bytes([0x0C, 0x81, 0xC8]) + body) == body

    def test_bytes_that_are_not_a_der_string_are_left_alone(self):
        from provenance.identity import _der_string

        assert _der_string(b'https://github.com/owner/project') == (
            b'https://github.com/owner/project')

GOOGLE = "service@example.invalid"
GOOGLE_ISSUER = "https://accounts.google.com"

class TestExpectedIdentity:
    def _entry(self):
        return make_entry({"signature": {"publicKey": {"content": "x"}}},
                          kind="hashedrekord")

    def test_a_recorded_identity_outranks_the_hosted_issuer_rule(self, monkeypatch):
        _stub_identity(monkeypatch,
                       Identity(subject=GOOGLE, issuer=GOOGLE_ISSUER))
        assert classify(self._entry()).role is Role.OBSERVER
        assert classify(self._entry(),
                        expected_identity=GOOGLE,
                        expected_issuer=GOOGLE_ISSUER).role is Role.PUBLISHER

    def test_an_identity_the_registry_did_not_record_stays_an_observer(
            self, monkeypatch):
        _stub_identity(monkeypatch,
                       Identity(subject="someone@else.example",
                                issuer=GOOGLE_ISSUER))
        assert classify(self._entry(),
                        expected_identity=GOOGLE).role is Role.OBSERVER

class TestNpmReadsSlsaV02:

    PAYLOAD = "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZSI6eyJidWlsZFR5cGUiOiJodHRwczovL2dpdGh1Yi5jb20vbnBtL2NsaS9naGEvdjIiLCJpbnZvY2F0aW9uIjp7ImNvbmZpZ1NvdXJjZSI6eyJlbnRyeVBvaW50IjoiLmdpdGh1Yi93b3JrZmxvd3MvcmVsZWFzZS55bWwiLCJ1cmkiOiJnaXQraHR0cHM6Ly9naXRodWIuY29tL293bmVyL3Byb2plY3RAcmVmcy9oZWFkcy9tYWluIn19fSwicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vc2xzYS5kZXYvcHJvdmVuYW5jZS92MC4yIiwic3ViamVjdCI6W3siZGlnZXN0Ijp7InNoYTI1NiI6ImYzOGQxOTAwYTJmNzM0NDNjYjgwMDkyODU0ODZmNDQ5ZjY4MzI0NjEwY2M2ZGY5OTQ5OTcxN2NkNGFkODc2NjQifSwibmFtZSI6InBrZzpucG0vZXhhbXBsZS1wYWNrYWdlQDEuMC4wIn1dfQ=="

    def _adapter(self, monkeypatch, document):
        from provenance.ecosystems import npm as npm_module

        class Stub:
            def get_json(self, url, **kwargs):
                return document

        adapter = npm_module.Npm(Stub())
        return adapter

    def _release(self):
        from provenance.ecosystems.base import Release

        return Release(package="example-package", version="1.0.0",
                       metadata={"attestations_url": "https://example/att"})

    def test_the_repository_is_read_from_a_v0_2_statement(self, monkeypatch):
        document = {"attestations": [
            {"predicateType": "https://slsa.dev/provenance/v0.2",
             "bundle": {"dsseEnvelope": {"payload": self.PAYLOAD}}}]}
        adapter = self._adapter(monkeypatch, document)
        assert adapter.expected_publisher(self._release()) == "owner/project"

    def test_a_v0_2_predicate_still_counts_as_provenance(self, monkeypatch):
        document = {"attestations": [
            {"predicateType": "https://slsa.dev/provenance/v0.2",
             "bundle": {"dsseEnvelope": {"payload": self.PAYLOAD}}}]}
        adapter = self._adapter(monkeypatch, document)
        assert adapter.registry_evidence(self._release()).present

class TestReusableWorkflowSigning:

    def test_the_build_extension_decides_the_publisher(self, monkeypatch):
        _stub_identity(monkeypatch, Identity(
            subject="https://github.com/workflow-owner/workflows/.github/workflows/release.yml@refs/heads/v1",
            issuer=ACTIONS,
            build={"source_repository": "https://github.com/package-owner/project"}))
        result = classify(
            make_entry({"signature": {"publicKey": {"content": "x"}}},
                       kind="hashedrekord"),
            expected_repository="package-owner/project")
        assert result.role is Role.PROJECT_SIGNER

    def test_the_subject_still_decides_when_there_is_no_extension(
            self, monkeypatch):
        _stub_identity(monkeypatch, Identity(subject=WORKFLOW, issuer=ACTIONS))
        assert classify(
            make_entry({"signature": {"publicKey": {"content": "x"}}},
                       kind="hashedrekord"),
            expected_repository="owner/project").role is Role.PROJECT_SIGNER

    def test_an_unrelated_repository_is_still_an_observer(self, monkeypatch):
        _stub_identity(monkeypatch, Identity(
            subject="https://github.com/someone/else/.github/workflows/a.yml@refs/heads/main",
            issuer=ACTIONS,
            build={"source_repository": "https://github.com/someone/else"}))
        assert classify(
            make_entry({"signature": {"publicKey": {"content": "x"}}},
                       kind="hashedrekord"),
            expected_repository="package-owner/project").role is Role.OBSERVER

class TestExtensionIsNotAFallbackForTheSubject:

    def test_the_subject_cannot_match_when_an_extension_disagrees(
            self, monkeypatch):
        _stub_identity(monkeypatch, Identity(
            subject="https://github.com/workflow-owner/workflows/.github/workflows/release.yml@refs/heads/v1",
            issuer=ACTIONS,
            build={"source_repository": "https://github.com/package-owner/project"}))
        result = classify(
            make_entry({"signature": {"publicKey": {"content": "x"}}},
                       kind="hashedrekord"),
            expected_repository="workflow-owner/workflows")
        assert result.role is Role.OBSERVER

class TestFourRoles:

    def _entry(self):
        return make_entry({"signatures": [{"verifier": "x"}]})

    def _signer(self, monkeypatch, repository="owner/project"):
        _stub_identity(monkeypatch, Identity(
            subject=f"https://github.com/{repository}/.github/workflows/a.yml",
            issuer=ACTIONS,
            build={"source_repository": f"https://github.com/{repository}"}))

    def test_a_registry_record_makes_a_publisher(self, monkeypatch):
        self._signer(monkeypatch)
        result = classify(self._entry(),
                          expected_repository="owner/project",
                          expected_issuer=ACTIONS,
                          registry_authorizes=True)
        assert result.role is Role.PUBLISHER
        assert result.registry_authorized

    def test_the_package_claiming_its_own_repository_does_not(self, monkeypatch):
        self._signer(monkeypatch)
        result = classify(self._entry(), expected_repository="owner/project")
        assert result.role is Role.PROJECT_SIGNER
        assert not result.registry_authorized
        assert result.names_the_project

    def test_a_caller_that_got_the_repository_from_a_registry_says_so(
            self, monkeypatch):
        self._signer(monkeypatch)
        result = classify(self._entry(), expected_repository="owner/project",
                          registry_authorizes=True, expected_issuer=ACTIONS)
        assert result.role is Role.PUBLISHER

    def test_another_project_is_an_observer(self, monkeypatch):
        self._signer(monkeypatch, repository="nexenio/eudi-cloak")
        result = classify(self._entry(), expected_repository="zxing/zxing")
        assert result.role is Role.OBSERVER

    def test_a_sibling_repository_is_still_the_project(self, monkeypatch):
        self._signer(monkeypatch, repository="owner/project-release")
        result = classify(self._entry(), expected_repository="owner/project")
        assert result.role is Role.PROJECT_SIGNER

    def test_a_raw_key_is_a_bare_key(self, monkeypatch):
        _stub_identity(monkeypatch, Identity(key_fingerprint="ab" * 8))
        result = classify(self._entry(), expected_repository="owner/project")
        assert result.role is Role.BARE_KEY
        assert not result.names_the_project

    def test_a_hosted_issuer_stays_an_observer(self, monkeypatch):
        _stub_identity(monkeypatch, Identity(
            subject="https://issuer.enforce.dev/x",
            issuer="https://issuer.enforce.dev/x"))
        result = classify(self._entry(), expected_repository="owner/project")
        assert result.role is Role.OBSERVER

    def test_the_role_says_nothing_about_the_signature(self, monkeypatch):
        self._signer(monkeypatch)
        result = classify(self._entry(), expected_repository="owner/project")
        assert result.role is Role.PROJECT_SIGNER
        assert result.could_be_provenance

    def test_every_role_has_a_single_token_form(self):
        assert Role.PROJECT_SIGNER.token == "project_signer"
        assert Role.BARE_KEY.token == "bare_key"
        assert all(" " not in role.token for role in Role)

class TestRegistryPublisherIsNotTheSelfClaim:

    def _adapter(self, document):
        from provenance.ecosystems import pypi as pypi_module

        class Stub:
            def get_json(self, url, **kwargs):
                return document

        return pypi_module.PyPI(Stub())

    def _release(self):
        from provenance.ecosystems.base import Release

        return Release(package="example", version="1.0.0",
                       artifact_url="https://files.pythonhosted.org/example.whl",
                       metadata={"filename": "example-1.0.0-py3-none-any.whl"},
                       declared_repository="example-org/example")

    def test_no_trusted_publisher_leaves_the_registry_silent(self):
        adapter = self._adapter({"urls": [{"packagetype": "bdist_wheel",
                                           "provenance": None}]})
        release = self._release()
        assert adapter.registry_publisher(release) == ""
        assert adapter.expected_publisher(release) == "example-org/example"

    def test_the_registrys_record_is_what_authorizes(self):
        adapter = self._adapter({"urls": [{"packagetype": "bdist_wheel"}],
                                 "attestation_bundles": [
                                     {"publisher": {"kind": "GitHub",
                                                    "repository":
                                                        "example-org/example"},
                                      "attestations": []}]})
        assert (adapter.registry_publisher(self._release())
                == "example-org/example")

    def test_google_publishers_use_the_service_account_at_tier_three(self):
        adapter = self._adapter({
            "attestation_bundles": [{
                "publisher": {
                    "kind": "Google",
                    "email": "service@example.invalid",
                },
                "attestations": [],
            }]
        })
        commands = adapter.verifier_commands(self._release())
        assert [tier for tier, _ in commands] == ["1", "3"]
        assert "--gcp-service-account" in commands[-1][1]
        assert "service@example.invalid" in commands[-1][1]

    def test_a_registry_without_records_says_nothing_for_every_package(self):
        from provenance.ecosystems import maven as maven_module
        from provenance.ecosystems.base import Release

        class Stub:
            def get_json(self, url, **kwargs):
                return None

            def get_bytes(self, url, **kwargs):
                return None

        adapter = maven_module.Maven(Stub())
        release = Release(package="org.junit.jupiter:junit-jupiter-api",
                          version="6.1.3",
                          declared_repository="junit-team/junit-framework")
        assert adapter.registry_publisher(release) == ""

class TestARegistryThatAnswersLeavesNoProjectSigner:

    def _signed_by(self, monkeypatch, repository):
        _stub_identity(
            monkeypatch,
            Identity(
                subject=f"https://github.com/{repository}/.github/workflows/"
                        f"release.yml@refs/tags/v1",
                issuer="https://token.actions.githubusercontent.com",
            ),
        )
        return make_entry({"signatures": [{"verifier": "x"}]})

    def test_a_registry_that_answers_makes_it_an_observer(self, monkeypatch):
        entry = self._signed_by(monkeypatch, "owner/project")
        result = classify(entry, expected_repository="owner/project",
                          registry_answers=True)
        assert result.role is Role.OBSERVER

    def test_and_it_is_still_countable_as_the_project(self, monkeypatch):
        entry = self._signed_by(monkeypatch, "owner/project")
        result = classify(entry, expected_repository="owner/project",
                          registry_answers=True)
        assert result.names_the_project

    def test_a_registry_that_cannot_answer_makes_it_a_project_signer(
            self, monkeypatch):
        entry = self._signed_by(monkeypatch, "owner/project")
        result = classify(entry, expected_repository="owner/project",
                          registry_answers=False)
        assert result.role is Role.PROJECT_SIGNER
        assert result.names_the_project

    def test_a_stranger_is_an_observer_either_way(self, monkeypatch):
        for answers in (True, False):
            entry = self._signed_by(monkeypatch, "someone-else/project")
            result = classify(entry, expected_repository="owner/project",
                              registry_answers=answers)
            assert result.role is Role.OBSERVER
            assert not result.names_the_project

    def test_a_registry_record_still_wins(self, monkeypatch):
        entry = self._signed_by(monkeypatch, "owner/project")
        result = classify(entry, expected_repository="owner/project",
                          registry_authorizes=True, registry_answers=True,
                          expected_issuer=ACTIONS)
        assert result.role is Role.PUBLISHER

    def test_release_classification_receives_the_registry_capability(
            self, monkeypatch):
        from provenance.attestor import classify_for_release
        from provenance.ecosystems.base import Release

        entry = self._signed_by(monkeypatch, "owner/project")

        class AnsweringRegistry:
            answers_publisher_authorization = True

            @staticmethod
            def registry_publisher(release):
                return ""

        result = classify_for_release(
            entry,
            AnsweringRegistry(),
            Release("example", "1", declared_repository="owner/project"),
        )
        assert result.role is Role.OBSERVER

def test_subject_and_build_extension_read_the_same_forges():
    from provenance.identity import Identity, repository_in

    gitlab = "https://gitlab.com/example-owner/example-project//.gitlab-ci.yml@refs/tags/0.9"
    github = "https://github.com/example-owner/example-project/.github/workflows/publish.yml@v1"
    assert Identity(subject=gitlab).repository == "example-owner/example-project"
    assert Identity(subject=gitlab).owner == "example-owner"
    assert Identity(subject=github).repository == "example-owner/example-project"
    for subject in (gitlab, github):
        assert Identity(subject=subject).repository == repository_in(subject)
    assert Identity(subject="service@example.invalid").repository == ""
