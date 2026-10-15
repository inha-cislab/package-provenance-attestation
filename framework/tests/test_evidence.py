import csv
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from provenance import cli
from provenance.collect.log_path import LogObservation
from provenance.verify import evidence
from provenance.verify.registry import crates, go, maven, nuget


def coordinates(path):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ecosystem", "package", "version", "digest_sha256"])
        writer.writeheader()
        writer.writerows([
            {"ecosystem": "npm", "package": "example-a", "version": "1.0.0"},
            {"ecosystem": "maven", "package": "example:one", "version": "2.0.0", "digest_sha256": "a" * 64},
            {"ecosystem": "maven", "package": "example:two", "version": "3.0.0"},
        ])
    return path


def test_selects_all_and_only_requested_ecosystem(tmp_path):
    rows = evidence.load_coordinates(coordinates(tmp_path / "input.csv"), "maven")
    assert [row["package"] for row in rows] == ["example:one", "example:two"]
    assert rows[0]["digest_sha256"] == "a" * 64
    assert [row["version"] for row in rows] == ["2.0.0", "3.0.0"]
    with pytest.raises(ValueError, match="no go coordinates"):
        evidence.load_coordinates(tmp_path / "input.csv", "go")


@pytest.mark.parametrize("ecosystem,module,function", [
    ("crates", crates, "verify_crate"), ("go", go, "verify_go"),
    ("maven", maven, "verify_maven"), ("nuget", nuget, "verify_nuget"),
])
def test_registry_dispatch(ecosystem, module, function, tmp_path, monkeypatch):
    verifier = Mock(return_value={"outcome": "verified"})
    monkeypatch.setattr(module, function, verifier)
    result = evidence.verify_package(ecosystem, {"package": "example", "version": "1.0.0"},
                                     path="registry", work_root=tmp_path)
    assert result["outcome"] == "verified"
    assert result["version"] == "1.0.0"
    assert verifier.call_args.args[0]["version"] == "1.0.0"
    if ecosystem != "crates":
        assert verifier.call_args.kwargs["work_root"] == tmp_path.resolve()


@pytest.mark.parametrize("ecosystem", ["pypi", "npm", "rubygems"])
def test_log_dispatch_preserves_existing_verifier(ecosystem, tmp_path, monkeypatch):
    adapter = SimpleNamespace(client=Mock(), resolve=Mock(return_value=object()))
    monkeypatch.setattr(evidence.ecosystems, "load", lambda *args: adapter)
    observation = LogObservation(ecosystem, "example", "1.0.0", "found",
                                 entries={"sha256": ["synthetic-entry"]})
    monkeypatch.setattr(evidence.collect, "observe_log", Mock(return_value=observation))

    def verify(*args, **kwargs):
        assert args[0] is adapter
        assert callable(kwargs["classifier"])
        assert "verifier" not in kwargs
        observation.verification = {"verified_and_bound": 1}

    monkeypatch.setattr(evidence.collect, "verify_log", verify)
    result = evidence.verify_package(ecosystem, {"package": "example", "version": "1.0.0"},
                                     path="log", work_root=tmp_path)
    assert result["outcome"] == "verified"
    assert result["verification"]["verified_and_bound"] == 1


def test_npm_registry_dispatch(tmp_path, monkeypatch):
    verifier = Mock(return_value=SimpleNamespace(as_dict=lambda: {"outcome": "verified"}))
    monkeypatch.setattr(evidence, "verify_registry_tool", verifier)
    result = evidence.verify_package("npm", {"package": "example", "version": "1.0.0"},
                                     path="registry", work_root=tmp_path)
    assert result["outcome"] == "verified"
    verifier.assert_called_once()


def test_missing_csv_version_is_not_resolved(tmp_path, monkeypatch):
    adapter = Mock()
    monkeypatch.setattr(evidence.ecosystems, "load", lambda *args: adapter)
    result = evidence.verify_package("go", {"package": "example", "version": ""},
                                     path="registry", work_root=tmp_path)
    assert result["outcome"] == "unresolved"
    adapter.resolve.assert_not_called()


def test_single_package_can_resolve_version(tmp_path, monkeypatch):
    adapter = Mock()
    adapter.resolve.return_value.version = "1.2.3"
    monkeypatch.setattr(evidence.ecosystems, "load", lambda *args: adapter)
    verifier = Mock(return_value={"outcome": "verified"})
    monkeypatch.setattr(crates, "verify_crate", verifier)
    result = evidence.verify_package("crates", {"package": "example"}, path="registry",
                                     work_root=tmp_path, resolve_version=True)
    assert result["version"] == "1.2.3"
    assert verifier.call_args.args[0]["version"] == "1.2.3"


def test_batch_keeps_order_and_continues_after_error(tmp_path, monkeypatch):
    def verify(row):
        if row["package"] == "bad":
            raise OSError("synthetic download error")
        return {"outcome": "verified"}

    monkeypatch.setattr(crates, "verify_crate", verify)
    rows = [{"package": name, "version": "1.0.0"} for name in ("bad", "good")]
    results = evidence.run("crates", rows, path="registry", work_root=tmp_path, workers=2)
    assert [row["package"] for row in results] == ["bad", "good"]
    assert [row["outcome"] for row in results] == ["error", "verified"]
    assert all("toolchain" in row for row in results)


def test_mixed_batch_rejected(tmp_path):
    with pytest.raises(ValueError, match="selected ecosystem"):
        evidence.run("crates", [{"ecosystem": "npm"}], path="registry", work_root=tmp_path)


def test_cli_csv_filters_without_limit(tmp_path, monkeypatch):
    source = coordinates(tmp_path / "input.csv")
    out = tmp_path / "out.jsonl"
    runner = Mock(return_value=[{"outcome": "verified"}, {"outcome": "verified"}])
    monkeypatch.setattr(evidence, "run", runner)
    assert cli.main(["verify-evidence", "--ecosystem", "maven", "--path", "registry",
                     "--coordinates", str(source), "--out", str(out)]) == 0
    assert len(runner.call_args.args[1]) == 2
    assert runner.call_args.kwargs["resolve_version"] is False
    assert len(out.read_text().splitlines()) == 2


def test_cli_single_failure_is_nonzero(tmp_path, monkeypatch):
    monkeypatch.setattr(evidence, "run", Mock(return_value=[{"outcome": "verification failed"}]))
    assert cli.main(["verify-evidence", "--ecosystem", "crates", "--path", "registry",
                     "--package", "example", "--version", "1.0.0", "--workdir", str(tmp_path)]) == 1


def test_cli_refuses_existing_output(tmp_path, monkeypatch):
    out = coordinates(tmp_path / "existing.csv")
    original = out.read_bytes()
    runner = Mock()
    monkeypatch.setattr(evidence, "run", runner)
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        cli.main(["verify-evidence", "--ecosystem", "crates", "--path", "registry",
                  "--package", "example", "--out", str(out)])
    runner.assert_not_called()
    assert out.read_bytes() == original


def test_cli_rejects_version_override_for_csv(tmp_path):
    with pytest.raises(SystemExit, match="only to --package"):
        cli.main(["verify-evidence", "--ecosystem", "maven", "--path", "registry",
                  "--coordinates", str(tmp_path / "input.csv"), "--version", "1.0.0"])


def test_key_lookup_checks_each_keyring(monkeypatch):
    monkeypatch.setattr(maven, "read_bytes", lambda *args, **kwargs: b"-----BEGIN PGP PUBLIC KEY-----")
    process = Mock(side_effect=[
        SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
        SimpleNamespace(returncode=1, stdout=b"", stderr=b""),
        SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
        SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
    ])
    monkeypatch.setattr(maven, "run_gpg", process)
    assert maven.fetch_gpg_key("SYNTHETIC", {"GNUPGHOME": "first"})[0]
    assert maven.fetch_gpg_key("SYNTHETIC", {"GNUPGHOME": "second"})[0]
    assert process.call_count == 4


def test_crate_digest_mismatch_is_not_verified(monkeypatch):
    monkeypatch.setattr(crates, "read_bytes", lambda url: json.dumps({"vers": "1.0.0", "cksum": "a" * 64}).encode())
    monkeypatch.setattr(crates, "stream_sha256", lambda url: ("b" * 64, 10))
    result = crates.verify_crate({"package": "example", "version": "1.0.0"})
    assert result["outcome"] == "digest mismatch"
