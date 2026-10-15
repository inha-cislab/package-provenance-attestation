import sys
from types import SimpleNamespace

from provenance.behavior import SCENARIOS, command_for, domains_in
from provenance.behavior.cargo_external import crate_bytes
from provenance.behavior import go_cache
from provenance.behavior.packagist_local import archive_bytes


def test_pypi_bad_input_uses_the_mismatched_repository():
    command = command_for(
        "pypi",
        "bad-input",
        {
            "mismatched_repository": "https://github.com/example/wrong",
            "artifact": "pypi:example.whl",
        },
    )
    assert "--repository" in command
    assert "https://github.com/example/wrong" in command
    assert command[0] == sys.executable


def test_missing_inputs_do_not_produce_a_partial_command():
    assert command_for("maven", "bad-input", {"signature": "example.asc"}) == []


def test_privacy_is_not_defined_for_crates_or_packagist():
    assert command_for("crates", "privacy", {}) == []
    assert command_for("packagist", "privacy", {}) == []


def test_domains_are_read_from_verbose_command_output():
    output = "GET https://pypi.org/a GET https://tuf-repo-cdn.sigstore.dev/timestamp.json"
    assert domains_in(output) == ["pypi.org", "tuf-repo-cdn.sigstore.dev"]


def test_pypi_privacy_uses_the_socket_trace_wrapper():
    command = command_for(
        "pypi",
        "privacy",
        {"repository": "https://github.com/psf/requests", "artifact": "pypi:requests.whl"},
    )
    assert command[2:4] == ["provenance.behavior.python_trace", "pypi_attestations"]


def test_scenario_coverage_matches_the_paper():
    assert {name for name, cases in SCENARIOS.items() if "default" in cases} == set(SCENARIOS)
    assert {name for name, cases in SCENARIOS.items() if "bad-input" in cases} == set(SCENARIOS)
    assert {name for name, cases in SCENARIOS.items() if "missing-entry" in cases} == {"pypi", "npm"}
    assert {name for name, cases in SCENARIOS.items() if "privacy" in cases} == {
        "pypi", "npm", "rubygems", "maven", "nuget", "go"
    }


def test_cargo_bad_input_is_a_valid_but_different_archive():
    original = crate_bytes(b"pub fn value() -> u8 { 1 }\n")
    modified = crate_bytes(b"pub fn value() -> u8 { 2 }\n")
    assert original != modified


def test_packagist_bad_input_is_a_valid_but_different_archive():
    original = archive_bytes("original\n")
    modified = archive_bytes("changed\n")
    assert original != modified


def test_go_privacy_probe_tolerates_a_missing_strace_output(monkeypatch, tmp_path):
    def fake_run(command, work, env):
        target = (
            work
            / "modcache"
            / "github.com"
            / "stretchr"
            / f"testify@{go_cache.VERSION}"
            / "README.md"
        )
        if command[:3] == ["go", "mod", "download"]:
            target.parent.mkdir(parents=True)
            target.write_text("original\n", encoding="utf-8")
        changed = target.exists() and "modified" in target.read_text(encoding="utf-8")
        return {"command": command, "exit_code": 1 if changed else 0,
                "stdout": "", "stderr": ""}

    monkeypatch.setattr(go_cache, "run", fake_run)
    monkeypatch.setattr(go_cache.shutil, "which", lambda name: "strace")
    monkeypatch.setattr(
        go_cache.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="go version test\n"),
    )

    result = go_cache.reproduce(tmp_path)

    assert result["privacy_exit_code"] == 0
    assert result["privacy_network_calls"] == 0
    assert result["bad_input"]["exit_code"] == 1
