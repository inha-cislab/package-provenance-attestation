import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

from provenance.verify.registry import maven


DATASET = Path(__file__).resolve().parents[2] / "dataset"


def test_gpg_keyring_failures_are_distinct_from_missing_keys():
    assert maven.gpg_keyring_error(
        "gpg: keyblock resource: add_keyblock_resource failed"
    )
    assert maven.gpg_keyring_error(
        "gpg: failed to create temporary file"
    )
    assert not maven.gpg_keyring_error(
        "gpg: keyserver receive failed: No data"
    )


def _assert_manifest(root, manifest_path):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    recorded = {item["path"]: item for item in manifest["files"]}
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != manifest_path
    }
    assert set(recorded) == actual
    for relative, item in recorded.items():
        data = (root / relative).read_bytes()
        assert item["bytes"] == len(data)
        assert item["sha256"] == hashlib.sha256(data).hexdigest()
        if "rows" in item:
            assert item["rows"] == len(data.splitlines())


def test_dataset_manifests_match_every_file():
    _assert_manifest(DATASET, DATASET / "MANIFEST.json")
    corpus = DATASET / "corpus"
    _assert_manifest(corpus, corpus / "MANIFEST.json")


def _summary():
    with (DATASET / "summary.csv").open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_corpus_lists_match_ranked_csv():
    corpus = DATASET / "corpus"
    with (corpus / "corpus.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["ecosystem"]].append(row)
    assert len(rows) == 8000
    assert set(grouped) == {row["ecosystem"] for row in _summary()}
    for ecosystem, selected in grouped.items():
        names = (corpus / f"{ecosystem}.txt").read_text(encoding="utf-8").splitlines()
        assert len(selected) == len(names) == 1000
        assert [int(row["rank"]) for row in selected] == list(range(1, 1001))
        assert [row["package"] for row in selected] == names


def test_summary_counts_are_within_population():
    for row in _summary():
        assert int(row["packages"]) == 1000
        for key in ("registry_exposure", "registry_evidence", "verified_at_level", "log_matches"):
            assert 0 <= int(row[key]) <= int(row["packages"])
        assert int(row["verified_at_level"]) <= int(row["registry_evidence"])
        assert int(row["registry_evidence"]) <= int(row["registry_exposure"])


def test_summary_roles_partition_digest_matches():
    for row in _summary():
        roles = ("log_publisher", "log_project_signer", "log_observer", "log_bare_key")
        assert all(int(row[key]) >= 0 for key in roles)
        assert sum(int(row[key]) for key in roles) == int(row["log_matches"])


def test_readme_main_results_match_summary():
    names = {"pypi": "PyPI", "npm": "npm", "rubygems": "RubyGems", "maven": "Maven",
             "nuget": "NuGet", "crates": "crates.io", "packagist": "Packagist", "go": "Go Modules"}
    readme = (DATASET.parent / "README.md").read_text(encoding="utf-8")
    assert "## Main results" in readme
    table = {}
    for line in readme.splitlines():
        if line.startswith("| "):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            table[cells[0]] = cells[1:]
    fields = ("registry_exposure", "verified_at_level", "log_matches", "log_publisher",
              "log_project_signer", "log_observer", "log_bare_key")
    for row in _summary():
        cells = table[names[row["ecosystem"]]]
        assert cells[0] == row["group"]
        assert [int(cell.replace(",", "")) for cell in cells[1:]] == [int(row[key]) for key in fields]
