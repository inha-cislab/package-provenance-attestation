import csv

import pytest

from provenance import ecosystems, measurement
from provenance.http import Client


def _write_coordinates(path, rows, fieldnames=("rank", "ecosystem", "package", "version")):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_coordinate_manifest_preserves_exact_versions_and_ignores_result_columns(
    tmp_path,
):
    path = tmp_path / "packages.csv"
    _write_coordinates(
        path,
        [{
            "rank": "2",
            "ecosystem": "pypi",
            "package": "packaging",
            "version": "26.3",
            "registry_present": "True",
        }],
        fieldnames=(
            "rank", "ecosystem", "package", "version", "registry_present"
        ),
    )

    assert measurement.load_coordinates(path) == [
        measurement.Coordinate("pypi", "packaging", "26.3", 2)
    ]


@pytest.mark.parametrize("missing", ["ecosystem", "package", "version"])
def test_coordinate_manifest_requires_every_coordinate_column(tmp_path, missing):
    path = tmp_path / "bad.csv"
    fields = [name for name in ("ecosystem", "package", "version") if name != missing]
    _write_coordinates(path, [{name: "x" for name in fields}], fieldnames=fields)

    with pytest.raises(ValueError, match=missing):
        measurement.load_coordinates(path)


def test_coordinate_manifest_rejects_duplicate_package_versions(tmp_path):
    path = tmp_path / "duplicates.csv"
    row = {"rank": "1", "ecosystem": "npm", "package": "react", "version": "19.1.1"}
    _write_coordinates(path, [row, {**row, "rank": "2"}])

    with pytest.raises(ValueError, match="repeats"):
        measurement.load_coordinates(path)


def test_coordinate_manifest_retains_a_snapshot_row_that_did_not_resolve(tmp_path):
    path = tmp_path / "unresolved.csv"
    _write_coordinates(path, [{
        "rank": "1", "ecosystem": "go", "package": "retract", "version": ""
    }])

    assert measurement.load_coordinates(path) == [
        measurement.Coordinate("go", "retract", "", 1)
    ]


def test_only_group_a_registries_answer_publisher_authorization():
    client = Client()
    expected = {"pypi", "npm", "rubygems"}
    actual = {
        name for name in ecosystems.names()
        if ecosystems.load(name, client).answers_publisher_authorization
    }
    assert actual == expected


def test_packagist_distinguishes_field_exposure_from_usable_evidence():
    from provenance.collect.registry_path import observe
    from provenance.ecosystems.packagist import Packagist

    class Stub:
        def get_json(self, url, **kwargs):
            return {
                "packages": {
                    "vendor/package": [{
                        "version": "1.0.0",
                        "dist": {"url": "https://example.test/a.zip", "shasum": ""},
                    }]
                }
            }

    result = observe(Packagist(Stub()), "vendor/package", "1.0.0")
    assert result.exposed
    assert not result.present


def test_measure_command_accepts_a_coordinate_file():
    from provenance import cli

    parsed = cli._build_parser().parse_args([
        "measure",
        "--coordinates", "current-coordinates.csv",
        "--out", "measurement.jsonl",
    ])
    assert parsed.coordinates.name == "current-coordinates.csv"
    assert not parsed.registry_verifier
