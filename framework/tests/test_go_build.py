import base64
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from provenance.behavior import go_build


def test_only_artifact_checksum_changes():
    digest = "h1:" + base64.b64encode(bytes(32)).decode()
    mod = f"{go_build.PACKAGE} {go_build.VERSION}/go.mod {digest}"
    artifact = f"{go_build.PACKAGE} {go_build.VERSION} {digest}"
    changed = go_build.mismatched_sum(mod + "\n" + artifact + "\n")
    assert changed.splitlines()[0] == mod
    assert changed.splitlines()[1] != artifact
    assert len(base64.b64decode(changed.splitlines()[1].split()[2][3:])) == 32


def test_missing_artifact_checksum_is_not_silently_ignored():
    with pytest.raises(ValueError):
        go_build.mismatched_sum("")


def test_isolated_environment_has_absolute_caches(monkeypatch):
    monkeypatch.setenv("GONOSUMDB", "*")
    monkeypatch.setenv("GOFLAGS", "-mod=vendor")
    env = go_build.environment(Path("relative-work"))
    for name in ("GOPATH", "GOMODCACHE", "GOCACHE"):
        assert Path(env[name]).is_absolute()
    assert env["GONOSUMDB"] == "" and env["GOFLAGS"] == ""
    assert env["GOSUMDB"] == "sum.golang.org"


def test_local_sumdb_failure_is_recorded():
    with go_build.unavailable_sumdb() as (url, requests):
        with pytest.raises(HTTPError) as error:
            urlopen(url + "/lookup/example.com/test@v1.0.0")
        assert error.value.code == 503
        assert requests == ["/lookup/example.com/test@v1.0.0"]


def test_nonzero_exit_alone_does_not_pass():
    summary = {
        "baseline": {"exit_code": 0, "binary_created": True},
        "checksum_mismatch": {"exit_code": 1, "binary_created": False,
                              "stderr": "compiler error"},
        "sumdb_unavailable": {"exit_code": 1, "binary_created": False,
                              "stderr": "503"},
        "sumdb_requests": ["/lookup/example.com/test@v1.0.0"],
    }
    assert not go_build.passed(summary)
    summary["checksum_mismatch"]["stderr"] = "checksum mismatch"
    assert go_build.passed(summary)
