import hashlib
import io
import json
from types import SimpleNamespace

import pytest

from provenance import ecosystems
from provenance.collect.log_path import observe
from provenance.digest import digest_artifact
from provenance.ecosystems.base import Release
from provenance.http import Client, Response, TransportError
from provenance.rekor import IndexQueryError, RekorClient


class Stream(io.BytesIO):
    status = 200

    def __init__(self, body, length=None):
        super().__init__(body)
        self.headers = {"Content-Length": str(len(body) if length is None else length)}

    def read(self, size=-1):
        assert 0 < size <= 1024 * 1024
        return super().read(size)


@pytest.mark.parametrize("name", ecosystems.names())
def test_each_ecosystem_hashes_downloaded_bytes_for_both_queries(name, monkeypatch):
    body = b"downloaded artifact, not the registry digest" * 50000
    calls = []

    def open_url(request, **kwargs):
        calls.append(request.full_url)
        return Stream(body)

    monkeypatch.setattr("urllib.request.urlopen", open_url)
    client = Client(retries=1)
    adapter = ecosystems.load(name, client)
    release = Release("example", "1.0.0", artifact_url="https://example.invalid/artifact")
    monkeypatch.setattr(adapter, "resolve", lambda *args: release)
    monkeypatch.setattr(adapter, "published_digest", lambda *args: pytest.fail("registry digest was consulted"))
    monkeypatch.setattr(adapter, "log_hints", lambda release: [])
    queries = {}

    def search_all(digests):
        queries.update(digests)
        return {a: [] for a in digests}

    result = observe(adapter, SimpleNamespace(search_all=search_all), "example", "1.0.0")
    expected = {a: hashlib.new(a, body).hexdigest() for a in ("sha256", "sha512")}
    assert tuple(adapter.digest_algorithms) == ("sha256", "sha512")
    assert result.digests == queries == expected
    assert calls == [release.artifact_url]
    assert result.status == "not found"


def test_incomplete_download_is_not_hashed_or_queried(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: Stream(b"short", length=100))
    with pytest.raises(TransportError, match="incomplete artifact"):
        digest_artifact(Client(retries=1), "https://example.invalid/artifact")


def test_retry_restarts_hashing_from_the_beginning(monkeypatch):
    responses = iter([Stream(b"partial", length=100), Stream(b"complete")])
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: next(responses))
    result = digest_artifact(Client(retries=2, backoff=0), "https://example.invalid/artifact")
    assert result.size == len(b"complete")
    assert result.values == {a: hashlib.new(a, b"complete").hexdigest() for a in ("sha256", "sha512")}


def test_unavailable_artifact_does_not_fall_back_to_registry_hash():
    adapter = SimpleNamespace(
        name="pypi", client=SimpleNamespace(request=lambda *a, **k: Response(404, b"")),
        resolve=lambda *a: Release("example", "1", artifact_url="https://example.invalid/a"),
        artifact_url=lambda r: r.artifact_url,
        published_digest=lambda *a: pytest.fail("must not substitute registry digest"),
    )
    result = observe(adapter, SimpleNamespace(search_all=lambda *a: pytest.fail("must not query")), "example", "1")
    assert result.status == "unreachable"
    assert result.digests == {}


def test_no_artifact_url_is_not_an_empty_log_search():
    adapter = SimpleNamespace(name="maven", resolve=lambda *a: Release("example", "1"), artifact_url=lambda r: "")
    result = observe(adapter, SimpleNamespace(search_all=lambda *a: pytest.fail("must not query")), "example", "1")
    assert result.status == "no artifact"


@pytest.mark.parametrize("response", [Response(429, b""), Response(500, b""), Response(200, b"invalid"), Response(200, b"{}")])
def test_index_errors_are_not_not_found(response, monkeypatch):
    monkeypatch.setattr("provenance.rekor.time.sleep", lambda _: None)
    rekor = RekorClient(SimpleNamespace(request=lambda *a, **k: response))
    with pytest.raises(IndexQueryError):
        rekor.search("sha512", "a" * 128)


def test_empty_index_response_is_retried(monkeypatch):
    calls = []
    monkeypatch.setattr("provenance.rekor.time.sleep", lambda _: None)

    def request(*args, **kwargs):
        calls.append(kwargs["json_body"])
        return Response(200, b"[]")

    assert RekorClient(SimpleNamespace(request=request)).search("sha256", "a" * 64) == []
    assert len(calls) == 3


def test_index_retry_can_recover_from_http_error(monkeypatch):
    responses = iter([Response(503, b""), Response(200, json.dumps(["entry"]).encode())])
    monkeypatch.setattr("provenance.rekor.time.sleep", lambda _: None)
    client = SimpleNamespace(request=lambda *a, **k: next(responses))
    assert RekorClient(client).search("sha256", "a" * 64) == ["entry"]


def test_index_retry_can_recover_with_empty_success(monkeypatch):
    responses = iter([Response(503, b""), Response(200, b"[]"), Response(200, b"[]")])
    monkeypatch.setattr("provenance.rekor.time.sleep", lambda _: None)
    client = SimpleNamespace(request=lambda *a, **k: next(responses))
    assert RekorClient(client).search("sha256", "a" * 64) == []
