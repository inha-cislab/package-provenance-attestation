from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Mapping, Optional

USER_AGENT = "package-provenance/1.0 (research measurement)"

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})

class TransportError(Exception):
    pass

@dataclass(frozen=True)
class Response:
    status: int
    body: bytes

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        return json.loads(self.body)

class Client:
    def __init__(
        self,
        *,
        user_agent: str = USER_AGENT,
        timeout: float = 90.0,
        retries: int = 4,
        backoff: float = 2.0,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        json_body: Any = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        consume: Optional[Callable[[BinaryIO], None]] = None,
    ) -> Response:
        payload = json.dumps(json_body).encode() if json_body is not None else None
        merged = {"User-Agent": self.user_agent}
        if payload is not None:
            merged["Content-Type"] = "application/json"
        merged.update(headers or {})

        last_error: Optional[BaseException] = None
        for attempt in range(self.retries):
            request = urllib.request.Request(
                url, data=payload, headers=merged, method=method
            )
            try:
                with urllib.request.urlopen(
                    request, timeout=timeout or self.timeout
                ) as response:
                    if consume is not None:
                        consume(response)
                        return Response(response.status, b"")
                    return Response(response.status, response.read())
            except urllib.error.HTTPError as error:
                if error.code in RETRYABLE_STATUS and attempt < self.retries - 1:
                    time.sleep(self.backoff * (attempt + 1))
                    continue
                return Response(error.code, b"")
            except Exception as error:
                last_error = error
                if attempt < self.retries - 1:
                    time.sleep(self.backoff * (attempt + 1))
                    continue
        raise TransportError(f"{method} {url} failed: {last_error}")

    def get_json(self, url: str, **kwargs: Any) -> Optional[Any]:
        response = self.request(url, **kwargs)
        if not response.ok:
            return None
        try:
            return response.json()
        except ValueError:
            return None

    def get_bytes(self, url: str, **kwargs: Any) -> Optional[bytes]:
        response = self.request(url, **kwargs)
        return response.body if response.ok and response.body else None

    def exists(self, url: str) -> bool:
        return self.request(url, method="HEAD").ok

def quote(value: str, safe: str = "") -> str:
    return urllib.parse.quote(value, safe=safe)
