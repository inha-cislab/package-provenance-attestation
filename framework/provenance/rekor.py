from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from .http import Client

REKOR_URL = "https://rekor.sigstore.dev"

class EntryUnavailable(Exception):
    pass

class IndexQueryError(Exception):
    pass

@dataclass(frozen=True)
class Entry:
    uuid: str
    log_index: Optional[int]
    integrated_at: Optional[datetime]
    kind: str
    api_version: str
    body: Dict[str, Any] = field(repr=False)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def spec(self) -> Dict[str, Any]:
        return self.body.get("spec") or {}

    @property
    def materials(self) -> List[str]:
        spec = self.spec
        found: List[str] = []

        for signature in spec.get("signatures") or []:
            if signature.get("verifier"):
                found.append(signature["verifier"])

        envelope = (spec.get("content") or {}).get("envelope") or {}
        for signature in envelope.get("signatures") or []:
            for key in ("publicKey", "verifier"):
                if signature.get(key):
                    found.append(signature[key])

        for holder in ((spec.get("signature") or {}).get("publicKey"),
                       spec.get("publicKey")):
            material = _content_of(holder)
            if material:
                found.append(material)

        return found

    @property
    def payload_hash(self) -> Optional[str]:
        content = (self.spec.get("content") or {})
        recorded = content.get("payloadHash") or {}
        return recorded.get("value")

def _content_of(holder) -> Optional[str]:
    if isinstance(holder, str):
        return holder or None
    if isinstance(holder, dict):
        return holder.get("content") or None
    return None

class RekorClient:
    def __init__(self, client: Client, base_url: str = REKOR_URL) -> None:
        self._client = client
        self._base = base_url.rstrip("/")

    def search(self, algorithm: str, digest: str, *, attempts: int = 3) -> List[str]:
        url = f"{self._base}/api/v1/index/retrieve"
        error = None
        for attempt in range(attempts):
            response = self._client.request(
                url, method="POST", json_body={"hash": f"{algorithm}:{digest}"}
            )
            if response.ok:
                try:
                    found = response.json()
                except ValueError as exc:
                    found = None
                    error = f"unreadable index response: {exc}"
                if not isinstance(found, list) or any(not isinstance(item, str) for item in found):
                    error = "index response is not a list of entry IDs"
                elif found:
                    return list(found)
                else:
                    error = None
            else:
                error = f"index returned HTTP {response.status}"
            if attempt < attempts - 1:
                time.sleep(1 + attempt)
        if error is not None:
            raise IndexQueryError(f"{algorithm}:{digest}: {error}")
        return []

    def search_all(self, digests: Dict[str, str]) -> Dict[str, List[str]]:
        return {name: self.search(name, value) for name, value in digests.items()}

    def entry(self, uuid: str) -> Entry:
        url = f"{self._base}/api/v1/log/entries/{uuid}"
        response = self._client.request(url)
        if not response.ok:
            raise EntryUnavailable(f"{uuid}: log returned {response.status}")
        try:
            payload = next(iter(response.json().values()))
            body = json.loads(base64.b64decode(payload["body"]))
        except Exception as error:
            raise EntryUnavailable(f"{uuid}: unreadable entry") from error

        integrated = payload.get("integratedTime")
        return Entry(
            uuid=uuid,
            log_index=payload.get("logIndex"),
            integrated_at=(
                datetime.fromtimestamp(integrated, tz=timezone.utc)
                if integrated
                else None
            ),
            kind=body.get("kind", ""),
            api_version=body.get("apiVersion", ""),
            body=body,
            raw=payload,
        )

    def entry_at_index(self, log_index: int) -> Entry:
        url = f"{self._base}/api/v1/log/entries?logIndex={log_index}"
        response = self._client.request(url)
        if not response.ok:
            raise EntryUnavailable(f"index {log_index}: log returned {response.status}")
        try:
            uuid = next(iter(response.json()))
        except Exception as error:
            raise EntryUnavailable(f"index {log_index}: unreadable response") from error
        return self.entry(uuid)

    def entries(self, uuids: Sequence[str]) -> List[Entry]:
        found = []
        for uuid in uuids:
            try:
                found.append(self.entry(uuid))
            except EntryUnavailable:
                continue
        return found
