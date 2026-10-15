from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Dict, Iterable, List, Optional

from . import collect, ecosystems
from .attestor import classify_for_release
from .http import Client
from .rekor import RekorClient
from .verify import verify_with_registry_tool

SCHEMA = "measurement/1"


@dataclass(frozen=True)
class Coordinate:
    ecosystem: str
    package: str
    version: str
    rank: Optional[int] = None

    def as_dict(self) -> dict:
        record = asdict(self)
        if self.rank is None:
            record.pop("rank")
        return record


def load_coordinates(path: Path) -> List[Coordinate]:
    """Read package-version coordinates from a CSV file."""
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        required = {"ecosystem", "package", "version"}
        missing = required.difference(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"coordinate CSV lacks column(s): {', '.join(sorted(missing))}"
            )

        coordinates: List[Coordinate] = []
        seen = set()
        known = set(ecosystems.names())
        for line_number, row in enumerate(reader, start=2):
            ecosystem = (row.get("ecosystem") or "").strip().lower()
            package = (row.get("package") or "").strip()
            version = (row.get("version") or "").strip()
            if not ecosystem or not package:
                raise ValueError(
                    f"coordinate CSV line {line_number} has an empty required value"
                )
            if ecosystem not in known:
                raise ValueError(
                    f"coordinate CSV line {line_number} has unknown ecosystem "
                    f"{ecosystem!r}"
                )
            key = (ecosystem, package, version)
            if key in seen:
                raise ValueError(
                    f"coordinate CSV line {line_number} repeats {key!r}"
                )
            seen.add(key)

            rank_text = (row.get("rank") or "").strip()
            try:
                rank = int(rank_text) if rank_text else None
            except ValueError as error:
                raise ValueError(
                    f"coordinate CSV line {line_number} has invalid rank "
                    f"{rank_text!r}"
                ) from error
            coordinates.append(Coordinate(ecosystem, package, version, rank))

    if not coordinates:
        raise ValueError("coordinate CSV contains no package-version rows")
    return coordinates


class Runner:
    """Run collection and evidence verification for fixed coordinates."""

    def __init__(self, *, registry_verifier: bool = False,
                 use_registry_bundles: bool = True) -> None:
        self.client = Client()
        self.rekor = RekorClient(self.client)
        self.adapters = {
            name: ecosystems.load(name, self.client) for name in ecosystems.names()
        }
        self.registry_keys: Dict[str, dict] = {}
        self._registry_keys_lock = Lock()
        self.run_registry_verifier = registry_verifier
        self.use_registry_bundles = use_registry_bundles

    def measure(self, coordinate: Coordinate) -> dict:
        record = {
            "schema": SCHEMA,
            "coordinate": coordinate.as_dict(),
        }
        if not coordinate.version:
            skipped = {
                "status": "unresolved",
                "detail": "no release version was supplied",
            }
            record["registry_path"] = dict(skipped)
            record["public_log_path"] = dict(skipped)
            if self.run_registry_verifier:
                record["registry_verifier"] = dict(skipped)
            return record

        adapter = self.adapters[coordinate.ecosystem]

        try:
            registry = collect.observe_registry(
                adapter, coordinate.package, coordinate.version
            )
            record["registry_path"] = registry.as_dict()
        except Exception as error:
            record["registry_path"] = _error(error)

        try:
            log = collect.observe_log(
                adapter,
                self.rekor,
                coordinate.package,
                coordinate.version,
            )
            release = adapter.resolve(coordinate.package, coordinate.version)

            def classifier(entry):
                return classify_for_release(
                    entry,
                    adapter,
                    release,
                    self._keys(coordinate.ecosystem),
                )

            collect.verify_log(
                adapter,
                self.rekor,
                log,
                classifier=classifier,
                use_registry_bundles=self.use_registry_bundles,
            )
            record["public_log_path"] = log.as_dict()
        except Exception as error:
            record["public_log_path"] = _error(error)

        if self.run_registry_verifier:
            try:
                outcome = verify_with_registry_tool(
                    adapter, coordinate.package, coordinate.version
                )
                record["registry_verifier"] = outcome.as_dict()
            except Exception as error:
                record["registry_verifier"] = _error(error)

        return record

    def _keys(self, ecosystem: str) -> dict:
        with self._registry_keys_lock:
            if ecosystem not in self.registry_keys:
                adapter = self.adapters[ecosystem]
                self.registry_keys[ecosystem] = (
                    adapter.registry_keys()
                    if hasattr(adapter, "registry_keys") else {}
                )
            return self.registry_keys[ecosystem]


def run(coordinates: Iterable[Coordinate], *, workers: int = 6,
        registry_verifier: bool = False,
        use_registry_bundles: bool = True, progress=None) -> List[dict]:
    selected = list(coordinates)
    runner = Runner(
        registry_verifier=registry_verifier,
        use_registry_bundles=use_registry_bundles,
    )

    def measure(index_and_coordinate):
        index, coordinate = index_and_coordinate
        record = runner.measure(coordinate)
        if progress is not None:
            progress(index + 1, len(selected), record)
        return record

    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(measure, enumerate(selected)))


def _error(error: Exception) -> dict:
    return {"error": type(error).__name__, "detail": str(error)}
