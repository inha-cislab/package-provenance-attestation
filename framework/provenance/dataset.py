from __future__ import annotations

import concurrent.futures
import datetime as dt
import math
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from . import ecosystems
from .http import Client

RANKING_API = "https://packages.ecosyste.ms/api/v1/registries"


@dataclass(frozen=True)
class RankingSpec:
    registry: str
    metric: str


RANKING_SPECS: Dict[str, RankingSpec] = {
    "pypi": RankingSpec("pypi.org", "downloads"),
    "npm": RankingSpec("npmjs.org", "dependent_packages_count"),
    "rubygems": RankingSpec("rubygems.org", "downloads"),
    "maven": RankingSpec("repo1.maven.org", "dependent_packages_count"),
    "nuget": RankingSpec("nuget.org", "downloads"),
    "packagist": RankingSpec("packagist.org", "downloads"),
    "go": RankingSpec("proxy.golang.org", "dependent_packages_count"),
    "crates": RankingSpec("crates.io", "downloads"),
}


@dataclass(frozen=True)
class RankedPackage:
    ecosystem: str
    rank: int
    package: str
    ranking_metric: str
    ranking_value: Optional[int]
    ranking_source: str = "packages.ecosyste.ms API"


@dataclass(frozen=True)
class Coordinate:
    ecosystem: str
    rank: int
    package: str
    version: str
    resolved: bool
    ranking_metric: str
    ranking_value: Optional[int]
    ranking_source: str
    captured_at: str
    resolution_detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def collect_ranking(
    client: Client,
    ecosystem: str,
    *,
    limit: int = 1000,
    workers: int = 4,
) -> List[RankedPackage]:
    if ecosystem not in RANKING_SPECS:
        raise ValueError(f"unsupported ecosystem: {ecosystem}")
    if limit < 1:
        raise ValueError("limit must be positive")

    spec = RANKING_SPECS[ecosystem]
    per_page = min(100, limit)
    page_count = math.ceil(limit / per_page)

    def fetch(page: int) -> tuple[int, list]:
        registry = urllib.parse.quote(spec.registry, safe="")
        query = urllib.parse.urlencode(
            {
                "sort": spec.metric,
                "order": "desc",
                "per_page": per_page,
                "page": page,
            }
        )
        rows = client.get_json(f"{RANKING_API}/{registry}/packages?{query}")
        if not isinstance(rows, list):
            raise RuntimeError(
                f"{ecosystem}: ranking page {page} did not return a list"
            )
        return page, rows

    pages: Dict[int, list] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(fetch, page) for page in range(1, page_count + 1)]
        for future in concurrent.futures.as_completed(futures):
            page, rows = future.result()
            pages[page] = rows

    rows = [
        row
        for page in range(1, page_count + 1)
        for row in pages[page]
    ][:limit]
    if len(rows) != limit:
        raise RuntimeError(
            f"{ecosystem}: expected {limit} ranked packages, received {len(rows)}"
        )

    names = [str(row.get("name") or "").strip() for row in rows]
    if any(not name for name in names):
        raise RuntimeError(f"{ecosystem}: ranking contains an empty package name")
    if len(set(names)) != len(names):
        raise RuntimeError(f"{ecosystem}: ranking contains duplicate package names")

    return [
        RankedPackage(
            ecosystem=ecosystem,
            rank=index,
            package=name,
            ranking_metric=spec.metric,
            ranking_value=_integer_or_none(row.get(spec.metric)),
        )
        for index, (name, row) in enumerate(zip(names, rows), 1)
    ]


def load_fixed_ranking(
    directory: Path,
    ecosystem: str,
    *,
    limit: int = 1000,
) -> List[RankedPackage]:
    path = directory / f"{ecosystem}.txt"
    names = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ][:limit]
    if len(names) != limit:
        raise ValueError(f"{path}: expected {limit} package names, found {len(names)}")
    spec = RANKING_SPECS[ecosystem]
    return [
        RankedPackage(
            ecosystem=ecosystem,
            rank=rank,
            package=name,
            ranking_metric=spec.metric,
            ranking_value=None,
            ranking_source=str(path),
        )
        for rank, name in enumerate(names, 1)
    ]


def resolve_ranking(
    adapter,
    ranking: Iterable[RankedPackage],
    *,
    captured_at: str,
    workers: int = 8,
    progress: Optional[Callable[[int, int, Coordinate], None]] = None,
) -> List[Coordinate]:
    selected = list(ranking)

    def resolve(index_and_package) -> Coordinate:
        index, item = index_and_package
        try:
            release = adapter.resolve(item.package)
            version = release.version if release.resolved else ""
            detail = "" if version else "package did not resolve"
        except Exception as error:
            version = ""
            detail = str(error)[:200]
        coordinate = Coordinate(
            ecosystem=item.ecosystem,
            rank=item.rank,
            package=item.package,
            version=version,
            resolved=bool(version),
            ranking_metric=item.ranking_metric,
            ranking_value=item.ranking_value,
            ranking_source=item.ranking_source,
            captured_at=captured_at,
            resolution_detail=detail,
        )
        if progress is not None:
            progress(index + 1, len(selected), coordinate)
        return coordinate

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(resolve, enumerate(selected)))


def construct(
    client: Client,
    selected_ecosystems: Sequence[str],
    *,
    limit: int = 1000,
    workers: int = 8,
    ranking_directory: Optional[Path] = None,
    captured_at: Optional[str] = None,
    progress: Optional[Callable[[int, int, Coordinate], None]] = None,
) -> List[Coordinate]:
    timestamp = captured_at or dt.datetime.now(dt.timezone.utc).isoformat()
    coordinates: List[Coordinate] = []
    for name in selected_ecosystems:
        ranking = (
            load_fixed_ranking(ranking_directory, name, limit=limit)
            if ranking_directory
            else collect_ranking(client, name, limit=limit, workers=min(workers, 4))
        )
        adapter = ecosystems.load(name, client)
        coordinates.extend(
            resolve_ranking(
                adapter,
                ranking,
                captured_at=timestamp,
                workers=workers,
                progress=progress,
            )
        )
    return coordinates


def _integer_or_none(value) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
