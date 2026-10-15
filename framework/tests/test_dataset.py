from pathlib import Path
from urllib.parse import parse_qs, urlparse

from provenance import dataset
from provenance.ecosystems.base import Release


class RankingClient:
    def get_json(self, url):
        query = parse_qs(urlparse(url).query)
        page = int(query["page"][0])
        per_page = int(query["per_page"][0])
        start = (page - 1) * per_page
        return [
            {
                "name": f"package-{index}",
                "downloads": 10_000 - index,
            }
            for index in range(start, start + per_page)
        ]


class Adapter:
    def resolve(self, package):
        if package.endswith("2"):
            return Release(package=package, version="")
        return Release(package=package, version="1.0.0")


def test_collect_ranking_preserves_order_and_metric():
    rows = dataset.collect_ranking(RankingClient(), "pypi", limit=125, workers=2)
    assert len(rows) == 125
    assert rows[0].rank == 1
    assert rows[0].package == "package-0"
    assert rows[0].ranking_metric == "downloads"
    assert rows[-1].package == "package-124"


def test_load_fixed_ranking(tmp_path: Path):
    (tmp_path / "npm.txt").write_text("one\ntwo\n", encoding="utf-8")
    rows = dataset.load_fixed_ranking(tmp_path, "npm", limit=2)
    assert [row.package for row in rows] == ["one", "two"]
    assert rows[0].ranking_metric == "dependent_packages_count"
    assert rows[0].ranking_value is None


def test_resolve_ranking_retains_unresolved_rows():
    ranking = [
        dataset.RankedPackage("pypi", rank, f"package-{rank}", "downloads", rank)
        for rank in range(1, 4)
    ]
    rows = dataset.resolve_ranking(
        Adapter(), ranking, captured_at="2026-08-22T00:00:00+00:00", workers=1
    )
    assert len(rows) == 3
    assert rows[0].resolved
    assert not rows[1].resolved
    assert rows[1].version == ""
    assert rows[1].resolution_detail == "package did not resolve"
    assert rows[2].rank == 3
