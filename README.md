# Package provenance measurement artifact

This artifact contains the measurement framework, package lists, and aggregate
results for eight package ecosystems. The fixed measurement frame is
2026-08-22, with the 1,000 most-used packages selected for each ecosystem.
The framework covers dataset construction, evidence extraction, evidence
verification, and the behavioral experiments reported in the paper.

## Contents

| path | contents |
|---|---|
| `framework/` | the four framework components and their tests |
| `dataset/corpus/` | the eight ranked Top-1,000 package lists |
| `dataset/summary.csv` | aggregate deployment, verification, and transparency-log counts |

## Main results

`verified at level` reports verification at the highest level exposed by the
registry: provenance for Group A, attribution for Maven and NuGet, and
integrity for crates.io, Packagist, and Go Modules.
`deploy` counts packages for which the registry exposes the corresponding
field or evidence.

| ecosystem | group | deploy | verified at level | log matches | publisher | project signer | observer | bare key |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PyPI | A | 376 | 376 | 428 | 376 | 0 | 41 | 11 |
| npm | A | 208 | 208 | 378 | 208 | 0 | 84 | 86 |
| RubyGems | A | 91 | 89 | 89 | 89 | 0 | 0 | 0 |
| Maven | B | 918 | 905 | 73 | 0 | 13 | 44 | 16 |
| NuGet | B | 1,000 | 1,000 | 56 | 0 | 0 | 0 | 56 |
| crates.io | B | 1,000 | 1,000 | 0 | 0 | 0 | 0 | 0 |
| Packagist | C | 1,000 | 0 | 1 | 0 | 1 | 0 | 0 |
| Go Modules | C | 997 | 997 | 0 | 0 | 0 | 0 | 0 |

`log matches` counts packages with digest-query matches. The four signer
columns partition those packages.
Packagist exposes `dist.shasum` for all 1,000 packages, but every value is
empty; thus, its deploy count is 1,000 while its verified count is zero.

## Run the framework

The locked environment requires Python 3.12.

```bash
python -m venv .venv
.venv/bin/python -m pip install -r framework/requirements-lock.txt
.venv/bin/python -m pip install --no-deps --no-build-isolation -e framework
.venv/bin/python -m pytest framework/tests -q
```

On Windows, use `.venv\Scripts\python` in place of `.venv/bin/python`.

npm verification also requires Node.js 22.9 or later and
`npm ci --ignore-scripts --prefix framework/provenance/verify/sigstore_js`.

Construct a new dataset by fetching the current ecosyste.ms rankings and
resolving the version currently selected by each registry for every package:

```bash
provenance construct-dataset --out current-coordinates.csv
```

Use `--ecosystem <name>` to select ecosystems or `--limit <n>` for a smaller
run. The ranked package lists used in the paper are in `dataset/corpus/`.
To use those lists instead of fetching current rankings:

```bash
provenance construct-dataset --rankings dataset/corpus --out current-coordinates.csv
```

Example measurements:

```bash
provenance registry-path --ecosystem pypi --packages dataset/corpus/pypi.txt --out pypi-registry.jsonl
provenance log-path --ecosystem npm --packages dataset/corpus/npm.txt --classify --verify --out npm-log.jsonl
provenance verify --ecosystem pypi --package packaging
```

To run evidence extraction and verification over the generated coordinates:

```bash
provenance measure --coordinates current-coordinates.csv --out repeated-measurement.jsonl
```

The behavior component records the command, exit status, output, and contacted
domains for an applicable scenario:

```bash
provenance behavior --ecosystem pypi --scenario missing-entry --package boto3 --version 1.42.89 --repository https://github.com/boto/boto3 --missing-artifact pypi:boto3-1.42.89-py3-none-any.whl
```

Self-contained reproductions for the npm, Cargo, Go, RubyGems, Maven, NuGet,
and Packagist bad-input checks are listed in `framework/README.md`.

Add `--registry-verifier` to also run registry verification. npm verifies each
registry-served provenance bundle with JavaScript `sigstore.verify` and checks
the artifact binding and publisher identity.

Verify one ecosystem at a time from a coordinate CSV:

```bash
provenance verify-evidence --path registry --coordinates current-coordinates.csv --ecosystem maven --out maven-levels.jsonl
provenance verify-evidence --path registry --coordinates current-coordinates.csv --ecosystem nuget --out nuget-levels.jsonl
provenance verify-evidence --path registry --coordinates current-coordinates.csv --ecosystem crates --out crates-levels.jsonl
provenance verify-evidence --path registry --coordinates current-coordinates.csv --ecosystem go --out go-levels.jsonl
```

`verify-evidence` selects every CSV row for `--ecosystem` and uses its exact
version. It preserves input order and writes one result per package. For a
single package, use `--package` and `--version` instead of `--coordinates`;
without `--version`, the ecosystem adapter resolves the release.

```bash
provenance verify-evidence --ecosystem maven --path registry --package org.example:library --version 1.0.0
provenance verify-evidence --ecosystem npm --path registry --coordinates current-coordinates.csv --out npm-registry-verified.jsonl
provenance verify-evidence --ecosystem npm --path log --coordinates current-coordinates.csv --out npm-log-verified.jsonl
```

`--path registry` runs PyPI's three-tier verifier, npm's individual bundle
verifier, or Maven, NuGet, crates.io, and Go signature/checksum verification.
The npm registry verifier downloads the artifact and checks the registry-served
bundle with JavaScript `sigstore.verify`, including artifact binding and
publisher classification. `--path log` verifies evidence found through Rekor
and classifies its signers. Use `--workdir` to retain tool caches between runs.
The command exits with status 0 only when every selected package is verified.


The Maven command downloads each JAR and detached signature and invokes GnuPG;
the NuGet command invokes `dotnet nuget verify --all` on each exact package;
the crates.io command compares the downloaded crate's SHA-256 with the index
checksum; and the Go command independently recomputes the module ZIP's `h1`
hash, compares it with the authenticated SumDB value, and also compares the
ZIP's SHA-256 with `digest_sha256` when supplied in the input. Maven requires `gpg`, NuGet requires the
.NET SDK, and Go requires the Go toolchain. Packagist is omitted because its
1,000 exposed `dist.shasum` fields are empty and therefore provide no evidence
to verify.

The fixed-level results were reproduced with Python 3.12, GnuPG 2.2.27, Go
1.26.4, and .NET SDK 8.0.423. GnuPG 2.4.9 rejects six Maven signatures wrapped
in Bouncy Castle compressed packets that GnuPG 2.2.27 accepts; use 2.2.27 to
reproduce the reported Maven count.
