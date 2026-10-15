# Package-provenance framework

The framework collects and verifies evidence for package artifacts across eight
ecosystems.

## Components

| component | purpose | module |
|---|---|---|
| dataset construction | fetch rankings and resolve package-version coordinates | `dataset` |
| evidence extraction | collect registry evidence and query Rekor by artifact digest | `collect.registry_path`, `collect.log_path` |
| evidence verification | verify evidence, apply the three PyPI tiers, and classify attestors | `verify`, `attestor` |
| behavior analysis | run consumer tools and record outcomes and contacted domains | `behavior`, `verify.registry_verifier` |

Discovery and verification remain separate. `exposed` means that the registry
response contains the relevant field or evidence, while `present` means that
the field contains usable evidence. A record is verified only when its
signature and supporting evidence are valid and it covers the artifact
distributed by the registry.

## Ecosystems

| group | ecosystem | highest registry level | digest queried in Rekor |
|---|---|---|---|
| A | PyPI | provenance | SHA-256 and SHA-512 |
| A | npm | provenance | SHA-256 and SHA-512 |
| A | RubyGems | provenance | SHA-256 and SHA-512 |
| B | Maven | attribution | SHA-256 and SHA-512 |
| B | NuGet | attribution | SHA-256 and SHA-512 |
| B | crates.io | integrity | SHA-256 and SHA-512 |
| C | Packagist | integrity | SHA-256 and SHA-512 |
| C | Go Modules | integrity | SHA-256 and SHA-512 |

The public-log path downloads each artifact, computes both hashes from its
bytes, and queries Rekor with each hash.

## Signer roles

`--classify` assigns one of the four roles used in the paper:

| role | meaning |
|---|---|
| publisher | the registry identifies the signer as authorized to publish, and the certificate matches that information |
| project signer | the certificate identifies the package's repository or workflow, but the registry does not establish authorization to publish |
| observer | the registry does not authorize the signer, or the certificate identifies an independent third party |
| bare key | the entry carries a raw public key without an OIDC certificate identity |

Internal parse failures remain diagnostic outcomes and are not additional
signer roles. Entry-level output can also use `registry` as an internal marker
for a signature made with a known registry key; it is excluded from the four
package-attestor roles reported in the paper.

## Install and test

Use Python 3.12; the lock file records the exact environment tested for this
artifact.

```bash
python -m pip install -r requirements-lock.txt
python -m pip install --no-deps --no-build-isolation -e .
python -m pytest tests -q
```

The unit tests do not require network access.

## Dataset construction

Fetch the current Top-1,000 rankings from the packages.ecosyste.ms API using
downloads for PyPI, RubyGems, NuGet, Packagist, and crates.io, and dependent
package count for npm, Maven, and Go Modules. The framework then resolves the
version currently selected by each registry for every package.

```bash
provenance construct-dataset --out current-coordinates.csv
```

The paper's 2026-08-22 ranking lists are in `../dataset/corpus/`.
Pass `--rankings ../dataset/corpus` to resolve versions for those package lists.

## Evidence extraction and verification

```bash
provenance registry-path --ecosystem pypi --packages ../dataset/corpus/pypi.txt --out pypi-registry.jsonl
provenance log-path --ecosystem npm --packages ../dataset/corpus/npm.txt --classify --verify --out npm-log.jsonl
provenance verify --ecosystem pypi --package packaging
provenance measure --coordinates current-coordinates.csv --out repeated-measurement.jsonl
provenance ecosystems
```

`measure` reads exact `(ecosystem, package, version)` coordinates rather than
resolving the latest release. It runs the registry-API path and the verified,
classified public-log path for every row. Pass `--registry-verifier` to also run registry verification. Rows with no version are recorded as unresolved.

The PyPI verifier tries the three inputs described in the paper when they are
available: the repository in project metadata, the repository in Trusted
Publisher information, and the Google Cloud service-account identity. The
RubyGems collector obtains bundles from the attestations API; RubyGems does not
provide a standard Sigstore-aware consumer verifier.

Run registry evidence verification with a coordinate CSV containing
`ecosystem`, `package`, and `version`; `rank` and `digest_sha256` are optional:

```bash
provenance verify-evidence --path registry --coordinates current-coordinates.csv --ecosystem maven --out maven-levels.jsonl
provenance verify-evidence --path registry --coordinates current-coordinates.csv --ecosystem nuget --out nuget-levels.jsonl
provenance verify-evidence --path registry --coordinates current-coordinates.csv --ecosystem crates --out crates-levels.jsonl
provenance verify-evidence --path registry --coordinates current-coordinates.csv --ecosystem go --out go-levels.jsonl
```

These commands respectively perform detached OpenPGP verification, NuGet
signature verification, crate checksum comparison, and authenticated Go `h1`
comparison. A supplied `digest_sha256` is also checked against the downloaded
artifact. Packagist has no nonempty `dist.shasum` in
the fixed frame, so there is no integrity evidence to verify.

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


The fixed-level results were reproduced with Python 3.12, GnuPG 2.2.27, Go
1.26.4, and .NET SDK 8.0.423. Use GnuPG 2.2.27 for the reported Maven count;
GnuPG 2.4.9 rejects six Bouncy Castle compressed signatures accepted by the
reference version.

## Behavior reproduction

The generic command accepts the scenarios and inputs described in the paper:

```bash
provenance behavior --ecosystem <name> --scenario <default|bad-input|missing-entry|privacy> --package <name> --version <version> [scenario inputs]
```

The following modules construct their own bad-input fixtures and record both a
baseline and the changed input:

```bash
python -m provenance.behavior.npm_external --out behavior/npm
python -m provenance.behavior.cargo_external --out behavior/cargo
python -m provenance.behavior.go_cache --out behavior/go
python -m provenance.behavior.go_build --out behavior/go-build
python -m provenance.behavior.rubygems_local --out behavior/rubygems
python -m provenance.behavior.maven_gpg --out behavior/maven
python -m provenance.behavior.maven_checksum --out behavior/maven-checksum
python -m provenance.behavior.nuget_local --out behavior/nuget
python -m provenance.behavior.packagist_local --out behavior/packagist
```

These commands require the corresponding ecosystem tool. The npm experiment
uses separate local registry and artifact servers while retaining the original
attestation, so the registry accepts the changed artifact by integrity but the
provenance verifier rejects it. The Go cache experiment traces `go mod verify`
after download. The Go build experiment checks a normal build, a mismatched
`go.sum` artifact checksum, and an unavailable checksum database with fresh
caches.
The Maven experiment checks the no-key, valid-signature, and changed-
artifact outcomes separately.

The Maven checksum experiment uses a local synthetic JAR with matching and
mismatching SHA-1 sidecars. With Maven 3.6.3, the default policy warns and
continues. Each case uses a fresh local repository.

### npm bundle verification

`log-path --ecosystem npm --verify` uses JavaScript `sigstore.verify` and
compares the signed subject digests with the downloaded artifact's hashes.

With Node.js 22.9 or later, install the locked JavaScript verifier from the
repository root:

```bash
npm ci --ignore-scripts --prefix framework/provenance/verify/sigstore_js
```

Node.js must be on `PATH`, or selected with `PROVENANCE_NODE`.
For an installation outside the source tree, set `PROVENANCE_NPM_PREFIX`
to the directory containing the installed npm `node_modules` directory.

### Privacy capture

`behavior --scenario privacy` records request hosts and paths for PyPI and npm.
The PyPI wrapper instruments sockets and Python HTTP clients; the npm wrapper
instruments Node.js HTTP and HTTPS requests. The JSON `requests` field retains
request paths alongside the contacted `domains`.
