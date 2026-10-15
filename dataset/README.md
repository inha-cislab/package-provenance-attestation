# Measurement dataset

Frame: 2026-08-22. The dataset contains the Top 1,000 packages in each of eight
ecosystems.

## Files

| path | contents |
|---|---|
| `corpus/` | ranked package names and their sampling metadata |
| `summary.csv` | aggregate counts at each ecosystem's highest assurance level |
| `MANIFEST.json` | byte count, row count, and SHA-256 for every dataset file |

## Summary

| ecosystem | level | deploy | verified at level | log matches |
|---|---|---:|---:|---:|
| PyPI | provenance | 376 | 376 | 428 |
| npm | provenance | 208 | 208 | 378 |
| RubyGems | provenance | 91 | 89 | 89 |
| Maven | attribution | 918 | 905 | 73 |
| NuGet | attribution | 1,000 | 1,000 | 56 |
| crates.io | integrity | 1,000 | 1,000 | 0 |
| Packagist | integrity | 1,000 | 0 | 1 |
| Go Modules | integrity | 997 | 997 | 0 |

Deploy counts packages for which the registry exposes the field or evidence at
the listed level. For PyPI, npm, and RubyGems, the evidence is a provenance
attestation. For Maven and NuGet, it is a package signature. For crates.io and
Go Modules, it is a registry checksum. Packagist exposes `dist.shasum` for all
1,000 packages, but every value is empty, so no artifact can be reproduced from
that field.

The transparency-log roles are reported separately in `summary.csv`. A
publisher is authorized by information from the registry. A project signer is
associated with the package's repository or workflow, but the registry provides
no information that establishes authorization to publish. An observer is an
independent third party, and a bare key supplies no certificate identity.

If a package has entries in multiple roles, the
package-level columns in `summary.csv` use the order publisher, project signer,
observer, and bare key. This makes the four columns a partition of packages
with digest-query matches rather than a count of every Rekor entry.
