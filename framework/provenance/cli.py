from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Sequence

from . import behavior, collect, dataset, ecosystems, measurement
from .attestor import classify_for_release
from .http import Client
from .rekor import RekorClient
from .verify import verify_with_registry_tool

class _SigstoreNoOpFilter(logging.Filter):
    """Hide only the warning for the deliberate identity-policy no-op.

    The log verifier still verifies the signature, certificate chain, SCT,
    Rekor inclusion evidence, and artifact binding. Signer authorization is
    evaluated separately by this framework's registry-aware classifier.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return not record.getMessage().startswith(
            "unsafe (no-op) verification policy used!"
        )


def configure_logging() -> None:
    logger = logging.getLogger("sigstore.verify.policy")
    if not any(isinstance(item, _SigstoreNoOpFilter) for item in logger.filters):
        logger.addFilter(_SigstoreNoOpFilter())

def main(argv: Optional[Sequence[str]] = None) -> int:
    configure_logging()
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return 2
    return args.handler(args)

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provenance",
        description="Measure package provenance across registries.",
    )
    subcommands = parser.add_subparsers(dest="command")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--ecosystem", required=True, choices=ecosystems.names())
    common.add_argument("--packages", type=Path,
                        help="file with one package name per line")
    common.add_argument("--package", action="append", default=[],
                        help="a single package; repeatable")
    common.add_argument("--out", type=Path, help="write JSON Lines here")
    common.add_argument("--workers", type=int, default=6)

    registry = subcommands.add_parser(
        "registry-path", parents=[common],
        help="what the registry exposes for each package",
    )
    registry.set_defaults(handler=_registry_path)

    log = subcommands.add_parser(
        "log-path", parents=[common],
        help="what the transparency log holds for each artifact",
    )
    log.add_argument("--classify", action="store_true",
                     help="also attribute each entry that is found")
    log.add_argument("--verify", action="store_true",
                     help="cryptographically verify every entry that is found "
                          "and report whether it covers the artifact; without "
                          "this, a record is only reported as found")
    log.add_argument("--no-registry-bundles", action="store_true",
                     help="verify only from public log material, so DSSE "
                          "entries whose payload the log does not keep are "
                          "reported as having no material")
    log.set_defaults(handler=_log_path)

    verify = subcommands.add_parser(
        "verify", parents=[common],
        help="run registry verification for a package",
    )
    verify.set_defaults(handler=_verify)

    evidence = subcommands.add_parser(
        "verify-evidence", help="verify packages within one ecosystem",
    )
    evidence.add_argument("--ecosystem", required=True, choices=ecosystems.names())
    evidence.add_argument("--path", required=True, choices=("registry", "log"),
                          help="registry verification or public-log attestation verification")
    inputs = evidence.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--coordinates", type=Path, help="CSV containing ecosystem, package, version")
    inputs.add_argument("--package", help="package to verify")
    evidence.add_argument("--version", help="release version (with --package only)")
    evidence.add_argument("--out", type=Path, help="write JSON Lines here")
    evidence.add_argument("--workers", type=int, default=6)
    evidence.add_argument("--workdir", type=Path, help="directory for tool caches")
    evidence.set_defaults(handler=_verify_evidence)

    measure = subcommands.add_parser(
        "measure",
        help="collect and verify evidence for fixed package-version coordinates",
    )
    measure.add_argument(
        "--coordinates", type=Path, required=True,
        help="CSV containing ecosystem, package, and version columns",
    )
    measure.add_argument("--out", type=Path, required=True,
                         help="write the measurement as JSON Lines")
    measure.add_argument("--workers", type=int, default=6)
    measure.add_argument(
        "--registry-verifier", action="store_true",
        help="also run registry verification (toolchain-dependent)",
    )
    measure.add_argument(
        "--no-registry-bundles", action="store_true",
        help="verify only evidence reconstructed from the public log",
    )
    measure.set_defaults(handler=_measure)

    construct = subcommands.add_parser(
        "construct-dataset",
        help="collect package rankings and resolve package-version coordinates",
    )
    construct.add_argument(
        "--ecosystem", action="append", choices=ecosystems.names(),
        help="ecosystem to collect; repeatable (default: all eight)",
    )
    construct.add_argument("--limit", type=int, default=1000)
    construct.add_argument("--workers", type=int, default=8)
    construct.add_argument(
        "--rankings", type=Path,
        help="use <ecosystem>.txt rankings from this directory instead of "
             "fetching current ecosyste.ms rankings",
    )
    construct.add_argument(
        "--out", type=Path, required=True,
        help="write the constructed coordinate CSV here",
    )
    construct.set_defaults(handler=_construct_dataset)

    probe = subcommands.add_parser(
        "behavior", parents=[common],
        help="run an install or verification behavior scenario",
    )
    probe.add_argument("--version", default="", help="version to install")
    probe.add_argument(
        "--scenario",
        choices=("default", "bad-input", "missing-entry", "privacy"),
        default="default",
    )
    probe.add_argument("--artifact", default="")
    probe.add_argument("--tampered-artifact", default="")
    probe.add_argument("--missing-artifact", default="")
    probe.add_argument("--signature", default="")
    probe.add_argument("--repository", default="")
    probe.add_argument("--mismatched-repository", default="")
    probe.add_argument("--workdir", default="")
    probe.add_argument("--trace-file", default="")
    probe.set_defaults(handler=_behavior)

    listing = subcommands.add_parser("ecosystems", help="list what is supported")
    listing.set_defaults(handler=_list_ecosystems)
    return parser

def _packages(args) -> List[str]:
    names = list(args.package)
    if args.packages:
        names += [
            line.strip()
            for line in args.packages.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    if not names:
        raise SystemExit("give --package or --packages")
    return names

def _writer(path: Optional[Path]):
    handle = path.open("w", encoding="utf-8") if path else None

    def write(record: dict) -> None:
        line = json.dumps(record, ensure_ascii=False)
        if handle:
            handle.write(line + "\n")
            handle.flush()
        else:
            print(line)

    return write, handle

def _progress(label: str):
    def report(done: int, total: int, observation) -> None:
        if done % 25 == 0 or done == total:
            print(f"[{done}/{total}] {label}", file=sys.stderr, flush=True)

    return report

def _registry_path(args) -> int:
    client = Client()
    ecosystem = ecosystems.load(args.ecosystem, client)
    write, handle = _writer(args.out)
    try:
        results = collect.scan_registry(
            ecosystem, _packages(args), workers=args.workers,
            progress=_progress(args.ecosystem),
        )
        for observation in results:
            write(observation.as_dict())
    finally:
        if handle:
            handle.close()

    present = sum(1 for item in results if item.present)
    print(f"{args.ecosystem}: {present} of {len(results)} exposed by the registry",
          file=sys.stderr)
    return 0

def _log_path(args) -> int:
    client = Client()
    ecosystem = ecosystems.load(args.ecosystem, client)
    rekor = RekorClient(client)
    registry_keys = (
        ecosystem.registry_keys() if hasattr(ecosystem, "registry_keys") else {}
    )
    write, handle = _writer(args.out)
    try:
        results = collect.scan_log(
            ecosystem, rekor, _packages(args), workers=args.workers,
            progress=_progress(args.ecosystem),
        )
        for observation in results:
            if args.verify:
                collect.verify_log(
                    ecosystem, rekor, observation,
                    classifier=_classifier(ecosystem, observation, registry_keys)
                    if args.classify else None,
                    use_registry_bundles=not args.no_registry_bundles,
                )
            record = observation.as_dict()
            if args.classify and observation.present:
                record["attribution"] = _attribute(
                    rekor, ecosystem, observation, registry_keys
                )
            write(record)
    finally:
        if handle:
            handle.close()

    found = sum(1 for item in results if item.present)
    line = f"{args.ecosystem}: {found} of {len(results)} present in the log"
    if args.verify:
        verified = sum(1 for item in results if item.verified)
        line += f", {verified} verified and bound to the artifact"
    print(line, file=sys.stderr)
    return 0

def _classifier(ecosystem, observation, registry_keys):
    release = ecosystem.resolve(observation.package, observation.version)

    def classify_entry(entry):
        return classify_for_release(entry, ecosystem, release, registry_keys)

    return classify_entry

def _attribute(rekor: RekorClient, ecosystem, observation, registry_keys) -> List[dict]:
    release = ecosystem.resolve(observation.package, observation.version)
    attributed = []
    for entry in rekor.entries(observation.entry_ids):
        result = classify_for_release(entry, ecosystem, release, registry_keys)
        attributed.append(
            {
                "uuid": entry.uuid,
                "kind": f"{entry.kind}/{entry.api_version}",
                "integrated": entry.integrated_at.isoformat()
                if entry.integrated_at
                else "",
                "role": str(result.role),
                "role_token": result.role.token,
                "registry_authorized": result.registry_authorized,
                "subject": result.identity.subject,
                "issuer": result.identity.issuer,
                "detail": result.detail,
            }
        )
    return attributed

def _verify(args) -> int:
    client = Client()
    ecosystem = ecosystems.load(args.ecosystem, client)
    write, handle = _writer(args.out)
    outcomes = []
    try:
        for name in _packages(args):
            run = verify_with_registry_tool(ecosystem, name)
            outcomes.append(run)
            write(run.as_dict())
    finally:
        if handle:
            handle.close()

    verified = sum(1 for item in outcomes if item.succeeded)
    print(f"{args.ecosystem}: {verified} of {len(outcomes)} verified",
          file=sys.stderr)
    return 0

def _measure(args) -> int:
    try:
        coordinates = measurement.load_coordinates(args.coordinates)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    if args.out.exists():
        raise SystemExit(f"refusing to overwrite existing output: {args.out}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    results = measurement.run(
        coordinates,
        workers=args.workers,
        registry_verifier=args.registry_verifier,
        use_registry_bundles=not args.no_registry_bundles,
        progress=_progress("fixed coordinates"),
    )
    write, handle = _writer(args.out)
    try:
        for record in results:
            write(record)
    finally:
        if handle:
            handle.close()
    print(f"measured {len(results)} fixed package-version coordinates",
          file=sys.stderr)
    return 0


def _verify_evidence(args) -> int:
    from .verify import evidence

    if args.workers < 1:
        raise SystemExit("--workers must be positive")
    if args.coordinates and args.version is not None:
        raise SystemExit("--version applies only to --package")
    try:
        rows = evidence.load_coordinates(args.coordinates, args.ecosystem) if args.coordinates else [
            {"ecosystem": args.ecosystem, "package": args.package, "version": args.version or ""}]
    except ValueError as error:
        raise SystemExit(str(error)) from error
    if args.out:
        if args.out.exists():
            raise SystemExit(f"refusing to overwrite existing output: {args.out}")
        args.out.parent.mkdir(parents=True, exist_ok=True)

    def run(work_root):
        return evidence.run(args.ecosystem, rows, path=args.path, work_root=work_root,
                            workers=args.workers, resolve_version=args.coordinates is None,
                            progress=_progress(args.ecosystem))

    if args.workdir:
        results = run(args.workdir.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="provenance-verify-") as directory:
            results = run(Path(directory))
    write, handle = _writer(args.out)
    try:
        for result in results:
            write(result)
    finally:
        if handle:
            handle.close()
    verified = sum(item["outcome"] == "verified" for item in results)
    print(f"{args.ecosystem}: {verified} of {len(results)} verified", file=sys.stderr)
    return 0 if results and verified == len(results) else 1


def _construct_dataset(args) -> int:
    if args.out.exists():
        raise SystemExit(f"refusing to overwrite existing output: {args.out}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    selected = args.ecosystem or ecosystems.names()
    client = Client()
    coordinates = dataset.construct(
        client,
        selected,
        limit=args.limit,
        workers=args.workers,
        ranking_directory=args.rankings,
        progress=_progress("dataset construction"),
    )
    fields = list(dataset.Coordinate.__dataclass_fields__)
    with args.out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(item.as_dict() for item in coordinates)
    resolved = sum(item.resolved for item in coordinates)
    print(
        f"constructed {len(coordinates)} coordinates; {resolved} resolved",
        file=sys.stderr,
    )
    return 0


def _behavior(args) -> int:
    client = Client()
    ecosystem = ecosystems.load(args.ecosystem, client)
    write, handle = _writer(args.out)
    try:
        for name in _packages(args):
            version = args.version or ecosystem.resolve(name).version
            probe = behavior.run_scenario(
                args.ecosystem,
                args.scenario,
                {
                    "package": name,
                    "version": version,
                    "artifact": args.artifact,
                    "tampered_artifact": args.tampered_artifact,
                    "missing_artifact": args.missing_artifact,
                    "signature": args.signature,
                    "repository": args.repository,
                    "mismatched_repository": args.mismatched_repository,
                    "workdir": args.workdir,
                },
                workdir=args.workdir or None,
                trace_file=args.trace_file or None,
            )
            write(probe.as_dict())
    finally:
        if handle:
            handle.close()
    return 0

def _list_ecosystems(args) -> int:
    client = Client()
    print(f"{'group':<6} {'name':<11} {'level':<12} algorithms")
    for name in ecosystems.names():
        adapter = ecosystems.load(name, client)
        print(
            f"{ecosystems.group_of(name):<6} {name:<11} "
            f"{adapter.documented_level:<12} "
            f"{', '.join(adapter.digest_algorithms)}"
        )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
