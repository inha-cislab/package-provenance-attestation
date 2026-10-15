from __future__ import annotations

import argparse
import base64
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

PACKAGE = "caniuse-lite"
VERSION = "1.0.30001809"
REGISTRY = "https://registry.npmjs.org"


def fetch_bytes(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "npm-provenance-reproduction"})
    with urlopen(request, timeout=60) as response:
        return response.read()


def fetch_json(url: str) -> dict:
    return json.loads(fetch_bytes(url))


def modified_tarball(original: bytes) -> bytes:
    source = tarfile.open(fileobj=io.BytesIO(original), mode="r:gz")
    uncompressed = io.BytesIO()
    changed = False
    with source, tarfile.open(fileobj=uncompressed, mode="w") as target:
        for member in source.getmembers():
            extracted = source.extractfile(member) if member.isfile() else None
            data = extracted.read() if extracted is not None else None
            if not changed and data is not None and member.name.lower().endswith(("readme.md", "readme")):
                data += b"\n<!-- provenance bad-input reproduction -->\n"
                member = copy.copy(member)
                member.size = len(data)
                changed = True
            target.addfile(member, io.BytesIO(data) if data is not None else None)
    if not changed:
        raise RuntimeError("could not find a README file to modify")
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
        compressed.write(uncompressed.getvalue())
    return output.getvalue()


def integrity(data: bytes) -> str:
    digest = hashlib.sha512(data).digest()
    return "sha512-" + base64.b64encode(digest).decode("ascii")


class Server:
    def __init__(self, routes: dict[str, tuple[str, bytes]], requests: list[str]):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                requests.append(self.path)
                route = routes.get(self.path)
                if route is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                content_type, body = route
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def __enter__(self) -> "Server":
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def run(command: list[str], cwd: Path, env: dict[str, str]) -> dict:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    return {
        "command": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def scenario(
    name: str,
    tarball: bytes,
    original_packument: dict,
    attestations: bytes,
    out: Path,
) -> dict:
    registry_requests: list[str] = []
    artifact_requests: list[str] = []
    artifact_routes = {
        f"/{PACKAGE}-{VERSION}.tgz": ("application/octet-stream", tarball),
    }
    with Server(artifact_routes, artifact_requests) as artifact_server:
        packument = copy.deepcopy(original_packument)
        manifest = packument["versions"][VERSION]
        manifest["dist"]["tarball"] = f"{artifact_server.url}/{PACKAGE}-{VERSION}.tgz"
        manifest["dist"]["integrity"] = integrity(tarball)
        manifest["dist"]["shasum"] = hashlib.sha1(tarball).hexdigest()
        manifest["dist"].pop("signatures", None)
        attestation_path = f"/-/npm/v1/attestations/{PACKAGE}@{VERSION}"
        manifest["dist"]["attestations"]["url"] = f"http://registry.invalid{attestation_path}"
        registry_routes = {
            f"/{PACKAGE}": ("application/json", json.dumps(packument).encode()),
            f"/{PACKAGE}/": ("application/json", json.dumps(packument).encode()),
            attestation_path: ("application/json", attestations),
            "/-/npm/v1/keys": ("application/json", b'{"keys":[]}'),
        }
        with Server(registry_routes, registry_requests) as registry_server:
            work = Path(tempfile.mkdtemp(prefix=f"npm-{name}-"))
            try:
                (work / "package.json").write_text(
                    json.dumps(
                        {
                            "name": "npm-provenance-reproduction",
                            "version": "1.0.0",
                            "private": True,
                            "dependencies": {PACKAGE: VERSION},
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                cache = work / "npm-cache"
                common = [
                    f"--registry={registry_server.url}/",
                    f"--cache={cache}",
                    "--prefer-online",
                    "--fetch-retries=0",
                ]
                env = {**os.environ, "NO_COLOR": "1"}
                install = run(["npm", "install", "--ignore-scripts", "--loglevel=http", *common], work, env)
                audit = run(["npm", "audit", "signatures", "--json", "--loglevel=http", *common], work, env)
                result = {
                    "scenario": name,
                    "tarball_sha512": integrity(tarball),
                    "install_exit_code": install["exit_code"],
                    "audit_exit_code": audit["exit_code"],
                    "registry_requests": registry_requests,
                    "artifact_requests": artifact_requests,
                    "audit_stdout": audit["stdout"][-12000:],
                    "audit_stderr": audit["stderr"][-12000:],
                }
                (out / f"npm-{name}.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
                return result
            finally:
                shutil.rmtree(work, ignore_errors=True)


def reproduce(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    packument = fetch_json(f"{REGISTRY}/{PACKAGE}")
    manifest = packument["versions"][VERSION]
    original = fetch_bytes(manifest["dist"]["tarball"])
    attestation_document = fetch_json(manifest["dist"]["attestations"]["url"])
    attestation_document["attestations"] = [
        item
        for item in attestation_document["attestations"]
        if item["predicateType"].startswith("https://slsa.dev/provenance/")
    ]
    if len(attestation_document["attestations"]) != 1:
        raise RuntimeError("expected exactly one SLSA provenance attestation")
    attestations = json.dumps(attestation_document).encode()
    baseline = scenario("external-baseline", original, packument, attestations, out)
    bad_input = scenario("external-bad-input", modified_tarball(original), packument, attestations, out)
    summary = {
        "package": PACKAGE,
        "version": VERSION,
        "node": subprocess.run(["node", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
        "npm": subprocess.run(["npm", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
        "original_signed_sha512": integrity(original),
        "baseline": baseline,
        "bad_input": bad_input,
    }
    (out / "npm-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summary = reproduce(args.out)
    print(json.dumps(summary, indent=2))
    return 0 if summary["baseline"]["audit_exit_code"] == 0 and summary["bad_input"]["install_exit_code"] == 0 and summary["bad_input"]["audit_exit_code"] != 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
