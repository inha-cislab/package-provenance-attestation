from __future__ import annotations

import argparse
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

PACKAGE = "checksum-probe"
VERSION = "1.0.0"


def crate_bytes(source: bytes) -> bytes:
    tar_body = io.BytesIO()
    with tarfile.open(fileobj=tar_body, mode="w") as archive:
        files = {
            f"{PACKAGE}-{VERSION}/Cargo.toml": (
                f'[package]\nname = "{PACKAGE}"\nversion = "{VERSION}"\nedition = "2021"\n'
            ).encode(),
            f"{PACKAGE}-{VERSION}/src/lib.rs": source,
        }
        for name, body in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            member.mtime = 0
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(body))
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
        compressed.write(tar_body.getvalue())
    return output.getvalue()


class Server:
    def __init__(self, archive: bytes, expected: str):
        requests: list[str] = []
        self.requests = requests
        index = json.dumps(
            {
                "name": PACKAGE,
                "vers": VERSION,
                "deps": [],
                "cksum": expected,
                "features": {},
                "yanked": False,
                "links": None,
            },
            separators=(",", ":"),
        ).encode() + b"\n"
        routes: dict[str, tuple[str, bytes]] = {
            "/ch/ec/checksum-probe": ("text/plain", index),
            "/ch/ec/checksum_probe": ("text/plain", index),
            f"/crates/{PACKAGE}/{VERSION}/download": ("application/gzip", archive),
        }

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                requests.append(self.path)
                if self.path == "/config.json":
                    body = json.dumps({"dl": f"{server.url}/crates/{{crate}}/{{version}}/download"}).encode()
                    route = ("application/json", body)
                else:
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

        server = self
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


def scenario(name: str, archive: bytes, expected: str) -> dict:
    with Server(archive, expected) as server:
        work = Path(tempfile.mkdtemp(prefix=f"cargo-{name}-"))
        try:
            (work / ".cargo").mkdir()
            (work / "src").mkdir()
            (work / ".cargo" / "config.toml").write_text(
                "[source.crates-io]\nreplace-with = \"local\"\n\n"
                "[source.local]\n"
                f'registry = "sparse+{server.url}/"\n',
                encoding="utf-8",
            )
            (work / "Cargo.toml").write_text(
                f'[package]\nname = "behavior-probe"\nversion = "0.1.0"\nedition = "2021"\n\n'
                f'[dependencies]\n{PACKAGE} = "={VERSION}"\n',
                encoding="utf-8",
            )
            (work / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
            env = {**os.environ, "CARGO_HOME": str(work / "cargo-home"), "NO_COLOR": "1"}
            completed = subprocess.run(
                ["cargo", "build", "--verbose"],
                cwd=work,
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            return {
                "scenario": name,
                "command": ["cargo", "build", "--verbose"],
                "exit_code": completed.returncode,
                "requests": server.requests,
                "stdout": completed.stdout[-12000:],
                "stderr": completed.stderr[-12000:],
            }
        finally:
            shutil.rmtree(work, ignore_errors=True)


def reproduce(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    original = crate_bytes(b"pub fn value() -> u8 { 1 }\n")
    modified = crate_bytes(b"pub fn value() -> u8 { 2 }\n")
    expected = hashlib.sha256(original).hexdigest()
    baseline = scenario("baseline", original, expected)
    bad_input = scenario("bad-input", modified, expected)
    summary = {
        "package": PACKAGE,
        "version": VERSION,
        "cargo": subprocess.run(["cargo", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
        "expected_sha256": expected,
        "modified_sha256": hashlib.sha256(modified).hexdigest(),
        "baseline": baseline,
        "bad_input": bad_input,
    }
    (out / "cargo-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summary = reproduce(args.out)
    print(json.dumps(summary, indent=2))
    return 0 if summary["baseline"]["exit_code"] == 0 and summary["bad_input"]["exit_code"] != 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
