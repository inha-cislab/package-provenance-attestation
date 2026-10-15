from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import zipfile

PACKAGE = "behavior/probe"
VERSION = "1.0.0"


def archive_bytes(value: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            "behavior-probe/composer.json",
            json.dumps({"name": PACKAGE, "version": VERSION, "type": "library"}),
        )
        archive.writestr("behavior-probe/value.txt", value)
    return output.getvalue()


class Server:
    def __init__(self, archive: bytes):
        requests: list[str] = []
        self.requests = requests

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                requests.append(self.path)
                if self.path != "/behavior-probe.zip":
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(archive)))
                self.end_headers()
                self.wfile.write(archive)

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


def scenario(name: str, archive: bytes, out: Path) -> dict:
    with Server(archive) as server:
        work = Path(tempfile.mkdtemp(prefix=f"composer-{name}-"))
        try:
            package = {
                "name": PACKAGE,
                "version": VERSION,
                "type": "library",
                "dist": {
                    "url": f"{server.url}/behavior-probe.zip",
                    "type": "zip",
                    "shasum": "",
                },
            }
            root = {
                "name": "behavior/root",
                "require": {PACKAGE: VERSION},
                "repositories": [{"type": "package", "package": package}],
                "config": {"secure-http": False, "allow-plugins": False},
            }
            (work / "composer.json").write_text(json.dumps(root, indent=2), encoding="utf-8")
            completed = subprocess.run(
                ["composer", "install", "--no-interaction", "--no-plugins", "--no-scripts", "-vvv"],
                cwd=work,
                env={**os.environ, "COMPOSER_CACHE_DIR": str(work / "cache"), "NO_COLOR": "1"},
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            installed = work / "vendor" / "behavior" / "probe" / "value.txt"
            result = {
                "scenario": name,
                "command": ["composer", "install", "--no-interaction", "--no-plugins", "--no-scripts", "-vvv"],
                "dist_shasum": "",
                "exit_code": completed.returncode,
                "installed_value": installed.read_text(encoding="utf-8") if installed.exists() else "",
                "requests": server.requests,
                "stdout": completed.stdout[-12000:],
                "stderr": completed.stderr[-12000:],
            }
            (out / f"packagist-{name}.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            return result
        finally:
            shutil.rmtree(work, ignore_errors=True)


def reproduce(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    baseline = scenario("baseline", archive_bytes("original\n"), out)
    bad_input = scenario("bad-input", archive_bytes("changed\n"), out)
    summary = {
        "package": PACKAGE,
        "version": VERSION,
        "composer": subprocess.run(["composer", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
        "baseline": baseline,
        "bad_input": bad_input,
    }
    (out / "packagist-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summary = reproduce(args.out)
    return 0 if summary["baseline"]["exit_code"] == 0 and summary["bad_input"]["exit_code"] == 0 and summary["bad_input"]["installed_value"] == "changed\n" else 1


if __name__ == "__main__":
    raise SystemExit(main())
