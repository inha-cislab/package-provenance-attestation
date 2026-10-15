from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading

PACKAGE = "github.com/google/uuid"
VERSION = "v1.6.0"


def environment(work: Path) -> dict[str, str]:
    work = work.resolve()
    return {
        **os.environ,
        "GOENV": "off", "GOWORK": "off", "GOFLAGS": "",
        "GO111MODULE": "on", "GOTOOLCHAIN": "local",
        "GOPRIVATE": "", "GONOSUMDB": "", "GONOPROXY": "",
        "GOINSECURE": "", "GOPROXY": "https://proxy.golang.org",
        "GOSUMDB": "sum.golang.org", "CGO_ENABLED": "0",
        "GOPATH": str(work / "gopath"),
        "GOMODCACHE": str(work / "modcache"),
        "GOCACHE": str(work / "buildcache"),
    }


def mismatched_sum(text: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        parts = line.split()
        if len(parts) == 3 and parts[:2] == [PACKAGE, VERSION]:
            digest = bytearray(base64.b64decode(parts[2].removeprefix("h1:")))
            digest[0] ^= 1
            parts[2] = "h1:" + base64.b64encode(digest).decode()
            lines[index] = " ".join(parts)
            return "\n".join(lines) + "\n"
    raise ValueError("baseline go.sum has no artifact checksum for the selected module")


@contextmanager
def unavailable_sumdb():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b"checksum database unavailable in local test\n")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def build(work: Path, *, checksums: str = "", sumdb_url: str = "") -> dict:
    work.mkdir(parents=True, exist_ok=False)
    (work / "go.mod").write_text(
        f"module example.com/provenance-behavior\n\ngo 1.18\n\n"
        f"require {PACKAGE} {VERSION}\n", encoding="utf-8")
    (work / "main.go").write_text(
        f'package main\nimport _ "{PACKAGE}"\nfunc main() {{}}\n', encoding="utf-8")
    if checksums:
        (work / "go.sum").write_text(checksums, encoding="utf-8")
    env = environment(work)
    if sumdb_url:
        env["GOSUMDB"] = f"sum.golang.org {sumdb_url}"
    binary = work / "probe.bin"
    command = ["go", "build", "-mod=mod", "-o", str(binary), "."]
    completed = subprocess.run(command, cwd=work, env=env, capture_output=True,
                               text=True, timeout=300, check=False)
    result = {
        "command": command, "exit_code": completed.returncode,
        "stdout": completed.stdout, "stderr": completed.stderr,
        "binary_created": binary.exists(),
        "checksum_source": "go.sum" if checksums else "checksum database",
        "environment": {key: env[key] for key in (
            "GOMODCACHE", "GOCACHE", "GOPATH", "GOPROXY", "GOSUMDB",
            "GONOSUMDB", "GOPRIVATE", "GOFLAGS", "GOWORK", "GOTOOLCHAIN")},
    }
    (work / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def passed(summary: dict) -> bool:
    good, mismatch, unavailable = (summary[key] for key in (
        "baseline", "checksum_mismatch", "sumdb_unavailable"))
    return (
        good["exit_code"] == 0 and good["binary_created"]
        and mismatch["exit_code"] != 0 and not mismatch["binary_created"]
        and "checksum mismatch" in mismatch["stderr"].lower()
        and unavailable["exit_code"] != 0 and not unavailable["binary_created"]
        and "503" in unavailable["stderr"]
        and any(path.startswith("/lookup/") for path in summary["sumdb_requests"])
    )


def reproduce(out: Path) -> dict:
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any((out / name).exists() for name in (
            "baseline", "checksum-mismatch", "sumdb-unavailable", "go-build-summary.json")):
        raise FileExistsError("use a new output directory for this experiment")
    version = subprocess.run(["go", "version"], capture_output=True,
                             text=True, check=True).stdout.strip()
    baseline = build(out / "baseline")
    if baseline["exit_code"] != 0:
        raise RuntimeError(f"baseline build failed; see {out / 'baseline' / 'result.json'}")
    sums = (out / "baseline" / "go.sum").read_text(encoding="utf-8")
    mismatch = build(out / "checksum-mismatch", checksums=mismatched_sum(sums))
    with unavailable_sumdb() as (url, requests):
        unavailable = build(out / "sumdb-unavailable", sumdb_url=url)
    summary = {
        "package": PACKAGE, "version": VERSION, "go": version,
        "baseline": baseline, "checksum_mismatch": mismatch,
        "sumdb_unavailable": unavailable, "sumdb_requests": requests,
    }
    summary["passed"] = passed(summary)
    (out / "go-build-summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    summary = reproduce(parser.parse_args().out)
    print(json.dumps(summary, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
