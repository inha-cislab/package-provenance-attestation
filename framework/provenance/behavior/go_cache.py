from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

PACKAGE = "github.com/stretchr/testify"
VERSION = "v1.10.0"


def run(command: list[str], work: Path, env: dict[str, str]) -> dict:
    completed = subprocess.run(
        command,
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    return {
        "command": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-12000:],
        "stderr": completed.stderr[-12000:],
    }


def reproduce(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="go-behavior-"))
    try:
        (work / "go.mod").write_text(
            f"module behavior-probe\n\ngo 1.18\n\nrequire {PACKAGE} {VERSION}\n",
            encoding="utf-8",
        )
        env = {
            **os.environ,
            "GOMODCACHE": str(work / "modcache"),
            "GOCACHE": str(work / "gocache"),
            "GOPATH": str(work / "gopath"),
            "GOPROXY": "https://proxy.golang.org",
            "GOSUMDB": "sum.golang.org",
            "NO_COLOR": "1",
        }
        download = run(["go", "mod", "download", "-x", f"{PACKAGE}@{VERSION}"], work, env)
        baseline = run(["go", "mod", "verify"], work, env)
        network_trace = ""
        privacy_exit = baseline["exit_code"]
        if shutil.which("strace"):
            trace = work / "go-mod-verify.strace"
            privacy = run(
                [
                    "strace",
                    "-f",
                    "-s",
                    "300",
                    "-e",
                    "trace=connect,sendto,recvfrom",
                    "-o",
                    str(trace),
                    "go",
                    "mod",
                    "verify",
                ],
                work,
                env,
            )
            privacy_exit = privacy["exit_code"]
            if trace.exists():
                network_trace = trace.read_text(
                    encoding="utf-8", errors="replace"
                )
        module_dir = work / "modcache" / "github.com" / "stretchr" / f"testify@{VERSION}"
        target = module_dir / "README.md"
        if not target.exists():
            raise RuntimeError(f"downloaded module file not found: {target}")
        target.write_bytes(target.read_bytes() + b"\nmodified by behavior probe\n")
        bad_input = run(["go", "mod", "verify"], work, env)
        summary = {
            "package": PACKAGE,
            "version": VERSION,
            "go": subprocess.run(["go", "version"], capture_output=True, text=True, check=True).stdout.strip(),
            "download": download,
            "baseline": baseline,
            "bad_input": bad_input,
            "privacy_exit_code": privacy_exit,
            "privacy_network_calls": sum(
                1
                for line in network_trace.splitlines()
                if "connect(" in line or "sendto(" in line or "recvfrom(" in line
            ),
        }
        (out / "go-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        return summary
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summary = reproduce(args.out)
    print(json.dumps(summary, indent=2))
    return 0 if summary["download"]["exit_code"] == 0 and summary["baseline"]["exit_code"] == 0 and summary["bad_input"]["exit_code"] != 0 and summary["privacy_exit_code"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
