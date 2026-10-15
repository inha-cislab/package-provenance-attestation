from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.request import Request, urlopen
import zipfile

PACKAGE = "newtonsoft.json"
VERSION = "13.0.3"
URL = f"https://api.nuget.org/v3-flatcontainer/{PACKAGE}/{VERSION}/{PACKAGE}.{VERSION}.nupkg"


def fetch(url: str) -> bytes:
    with urlopen(Request(url, headers={"User-Agent": "provenance-behavior-reproduction"}), timeout=60) as response:
        return response.read()


def modified_package(original: bytes) -> bytes:
    output = io.BytesIO()
    changed = False
    with zipfile.ZipFile(io.BytesIO(original), "r") as source, zipfile.ZipFile(output, "w") as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if not changed and info.filename.lower().endswith(".nuspec"):
                data += b"\n"
                changed = True
            target.writestr(info, data)
    if not changed:
        raise RuntimeError("could not find the nuspec in the package")
    return output.getvalue()


def run(command: list[str], work: Path) -> dict:
    completed = subprocess.run(
        command,
        cwd=work,
        env={**os.environ, "NO_COLOR": "1"},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
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
    work = Path(tempfile.mkdtemp(prefix="nuget-behavior-"))
    try:
        original = fetch(URL)
        package = work / f"{PACKAGE}.{VERSION}.nupkg"
        tampered = work / f"{PACKAGE}.{VERSION}.tampered.nupkg"
        package.write_bytes(original)
        tampered.write_bytes(modified_package(original))
        baseline = run(["dotnet", "nuget", "verify", str(package), "--all"], work)
        bad_input = run(["dotnet", "nuget", "verify", str(tampered), "--all"], work)
        summary = {
            "package": "Newtonsoft.Json",
            "version": VERSION,
            "dotnet": subprocess.run(["dotnet", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
            "baseline": baseline,
            "bad_input": bad_input,
        }
        (out / "nuget-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        return summary
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summary = reproduce(args.out)
    print(json.dumps(summary, indent=2))
    return 0 if summary["baseline"]["exit_code"] == 0 and summary["bad_input"]["exit_code"] != 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
