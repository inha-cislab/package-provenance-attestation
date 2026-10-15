from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.request import Request, urlopen

BASE = "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.14.0"
JAR = "commons-lang3-3.14.0.jar"
KEYS = "https://downloads.apache.org/commons/KEYS"


def fetch(url: str) -> bytes:
    with urlopen(Request(url, headers={"User-Agent": "provenance-behavior-reproduction"}), timeout=60) as response:
        return response.read()


def run(command: list[str], work: Path, env: dict[str, str]) -> dict:
    completed = subprocess.run(command, cwd=work, env=env, capture_output=True, text=True, timeout=180, check=False)
    return {
        "command": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-12000:],
        "stderr": completed.stderr[-12000:],
    }


def reproduce(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="maven-gpg-behavior-"))
    try:
        jar = work / JAR
        signature = work / f"{JAR}.asc"
        keys = work / "KEYS"
        jar.write_bytes(fetch(f"{BASE}/{JAR}"))
        signature.write_bytes(fetch(f"{BASE}/{JAR}.asc"))
        keys.write_bytes(fetch(KEYS))
        empty_home = work / "gpg-empty"
        trusted_home = work / "gpg-trusted"
        empty_home.mkdir(mode=0o700)
        trusted_home.mkdir(mode=0o700)
        env = {**os.environ, "NO_COLOR": "1"}
        no_key = run(["gpg", "--batch", "--homedir", str(empty_home), "--verify", str(signature), str(jar)], work, env)
        imported = run(["gpg", "--batch", "--homedir", str(trusted_home), "--import", str(keys)], work, env)
        baseline = run(["gpg", "--batch", "--homedir", str(trusted_home), "--verify", str(signature), str(jar)], work, env)
        tampered = work / "commons-lang3-3.14.0-tampered.jar"
        body = bytearray(jar.read_bytes())
        body[4096] = (body[4096] + 1) % 256
        tampered.write_bytes(body)
        bad_input = run(["gpg", "--batch", "--homedir", str(trusted_home), "--verify", str(signature), str(tampered)], work, env)
        summary = {
            "package": "org.apache.commons:commons-lang3",
            "version": "3.14.0",
            "gpg": subprocess.run(["gpg", "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0],
            "no_key": no_key,
            "key_import": imported,
            "baseline": baseline,
            "bad_input": bad_input,
        }
        (out / "maven-gpg-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        return summary
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summary = reproduce(args.out)
    print(json.dumps(summary, indent=2))
    return 0 if summary["no_key"]["exit_code"] == 2 and summary["baseline"]["exit_code"] == 0 and summary["bad_input"]["exit_code"] == 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
