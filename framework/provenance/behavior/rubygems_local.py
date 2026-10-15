from __future__ import annotations

import argparse
import copy
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


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


def tamper_gem(original: bytes) -> bytes:
    source = tarfile.open(fileobj=io.BytesIO(original), mode="r:")
    output = io.BytesIO()
    with source, tarfile.open(fileobj=output, mode="w") as target:
        for member in source.getmembers():
            extracted = source.extractfile(member) if member.isfile() else None
            data = extracted.read() if extracted is not None else None
            if member.name == "data.tar.gz" and data is not None:
                content = gzip.decompress(data) + b"\nmodified by behavior probe\n"
                buffer = io.BytesIO()
                with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
                    compressed.write(content)
                data = buffer.getvalue()
                member = copy.copy(member)
                member.size = len(data)
            target.addfile(member, io.BytesIO(data) if data is not None else None)
    return output.getvalue()


def reproduce(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="rubygems-behavior-"))
    try:
        home = work / "home"
        gem_home = work / "gem-home"
        install_good = work / "install-good"
        install_bad = work / "install-bad"
        (work / "lib").mkdir()
        home.mkdir()
        gem_home.mkdir()
        (work / "lib" / "behavior_probe.rb").write_text("module BehaviorProbe; end\n", encoding="utf-8")
        (work / "behavior-probe.gemspec").write_text(
            "Gem::Specification.new do |s|\n"
            "  s.name = 'behavior-probe'\n"
            "  s.version = '1.0.0'\n"
            "  s.summary = 'verification behavior probe'\n"
            "  s.authors = ['Anonymous']\n"
            "  s.files = ['lib/behavior_probe.rb']\n"
            "  s.cert_chain = [File.expand_path('gem-public_cert.pem', __dir__)]\n"
            "  s.signing_key = File.expand_path('gem-private_key.pem', __dir__)\n"
            "end\n",
            encoding="utf-8",
        )
        env = {**os.environ, "HOME": str(home), "GEM_HOME": str(gem_home), "GEM_PATH": str(gem_home), "NO_COLOR": "1"}
        certificate = run(["gem", "cert", "--build", "artifact@example.invalid"], work, env)
        if certificate["exit_code"] != 0:
            raise RuntimeError(certificate["stderr"] or certificate["stdout"])
        trusted = run(["gem", "cert", "--add", "gem-public_cert.pem"], work, env)
        built = run(["gem", "build", "behavior-probe.gemspec"], work, env)
        gem_path = work / "behavior-probe-1.0.0.gem"
        if not gem_path.exists():
            raise RuntimeError(built["stderr"] or built["stdout"])
        tampered_path = work / "behavior-probe-1.0.0-tampered.gem"
        tampered_path.write_bytes(tamper_gem(gem_path.read_bytes()))
        baseline = run(["gem", "install", "--local", "--trust-policy", "HighSecurity", "--install-dir", str(install_good), str(gem_path)], work, env)
        bad_input = run(["gem", "install", "--local", "--trust-policy", "HighSecurity", "--install-dir", str(install_bad), str(tampered_path)], work, env)
        summary = {
            "package": "behavior-probe",
            "version": "1.0.0",
            "ruby": subprocess.run(["ruby", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
            "rubygems": subprocess.run(["gem", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
            "certificate": certificate,
            "trusted": trusted,
            "build": built,
            "baseline": baseline,
            "bad_input": bad_input,
        }
        (out / "rubygems-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
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
