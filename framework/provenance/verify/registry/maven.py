from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
from typing import Dict, List
import urllib.error

from .common import download_file, read_bytes


MAVEN_CENTRAL = "https://repo1.maven.org/maven2"
MAVEN_KEYS = (
    "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x{}",
    "https://keys.openpgp.org/vks/v1/by-keyid/{}",
)
_gpg_key_lock = threading.Lock()


def maven_urls(package: str, version: str) -> tuple[str, str]:
    group, artifact = package.split(":", 1)
    stem = (
        f"{MAVEN_CENTRAL}/{group.replace('.', '/')}/{artifact}/{version}/"
        f"{artifact}-{version}.jar"
    )
    return stem, stem + ".asc"


def run_gpg(arguments: List[str], env: Dict[str, str], stdin=None):
    return subprocess.run(
        ["gpg", "--batch", "--quiet", *arguments],
        env=env,
        input=stdin,
        capture_output=True,
        check=False,
    )


def gpg_output(completed) -> str:
    return "\n".join(
        part.decode("utf-8", "replace")
        for part in (completed.stdout, completed.stderr)
        if part
    )


def gpg_keyring_error(output: str) -> bool:
    lowered = output.lower()
    return any(
        marker in lowered
        for marker in (
            "add_keyblock_resource",
            "failed to create temporary file",
            "can't create keybox",
            "cannot create keybox",
        )
    )


def maven_key_id(signature: Path, env: Dict[str, str]) -> str:
    completed = run_gpg(["--list-packets", str(signature)], env)
    output = completed.stdout.decode("utf-8", "replace")
    match = re.search(r"keyid ([0-9A-Fa-f]{16})", output)
    return match.group(1).upper() if match else ""


def fetch_gpg_key(key_id: str, env: Dict[str, str]) -> tuple[bool, str]:
    """Import *key_id* from either public endpoint into the shared keyring."""
    diagnostics: List[str] = []
    with _gpg_key_lock:
        listed = run_gpg(["--list-keys", key_id], env)
        diagnostics.append(gpg_output(listed))
        if listed.returncode == 0:
            return True, "\n".join(diagnostics)
        for template in MAVEN_KEYS:
            try:
                body = read_bytes(
                    template.format(key_id), attempts=2, timeout=90
                )
            except Exception:
                continue
            if b"BEGIN PGP PUBLIC KEY" not in body:
                continue
            imported = run_gpg(["--import"], env, stdin=body)
            diagnostics.append(gpg_output(imported))
            listed = run_gpg(["--list-keys", key_id], env)
            diagnostics.append(gpg_output(listed))
            if listed.returncode == 0:
                return True, "\n".join(diagnostics)
    return False, "\n".join(diagnostics)


def verify_maven(row: Dict[str, str], *, work_root: Path) -> dict:
    package = row["package"]
    version = row["version"]
    jar_url, signature_url = maven_urls(package, version)
    expected_sha256 = (row.get("digest_sha256") or "").lower()
    record = {
        "ecosystem": "maven",
        "rank": int(row["rank"]) if row.get("rank") else None,
        "package": package,
        "version": version,
        "level": "attribution",
        "source": "detached OpenPGP .jar.asc",
        "artifact_url": jar_url,
        "signature_url": signature_url,
        "expected_sha256": expected_sha256,
    }
    if shutil.which("gpg") is None:
        return {**record, "outcome": "tool missing", "detail": "gpg not found"}

    keyring = work_root / "gnupg"
    keyring.mkdir(parents=True, exist_ok=True)
    try:
        keyring.chmod(0o700)
    except OSError:
        pass
    env = {**os.environ, "GNUPGHOME": str(keyring), "LC_ALL": "C"}

    with tempfile.TemporaryDirectory(
        prefix="package-", dir=work_root
    ) as temporary:
        directory = Path(temporary)
        signature = directory / "artifact.jar.asc"
        try:
            download_file(signature_url, signature)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return {
                    **record,
                    "outcome": "no evidence",
                    "detail": "Maven Central serves no .jar.asc sidecar",
                }
            return {
                **record,
                "outcome": "error",
                "detail": f"HTTPError: {error}",
            }
        except Exception as error:
            return {
                **record,
                "outcome": "error",
                "detail": f"{type(error).__name__}: {error}",
            }

        artifact = directory / "artifact.jar"
        try:
            actual_sha256, size = download_file(jar_url, artifact)
        except Exception as error:
            return {
                **record,
                "outcome": "error",
                "detail": f"{type(error).__name__}: {error}",
            }
        key_id = maven_key_id(signature, env)
        if key_id:
            key_available, key_diagnostics = fetch_gpg_key(key_id, env)
        else:
            key_available, key_diagnostics = False, ""
        completed = run_gpg(
            ["--status-fd", "1", "--verify", str(signature), str(artifact)], env
        )
        status_output = completed.stdout.decode("utf-8", "replace")
        stderr = completed.stderr.decode("utf-8", "replace")
        keyring_failed = gpg_keyring_error(
            "\n".join((key_diagnostics, status_output, stderr))
        )
        verdict = next(
            (
                label
                for label in (
                    "GOODSIG",
                    "EXPKEYSIG",
                    "REVKEYSIG",
                    "BADSIG",
                    "ERRSIG",
                    "NO_PUBKEY",
                )
                if f"[GNUPG:] {label}" in status_output
            ),
            "UNKNOWN",
        )

    bytes_match = not expected_sha256 or actual_sha256 == expected_sha256
    signature_valid = verdict in {"GOODSIG", "EXPKEYSIG", "REVKEYSIG"}
    if signature_valid and bytes_match:
        outcome = "verified"
    elif keyring_failed:
        outcome = "tool misconfigured"
    elif verdict in {"ERRSIG", "NO_PUBKEY"} or not key_available:
        outcome = "key unavailable"
    elif verdict == "BADSIG" or not bytes_match:
        outcome = "verification failed"
    else:
        outcome = "error"
    return {
        **record,
        "outcome": outcome,
        "exit_code": completed.returncode,
        "key_id": key_id,
        "key_available": key_available,
        "verdict": verdict,
        "actual_sha256": actual_sha256,
        "bytes_match": bytes_match,
        "signature_valid": signature_valid,
        "artifact_bytes": size,
        "keyring_status": key_diagnostics[-8000:],
        "gpg_status": status_output[-8000:],
        "stderr": stderr[-8000:],
        "detail": (
            "GnuPG could not initialize or access its keyring"
            if keyring_failed else ""
        ),
    }
