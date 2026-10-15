from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from .log_verifier import BundleVerification


class NpmLogVerifier:
    def __init__(self, *, client=None, artifact_url=""):
        self.client = client
        self.artifact_url = artifact_url

    def verify_bundle(self, bundle_json, *, artifact_digests,
                      expected_repository=""):
        node = os.environ.get("PROVENANCE_NODE") or shutil.which("node")
        if not node:
            return BundleVerification(False, False, "verifier unavailable",
                                      detail="Node.js is required for npm verification")
        request = {"bundle": bundle_json, "artifact_digests": artifact_digests,
                   "expected_repository": expected_repository}
        with tempfile.TemporaryDirectory(prefix="provenance-npm-") as directory:
            if bundle_json.get("messageSignature"):
                if self.client is None or not self.artifact_url:
                    return BundleVerification(False, False, "artifact unavailable")
                artifact = Path(directory) / "artifact"

                def consume(response):
                    with artifact.open("wb") as output:
                        shutil.copyfileobj(response, output)

                try:
                    response = self.client.request(self.artifact_url, consume=consume)
                    if not response.ok or not artifact.exists():
                        raise OSError("artifact download failed")
                except Exception as error:
                    return BundleVerification(False, False, "artifact unavailable",
                                              detail=str(error))
                request["artifact_path"] = str(artifact)
            try:
                completed = subprocess.run(
                    [node, str(Path(__file__).parent / "sigstore_js" / "npm_verify.cjs")],
                    input=json.dumps(request), capture_output=True, text=True,
                    encoding="utf-8", timeout=300)
                if completed.returncode:
                    raise RuntimeError(completed.stderr.strip() or "JavaScript verifier failed")
                result = json.loads(completed.stdout)
                if (not isinstance(result, dict)
                        or type(result.get("verified")) is not bool
                        or type(result.get("subject_matches")) is not bool
                        or not isinstance(result.get("outcome"), str)):
                    raise ValueError("invalid JavaScript verifier response")
                return BundleVerification(**result)
            except (OSError, ValueError, TypeError, RuntimeError,
                    subprocess.TimeoutExpired) as error:
                return BundleVerification(False, False, "verifier unavailable",
                                          detail=str(error)[:200])
