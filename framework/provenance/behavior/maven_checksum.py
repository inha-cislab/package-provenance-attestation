from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

GROUP = 'org.example.provenance'
ARTIFACT = 'checksum-probe'
VERSION = '1.0'
RELATIVE = Path(*GROUP.split('.')) / ARTIFACT / VERSION
JAR = f'{ARTIFACT}-{VERSION}.jar'
PLUGIN = 'org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get'


def make_repository(root: Path, *, mismatch: bool) -> bytes:
    folder = root / RELATIVE
    folder.mkdir(parents=True, exist_ok=False)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n\n')
        archive.writestr('probe.txt', 'local checksum experiment\n')
    data = buffer.getvalue()
    pom = (f'<project xmlns="http://maven.apache.org/POM/4.0.0">'
           f'<modelVersion>4.0.0</modelVersion><groupId>{GROUP}</groupId>'
           f'<artifactId>{ARTIFACT}</artifactId><version>{VERSION}</version>'
           '<packaging>jar</packaging></project>').encode()
    for filename, content in ((JAR, data), (f'{ARTIFACT}-{VERSION}.pom', pom)):
        (folder / filename).write_bytes(content)
        digest = '0' * 40 if mismatch and filename == JAR else hashlib.sha1(content).hexdigest()
        (folder / (filename + '.sha1')).write_text(digest, encoding='ascii')
    return data


def run_case(mvn: str, out: Path, label: str, remote: Path, data: bytes,
             *, strict: bool = False) -> dict:
    work = out / label
    work.mkdir()
    cache = work / 'repository'
    command = [mvn, '-B', '-s', str(out / 'settings.xml'), '-gs', str(out / 'settings.xml')]
    if strict:
        command.append('-C')
    command += [PLUGIN, f'-Dartifact={GROUP}:{ARTIFACT}:{VERSION}', '-Dtransitive=false',
                f'-DremoteRepositories=probe::default::{remote.as_uri()}',
                f'-Dmaven.repo.local={cache}']
    env = {k: v for k, v in os.environ.items()
           if k not in ('MAVEN_ARGS', 'MAVEN_OPTS', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS')}
    completed = subprocess.run(command, cwd=work, env=env, capture_output=True,
                               text=True, encoding='utf-8', errors='replace',
                               timeout=900, check=False)
    (work / 'stdout.txt').write_text(completed.stdout, encoding='utf-8')
    (work / 'stderr.txt').write_text(completed.stderr, encoding='utf-8')
    installed = cache / RELATIVE / JAR
    output = completed.stdout + completed.stderr
    result = {
        'command': command, 'exit_code': completed.returncode,
        'artifact_cached': installed.exists(),
        'artifact_matches': installed.exists() and installed.read_bytes() == data,
        'checksum_mismatch_reported': 'checksum validation failed' in output.lower()
            or 'checksum failed' in output.lower(),
    }
    (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


def passed(summary: dict) -> bool:
    good, default, strict = (summary[k] for k in ('baseline', 'default_mismatch', 'strict_mismatch'))
    return (good['exit_code'] == 0 and good['artifact_matches']
            and not good['checksum_mismatch_reported']
            and default['exit_code'] == 0 and default['artifact_matches']
            and default['checksum_mismatch_reported']
            and strict['exit_code'] != 0 and strict['checksum_mismatch_reported']
            and not strict['artifact_cached'])


def reproduce(out: Path, mvn: str = 'mvn') -> dict:
    executable = shutil.which(mvn)
    if not executable:
        raise FileNotFoundError(f'Maven executable not found: {mvn}')
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'settings.xml').write_text(
        '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"/>', encoding='utf-8')
    good_repo, bad_repo = out / 'matching-repository', out / 'mismatching-repository'
    good_data = make_repository(good_repo, mismatch=False)
    bad_data = make_repository(bad_repo, mismatch=True)
    version = subprocess.run([executable, '--version'], capture_output=True, text=True, check=True)
    summary = {
        'toolchain': version.stdout.strip(),
        'baseline': run_case(executable, out, 'baseline', good_repo, good_data),
        'default_mismatch': run_case(executable, out, 'default-mismatch', bad_repo, bad_data),
        'strict_mismatch': run_case(executable, out, 'strict-mismatch', bad_repo, bad_data, strict=True),
    }
    summary['passed'] = passed(summary)
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--mvn', default='mvn')
    args = parser.parse_args()
    summary = reproduce(args.out, args.mvn)
    print(json.dumps(summary, indent=2))
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
