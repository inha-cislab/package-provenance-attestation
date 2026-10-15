import hashlib
import io
import zipfile

from provenance.behavior.maven_checksum import JAR, RELATIVE, make_repository, passed


def test_synthetic_jar_and_checksum_sidecars(tmp_path):
    for mismatch in (False, True):
        root = tmp_path / str(mismatch)
        data = make_repository(root, mismatch=mismatch)
        assert zipfile.is_zipfile(io.BytesIO(data))
        expected = (root / RELATIVE / (JAR + '.sha1')).read_text()
        assert (expected == hashlib.sha1(data).hexdigest()) is not mismatch


def test_success_requires_mismatch_diagnostic_and_strict_rejection():
    baseline = {'exit_code': 0, 'artifact_matches': True, 'checksum_mismatch_reported': False}
    default = {**baseline, 'checksum_mismatch_reported': True}
    strict = {'exit_code': 1, 'artifact_cached': False, 'checksum_mismatch_reported': True}
    summary = {'baseline': baseline, 'default_mismatch': default, 'strict_mismatch': strict}
    assert passed(summary)
    strict['checksum_mismatch_reported'] = False
    assert not passed(summary)
