const { test } = require('node:test');
const assert = require('node:assert/strict');
const { statementBinding } = require('../provenance/verify/sigstore_js/npm_verify.cjs');

function bundle(digest, type = 'https://in-toto.io/Statement/v1') {
  return { dsseEnvelope: { payload: Buffer.from(JSON.stringify({
    _type: type, predicateType: 'https://slsa.dev/provenance/v1', subject: [{ digest }],
  })).toString('base64') } };
}

test('SHA-512 subject binds directly to the downloaded artifact', () => {
  assert.equal(statementBinding(bundle({ sha512: 'bb' }), { sha256: 'aa', sha512: 'bb' }).matches, true);
});
test('a mismatched or unsupported subject digest cannot bind', () => {
  assert.equal(statementBinding(bundle({ sha512: 'cc' }), { sha512: 'bb' }).matches, false);
  assert.equal(statementBinding(bundle({ md5: 'bb' }), { sha512: 'bb' }).matches, false);
});
test('all supported digests in the selected subject must match', () => {
  assert.equal(statementBinding(bundle({ sha256: 'cc', sha512: 'bb' }), { sha256: 'aa', sha512: 'bb' }).matches, false);
});
test('missing payload and unrecognized statement types cannot bind', () => {
  assert.equal(statementBinding({}, {}).matches, false);
  assert.equal(statementBinding(bundle({ sha512: 'bb' }, 'other'), { sha512: 'bb' }).matches, false);
});
