const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { verifyBundle } = require('../provenance/verify/sigstore_js/npm_verify.cjs');

class PolicyError extends Error {}
class TUFError extends Error {}
class ValidationError extends Error {}
class VerificationError extends Error {}
const api = verify => ({ verify, PolicyError, TUFError, ValidationError, VerificationError });
function request(digests = { sha512: 'ab' }) {
  return { bundle: { dsseEnvelope: { payload: Buffer.from(JSON.stringify({
    _type: 'https://in-toto.io/Statement/v1', subject: [{ digest: digests }],
  })).toString('base64') } }, artifact_digests: { sha256: 'cd', sha512: 'ab' } };
}

test('DSSE calls sigstore.verify and binds the SHA-512 subject', async () => {
  const input = request();
  let called = false;
  const result = await verifyBundle(input, api(async (bundle, options) => {
    called = true;
    assert.equal(bundle, input.bundle);
    assert.equal(options.tufForceCache, undefined);
  }));
  assert.ok(called);
  assert.equal(result.outcome, 'verified');
});

test('conflicting digests in one subject fail binding', async () => {
  const result = await verifyBundle(request({ sha256: 'ef', sha512: 'ab' }), api(async () => {}));
  assert.equal(result.verified, true);
  assert.equal(result.subject_matches, false);
  assert.equal(result.outcome, 'subject mismatch');
});

test('bare-key bundles are not reported as certificate-backed signatures', async () => {
  const input = request();
  input.bundle.verificationMaterial = { publicKey: { hint: 'example' } };
  const result = await verifyBundle(input, api(async () => { assert.fail('must not verify'); }));
  assert.equal(result.outcome, 'uncertified key');
  assert.equal(result.verified, false);
});

test('invalid signatures and unavailable trust roots cannot verify', async () => {
  for (const [error, outcome] of [[new VerificationError('bad signature'), 'verification failed'],
    [new TUFError('unavailable'), 'trust root unavailable'],
    [new Error('cache unavailable'), 'verifier unavailable'],
    [new ValidationError('bad bundle'), 'unreadable bundle']]) {
    const result = await verifyBundle(request(), api(async () => { throw error; }));
    assert.equal(result.verified, false);
    assert.equal(result.outcome, outcome);
  }
});

test('concurrent trust-cache creation retries without bypassing verification', async () => {
  let calls = 0;
  const result = await verifyBundle(request(), api(async () => {
    if (calls++ === 0) throw Object.assign(new Error('cache exists'), { code: 'EEXIST', syscall: 'mkdir' });
  }));
  assert.equal(calls, 2);
  assert.equal(result.outcome, 'verified');
});

test('repository policy refusal is distinct from invalid signatures', async () => {
  const input = { ...request(), expected_repository: 'owner/project' };
  const result = await verifyBundle(input, api(async (bundle, options) => {
    assert.equal(options.certificateIssuer, 'https://token.actions.githubusercontent.com');
    assert.equal(options.certificateOIDs['1.3.6.1.4.1.57264.1.5'], 'owner/project');
    throw new PolicyError('wrong repository');
  }));
  assert.equal(result.verified, true);
  assert.equal(result.outcome, 'policy refused');
});

test('message signatures pass artifact bytes and check recorded digests', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'npm-verifier-test-'));
  try {
    const bytes = Buffer.from('synthetic artifact');
    const digest = crypto.createHash('sha256').update(bytes).digest();
    const artifact = path.join(dir, 'artifact');
    await fs.writeFile(artifact, bytes);
    const input = { bundle: { messageSignature: { messageDigest: {
      algorithm: 'SHA2_256', digest: digest.toString('base64'),
    } } }, artifact_path: artifact, artifact_digests: { sha256: digest.toString('hex') } };
    const verifier = api(async (bundle, data, options) => {
      assert.deepEqual(data, bytes);
      assert.equal(options.tufForceCache, undefined);
    });
    assert.equal((await verifyBundle(input, verifier)).outcome, 'verified');
    input.artifact_digests.sha256 = 'ff';
    assert.equal((await verifyBundle(input, verifier)).outcome, 'subject mismatch');
  } finally {
    await fs.rm(dir, { recursive: true });
  }
});
