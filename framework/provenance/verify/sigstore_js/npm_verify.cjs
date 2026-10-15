const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

function statementBinding(bundle, actual) {
  const payload = bundle.dsseEnvelope?.payload;
  if (!payload) return { matches: false, reason: 'No DSSE statement payload' };
  const statement = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
  const subjects = statement.subject || [];
  const matches = subjects.some(s => {
    const recognized = Object.entries(s.digest || {}).filter(([a]) => ['sha256', 'sha512'].includes(a));
    return recognized.length > 0 && recognized.every(([a, value]) => String(value).toLowerCase() === actual[a]);
  });
  return { matches: matches && ['https://in-toto.io/Statement/v1', 'https://in-toto.io/Statement/v0.1'].includes(statement._type),
    statement_type: statement._type, predicate_type: statement.predicateType, subjects };
}

function loadSigstore() {
  const locations = [process.env.PROVENANCE_NPM_PREFIX, __dirname,
    path.resolve('framework/provenance/verify/sigstore_js'), process.cwd()].filter(Boolean);
  return require(require.resolve('sigstore', { paths: locations }));
}

async function verifyBundle(request, sigstore = loadSigstore()) {
  const { bundle, artifact_digests: actual, expected_repository: repository } = request;
  const result = { verified: false, subject_matches: false, outcome: 'verification failed',
    subject_digests: {}, subjects: 0, detail: '' };
  if (bundle.verificationMaterial?.publicKey) {
    return { ...result, outcome: 'uncertified key', detail: 'Bundle carries a public key without a certificate' };
  }
  let binding, bytes;
  try {
    if (bundle.dsseEnvelope) {
      binding = statementBinding(bundle, actual);
      for (const subject of binding.subjects || []) {
        for (const [algorithm, value] of Object.entries(subject.digest || {})) {
          (result.subject_digests[algorithm] ||= []).push(String(value).toLowerCase());
        }
      }
      result.subjects = (binding.subjects || []).length;
    } else if (bundle.messageSignature) {
      const recorded = bundle.messageSignature.messageDigest;
      const algorithm = { SHA2_256: 'sha256', SHA2_384: 'sha384', SHA2_512: 'sha512' }[recorded.algorithm];
      if (!algorithm) throw new Error('Unsupported message digest');
      const value = Buffer.from(recorded.digest, 'base64').toString('hex');
      result.subject_digests = { [algorithm]: [value] };
      result.subjects = 1;
      bytes = await fs.readFile(request.artifact_path);
      binding = { matches: actual[algorithm] === value
        && crypto.createHash(algorithm).update(bytes).digest('hex') === value
        && Object.entries(actual).every(([a, v]) => crypto.createHash(a).update(bytes).digest('hex') === v) };
    } else {
      throw new Error('Bundle carries no signed content');
    }
  } catch (error) {
    return { ...result, outcome: 'unreadable bundle', detail: error.message };
  }
  const options = { timeout: 30000, retry: 2 };
  if (repository) {
    options.certificateIssuer = 'https://token.actions.githubusercontent.com';
    options.certificateOIDs = { '1.3.6.1.4.1.57264.1.5': repository };
  }
  let policyRefused = false;
  try {
    for (let attempt = 0; ; attempt++) {
      try {
        if (bytes) await sigstore.verify(bundle, bytes, options);
        else await sigstore.verify(bundle, options);
        break;
      } catch (error) {
        if (error.code !== 'EEXIST' || error.syscall !== 'mkdir' || attempt >= 2) throw error;
        await new Promise(resolve => setTimeout(resolve, 200));
      }
    }
  } catch (error) {
    result.detail = error.message;
    if (error instanceof sigstore.PolicyError) policyRefused = true;
    else {
      if (error instanceof sigstore.TUFError) result.outcome = 'trust root unavailable';
      else if (error instanceof sigstore.ValidationError) result.outcome = 'unreadable bundle';
      else if (!(error instanceof sigstore.VerificationError)) result.outcome = 'verifier unavailable';
      return result;
    }
  }
  result.verified = true;
  result.subject_matches = binding.matches;
  result.outcome = !binding.matches ? 'subject mismatch' : policyRefused ? 'policy refused' : 'verified';
  return result;
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  const result = await verifyBundle(JSON.parse(input));
  process.stdout.write(JSON.stringify(result));
}

module.exports = { statementBinding, verifyBundle };
if (require.main === module) main().catch(error => {
  process.stderr.write(error.message + '\n');
  process.exitCode = 1;
});
