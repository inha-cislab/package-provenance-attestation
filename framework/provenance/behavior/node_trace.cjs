const fs = require('node:fs');

function record(value) {
  process.stderr.write(`network-request ${JSON.stringify(value)}\n`);
  if (process.env.PROVENANCE_NETWORK_TRACE) {
    fs.appendFileSync(process.env.PROVENANCE_NETWORK_TRACE, JSON.stringify(value) + '\n');
  }
}

for (const scheme of ['http', 'https']) {
  const transport = require('node:' + scheme);
  const original = transport.request;
  transport.request = function (...args) {
    const req = Reflect.apply(original, this, args);
    const info = {
      method: req.method, protocol: req.protocol || scheme + ':',
      host: req.getHeader('host'), path: req.path,
    };
    record({ event: 'request', ...info });
    req.once('response', res => record({ event: 'response', ...info, status: res.statusCode }));
    req.once('error', err => record({ event: 'error', ...info, code: err.code }));
    return req;
  };
  transport.get = function (...args) {
    const req = transport.request(...args);
    req.end();
    return req;
  };
}
