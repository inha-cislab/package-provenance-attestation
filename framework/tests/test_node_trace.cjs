const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');

test('Node wrapper records a real request host and path', async () => {
  const server = http.createServer((req, res) => { res.end('ok'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = `http://127.0.0.1:${server.address().port}/timestamp.json`;
    const hook = path.resolve(__dirname, '../provenance/behavior/node_trace.cjs');
    const code = `require('node:http').get(${JSON.stringify(address)}, r => r.resume());`;
    const child = spawn(process.execPath, ['--require', hook, '-e', code]);
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk; });
    const exit = await new Promise((resolve, reject) => { child.on('close', resolve); child.on('error', reject); });
    assert.equal(exit, 0, stderr);
    const requests = stderr.split('\n').filter(l => l.startsWith('network-request '))
      .map(l => JSON.parse(l.slice('network-request '.length)));
    assert.ok(requests.some(r => r.event === 'request' && r.path === '/timestamp.json'
      && r.host === `127.0.0.1:${server.address().port}`));
  } finally { await new Promise(resolve => server.close(resolve)); }
});
