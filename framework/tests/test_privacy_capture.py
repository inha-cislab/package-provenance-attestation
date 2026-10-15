import json
import os
from pathlib import Path
import subprocess
import sys

from provenance.behavior.scenarios import domains_in, requests_in, run_scenario


def test_request_paths_and_hosts_are_preserved():
    text = 'network-request ' + json.dumps({
        'event': 'request', 'host': 'tuf-repo-cdn.sigstore.dev:443',
        'path': '/timestamp.json', 'method': 'GET',
    })
    assert requests_in(text)[0]['path'] == '/timestamp.json'
    assert domains_in(text) == ['tuf-repo-cdn.sigstore.dev']
    assert requests_in('network-request invalid\nnetwork-request []') == []


def test_npm_privacy_injects_packaged_hook_and_preserves_environment(monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr('shutil.which', lambda cmd: cmd)
    monkeypatch.setenv('NODE_OPTIONS', '--no-warnings')
    def run(command, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, '', 'network-request {"event":"request","host":"example.org","path":"/a"}')
    monkeypatch.setattr('subprocess.run', run)
    result = run_scenario('npm', 'privacy', {}, workdir=str(tmp_path))
    assert '--no-warnings' in captured['env']['NODE_OPTIONS']
    assert 'node_trace.cjs' in captured['env']['NODE_OPTIONS']
    assert result.domains == ['example.org']
    assert result.requests[0]['path'] == '/a'


def test_python_wrapper_captures_local_http_request(tmp_path):
    source = '''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from urllib.request import urlopen
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')
    def log_message(self, *args): pass
server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
worker = threading.Thread(target=server.serve_forever, daemon=True)
worker.start()
try:
    with urlopen(f'http://127.0.0.1:{server.server_port}/timestamp.json') as response:
        assert response.read() == b'ok'
finally:
    server.shutdown()
    server.server_close()
    worker.join()
'''
    (tmp_path / 'request_probe.py').write_text(source, encoding='utf-8')
    framework = str(Path(__file__).resolve().parents[1])
    result = subprocess.run([sys.executable, '-m', 'provenance.behavior.python_trace', 'request_probe'],
        env={**os.environ, 'PYTHONPATH': os.pathsep.join([str(tmp_path), framework])},
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert '127.0.0.1' in domains_in(result.stderr)
    assert any(r['path'] == '/timestamp.json' for r in requests_in(result.stderr))
