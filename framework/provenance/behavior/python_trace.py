from __future__ import annotations

import runpy
import http.client
import json
import socket
import sys
from urllib.parse import urlsplit

_getaddrinfo = socket.getaddrinfo
_create_connection = socket.create_connection
_connect = socket.socket.connect
_putrequest = http.client.HTTPConnection.putrequest
_seen = set()


def _record(host) -> None:
    value = str(host or "")
    if value and value not in _seen:
        _seen.add(value)
        print(f"network-domain https://{value}/", file=sys.stderr, flush=True)


def _traced_getaddrinfo(host, *args, **kwargs):
    _record(host)
    return _getaddrinfo(host, *args, **kwargs)


def _traced_create_connection(address, *args, **kwargs):
    if isinstance(address, tuple) and address:
        _record(address[0])
    return _create_connection(address, *args, **kwargs)


def _traced_connect(connection, address):
    if isinstance(address, tuple) and address:
        _record(address[0])
    return _connect(connection, address)


def _request(method, url):
    parsed = urlsplit(str(url))
    print('network-request ' + json.dumps({
        'event': 'request', 'method': method, 'protocol': parsed.scheme + ':',
        'host': parsed.netloc, 'path': parsed.path + ('?' + parsed.query if parsed.query else ''),
    }), file=sys.stderr, flush=True)


def _traced_putrequest(connection, method, url, *args, **kwargs):
    scheme = 'https' if isinstance(connection, http.client.HTTPSConnection) else 'http'
    target = url if url.startswith(('http://', 'https://')) else f'{scheme}://{connection.host}:{connection.port}{url}'
    _request(method, target)
    return _putrequest(connection, method, url, *args, **kwargs)


def install_hooks():
    socket.getaddrinfo = _traced_getaddrinfo
    socket.create_connection = _traced_create_connection
    socket.socket.connect = _traced_connect
    http.client.HTTPConnection.putrequest = _traced_putrequest
    try:
        import httpx
    except ImportError:
        return
    send = httpx.Client.send
    async_send = httpx.AsyncClient.send

    def traced_send(client, request, *args, **kwargs):
        _request(request.method, request.url)
        return send(client, request, *args, **kwargs)

    async def traced_async_send(client, request, *args, **kwargs):
        _request(request.method, request.url)
        return await async_send(client, request, *args, **kwargs)

    httpx.Client.send = traced_send
    httpx.AsyncClient.send = traced_async_send


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("give a Python module to run")
    module = sys.argv[1]
    sys.argv = [module, *sys.argv[2:]]
    install_hooks()
    runpy.run_module(module, run_name="__main__")


if __name__ == "__main__":
    main()
