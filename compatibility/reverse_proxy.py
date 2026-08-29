from __future__ import annotations

import contextlib
import http.client
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


class ReverseProxyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, upstream_port: int) -> None:
        self.upstream_port = upstream_port
        super().__init__(("127.0.0.1", 0), ReverseProxyHandler)


class ReverseProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format_string: str, *args: object) -> None:
        del format_string, args

    def do_GET(self) -> None:
        self._proxy()

    def do_POST(self) -> None:
        self._proxy()

    def do_DELETE(self) -> None:
        self._proxy()

    def _proxy(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path not in {"/gateway/runtime/mcp", "/gateway/runtime/mcp/"}:
            self.send_response_only(404)
            self.send_header("content-length", "0")
            self.end_headers()
            return

        content_length = int(self.headers.get("content-length", "0"))
        if content_length < 0 or content_length > 65_536:
            self.send_response_only(413)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        body = self.rfile.read(content_length) if content_length else None
        server = self.server
        if not isinstance(server, ReverseProxyServer):
            raise RuntimeError("reverse proxy server is misconfigured")
        upstream_headers = {
            name: value
            for name, value in self.headers.items()
            if name.casefold() not in _HOP_BY_HOP_HEADERS | {"host"}
        }
        upstream_headers["host"] = f"127.0.0.1:{server.upstream_port}"
        upstream_path = "/mcp/" if parsed.path.endswith("/") else "/mcp"
        if parsed.query:
            upstream_path = f"{upstream_path}?{parsed.query}"

        connection = http.client.HTTPConnection(
            "127.0.0.1",
            server.upstream_port,
            timeout=10,
        )
        completed = threading.Event()
        downstream_closed = threading.Event()

        def close_upstream_on_disconnect() -> None:
            while not completed.is_set():
                readable, _, _ = select.select([self.connection], [], [], 0.05)
                if not readable:
                    continue
                try:
                    pending = self.connection.recv(1, socket.MSG_PEEK)
                except OSError:
                    pending = b""
                if pending:
                    continue
                downstream_closed.set()
                upstream_socket = connection.sock
                if upstream_socket is not None:
                    with contextlib.suppress(OSError):
                        upstream_socket.shutdown(socket.SHUT_RDWR)
                connection.close()
                return

        try:
            connection.request(
                self.command,
                upstream_path,
                body=body,
                headers=upstream_headers,
            )
            monitor = threading.Thread(
                target=close_upstream_on_disconnect,
                name="mcp-proxy-disconnect-monitor",
                daemon=True,
            )
            monitor.start()
            response = connection.getresponse()
            response_body = response.read()
            self.send_response_only(response.status)
            for name, value in response.getheaders():
                if name.casefold() not in _HOP_BY_HOP_HEADERS | {"content-length"}:
                    self.send_header(name, value)
            self.send_header("content-length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
        except (http.client.HTTPException, OSError):
            if not downstream_closed.is_set():
                raise
        finally:
            completed.set()
            connection.close()


__all__ = ["ReverseProxyServer"]
