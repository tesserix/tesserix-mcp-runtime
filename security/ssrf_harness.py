"""Run isolated TLS SSRF probes outside the socket-free unit-test suite."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import ssl
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tesserix_mcp_runtime import ErrorCode
from tesserix_mcp_runtime.adapters.outbound_http import (
    OutboundHTTPClient,
    OutboundHTTPError,
)
from tesserix_mcp_runtime.egress import (
    DeclaredEgressPolicy,
    EgressDestination,
    EgressManifest,
)
from tesserix_mcp_runtime.redaction import SecretRedactor


class HarnessResolver:
    def __init__(self, answers: Mapping[str, list[tuple[str, ...]]]) -> None:
        self._answers = {host: list(values) for host, values in answers.items()}

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        del port
        values = self._answers[host]
        if len(values) > 1:
            return values.pop(0)
        return values[0]


class IsolatedTLSServer:
    def __init__(self, ssl_context: ssl.SSLContext, *, host: str) -> None:
        self._ssl_context = ssl_context
        self._host = host
        self._server: asyncio.Server | None = None
        self.port = 0
        self.connections = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle,
            host=self._host,
            port=0,
            ssl=self._ssl_context,
            limit=65_536,
        )
        sockets = self._server.sockets
        if not sockets:
            raise RuntimeError("isolated SSRF server did not bind")
        address = sockets[0].getsockname()
        self.port = int(address[1])

    async def close(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.connections += 1
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            first_line = request.split(b"\r\n", 1)[0]
            parts = first_line.split(b" ")
            path = parts[1].decode("ascii") if len(parts) == 3 else "/invalid"
            response = self._response(path)
            writer.write(response)
            await writer.drain()
        except (UnicodeDecodeError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError, ssl.SSLError):
                await writer.wait_closed()

    def _response(self, path: str) -> bytes:
        if path == "/redirect-metadata":
            return self._redirect("https://169.254.169.254/latest/meta-data/")
        if path == "/redirect-private":
            return self._redirect("https://private.example.test/hidden")
        if path == "/redirect-rebind":
            return self._redirect(f"https://localhost:{self.port}/ok")
        body = b"isolated-ok"
        return b"".join(
            (
                b"HTTP/1.1 200 OK\r\n",
                f"Content-Length: {len(body)}\r\n".encode("ascii"),
                b"Connection: close\r\n\r\n",
                body,
            )
        )

    @staticmethod
    def _redirect(location: str) -> bytes:
        return b"".join(
            (
                b"HTTP/1.1 302 Found\r\n",
                f"Location: {location}\r\n".encode("ascii"),
                b"Content-Length: 0\r\n",
                b"Connection: close\r\n\r\n",
            )
        )


def _tls_contexts(directory: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC).replace(tzinfo=None)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path = directory / "server-key.pem"
    certificate_path = directory / "server-certificate.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    certificate_path.write_bytes(certificate_bytes)

    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(certificate_path, key_path)
    client = ssl.create_default_context(cadata=certificate_bytes.decode("ascii"))
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    return server, client


def _policy(
    port: int,
    *,
    permitted_internal_networks: tuple[str, ...] = ("127.0.0.0/8",),
) -> DeclaredEgressPolicy:
    return DeclaredEgressPolicy(
        manifest=EgressManifest(
            destinations=(
                EgressDestination(host="localhost", port=port),
                EgressDestination(host="private.example.test", port=443),
            )
        ),
        permitted_internal_networks=permitted_internal_networks,
    )


async def _request(
    *,
    port: int,
    ssl_context: ssl.SSLContext,
    resolver: HarnessResolver,
    path: str,
    permitted_internal_networks: tuple[str, ...] = ("127.0.0.0/8",),
) -> bytes:
    async with OutboundHTTPClient(
        policy=_policy(
            port,
            permitted_internal_networks=permitted_internal_networks,
        ),
        redactor=SecretRedactor(),
        resolver=resolver,
        ssl_context=ssl_context,
    ) as client:
        response = await client.request(
            "GET",
            f"https://localhost:{port}{path}",
            request_id="ssrf-harness",
        )
        return response.body


async def _expect_error(
    *,
    port: int,
    ssl_context: ssl.SSLContext,
    resolver: HarnessResolver,
    path: str,
    code: ErrorCode,
) -> None:
    try:
        await _request(
            port=port,
            ssl_context=ssl_context,
            resolver=resolver,
            path=path,
        )
    except OutboundHTTPError as error:
        if error.error.code is code:
            return
    raise AssertionError("isolated SSRF probe did not fail with the expected stable code")


async def _expect_invalid_url(client: OutboundHTTPClient, url: str) -> None:
    try:
        await client.request("GET", url, request_id="ssrf-harness")
    except OutboundHTTPError as error:
        if error.error.code is ErrorCode.INVALID_INPUT:
            return
    raise AssertionError("unsafe URL did not fail with the stable invalid-input code")


async def _run() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="tesserix-ssrf-") as directory:
        server_context, client_context = _tls_contexts(Path(directory))
        server = IsolatedTLSServer(server_context, host="127.0.0.1")
        await server.start()
        try:
            body = await _request(
                port=server.port,
                ssl_context=client_context,
                resolver=HarnessResolver({"localhost": [("127.0.0.1",)]}),
                path="/ok",
            )
            if body != b"isolated-ok":
                raise AssertionError("explicit internal destination policy did not connect")

            await _expect_error(
                port=server.port,
                ssl_context=client_context,
                resolver=HarnessResolver({"localhost": [("127.0.0.1",)]}),
                path="/redirect-metadata",
                code=ErrorCode.FORBIDDEN,
            )
            await _expect_error(
                port=server.port,
                ssl_context=client_context,
                resolver=HarnessResolver(
                    {
                        "localhost": [("127.0.0.1",)],
                        "private.example.test": [("10.24.0.7",)],
                    }
                ),
                path="/redirect-private",
                code=ErrorCode.FORBIDDEN,
            )
            await _expect_error(
                port=server.port,
                ssl_context=client_context,
                resolver=HarnessResolver({"localhost": [("127.0.0.1",), ("10.24.0.7",)]}),
                path="/redirect-rebind",
                code=ErrorCode.FORBIDDEN,
            )

            client = OutboundHTTPClient(
                policy=_policy(server.port),
                redactor=SecretRedactor(),
                resolver=HarnessResolver({"localhost": [("127.0.0.1",)]}),
                ssl_context=client_context,
            )
            try:
                connections_before_invalid_urls = server.connections
                await _expect_invalid_url(client, "https://2130706433/")
                await _expect_invalid_url(
                    client,
                    f"https://user:placeholder@localhost:{server.port}/ok",
                )
                await _expect_invalid_url(
                    client,
                    f"https://local%68ost:{server.port}/ok",
                )
                if server.connections != connections_before_invalid_urls:
                    raise AssertionError("unsafe URL reached the isolated server")
            finally:
                await client.aclose()
        finally:
            await server.close()

        ipv6_server = IsolatedTLSServer(server_context, host="::1")
        await ipv6_server.start()
        try:
            body = await _request(
                port=ipv6_server.port,
                ssl_context=client_context,
                resolver=HarnessResolver({"localhost": [("::1",)]}),
                path="/ok",
                permitted_internal_networks=("::1/128",),
            )
            if body != b"isolated-ok":
                raise AssertionError("explicit IPv6 policy did not connect")
        finally:
            await ipv6_server.close()

        return {
            "checks": [
                "explicit_internal_policy",
                "explicit_internal_ipv6_policy",
                "metadata_redirect",
                "private_redirect",
                "dns_rebinding",
                "alternate_ip",
                "credential_url_rejected",
                "encoded_host_rejected",
            ],
            "connections": server.connections + ipv6_server.connections,
            "passed": True,
        }


def main() -> int:
    report = asyncio.run(_run())
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
