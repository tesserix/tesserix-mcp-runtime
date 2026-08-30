"""Exact outbound destination and connection-address policy contracts."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from tesserix_mcp_runtime.contracts import ErrorCode, JsonValue
from tesserix_mcp_runtime.errors import RuntimeFailure

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_NUMERIC_HOST = re.compile(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)(?:\.(?:0[xX][0-9A-Fa-f]+|[0-9]+))*\Z")
_NAT64_NETWORKS = (
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
)
_IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")
_INTERNAL_V4_NETWORKS = tuple(
    ipaddress.IPv4Network(value)
    for value in (
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
    )
)
_INTERNAL_V6_NETWORKS = tuple(
    ipaddress.IPv6Network(value) for value in ("::1/128", "fc00::/7", "fe80::/10")
)
_MAX_DESTINATIONS = 256
_MAX_INTERNAL_NETWORKS = 32
_MAX_DNS_ADDRESSES = 16


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


def _canonical_host(value: str) -> str:
    if (
        not _is_runtime_instance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 253
        or any(character in value for character in "/@%?#")
    ):
        raise ValueError("host must be a canonical DNS name or IP address")
    candidate = value[:-1] if value.endswith(".") else value
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass
    if _NUMERIC_HOST.fullmatch(candidate) is not None:
        raise ValueError("host must not use an alternate numeric IP representation")
    try:
        ascii_host = candidate.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        raise ValueError("host must be a canonical DNS name or IP address") from None
    labels = ascii_host.split(".")
    if not labels or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise ValueError("host must be a canonical DNS name or IP address")
    return ascii_host


@dataclass(frozen=True, slots=True, kw_only=True)
class EgressDestination:
    host: str
    port: int = 443

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", _canonical_host(self.host))
        if (
            _is_runtime_instance(self.port, bool)
            or not _is_runtime_instance(self.port, int)
            or not 1 <= self.port <= 65_535
        ):
            raise ValueError("port must be an integer from 1 through 65535")

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


@dataclass(frozen=True, slots=True, kw_only=True)
class EgressManifest:
    destinations: tuple[EgressDestination, ...] = ()

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.destinations, tuple)
            or len(self.destinations) > _MAX_DESTINATIONS
            or any(
                not _is_runtime_instance(destination, EgressDestination)
                for destination in self.destinations
            )
            or len(set(self.destinations)) != len(self.destinations)
        ):
            raise ValueError("egress manifest must contain at most 256 unique destinations")
        object.__setattr__(
            self,
            "destinations",
            tuple(sorted(self.destinations, key=lambda item: (item.host, item.port))),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "destinations": [
                {
                    "scheme": "https",
                    "host": destination.host,
                    "port": destination.port,
                }
                for destination in self.destinations
            ]
        }


class EgressPolicyViolation(RuntimeFailure):
    """Fail closed without attaching a rejected host or address."""

    def __init__(self) -> None:
        super().__init__(ErrorCode.FORBIDDEN)


@runtime_checkable
class EgressPolicy(Protocol):
    def authorize_destination(self, destination: EgressDestination) -> None: ...

    def authorize_connection(
        self,
        destination: EgressDestination,
        addresses: tuple[str, ...],
    ) -> None: ...


def _embedded_ipv4(address: ipaddress.IPv6Address) -> tuple[ipaddress.IPv4Address, ...]:
    if address.ipv4_mapped is not None:
        return (address.ipv4_mapped,)
    if address.sixtofour is not None:
        return (address.sixtofour,)
    if address.teredo is not None:
        return address.teredo
    if address in _IPV4_COMPATIBLE or any(address in network for network in _NAT64_NETWORKS):
        return (ipaddress.IPv4Address(int(address) & 0xFFFFFFFF),)
    return ()


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return False
    if isinstance(address, ipaddress.IPv6Address):
        return all(embedded.is_global for embedded in _embedded_ipv4(address))
    return True


def _is_internal_network(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> bool:
    if isinstance(network, ipaddress.IPv4Network):
        return any(network.subnet_of(candidate) for candidate in _INTERNAL_V4_NETWORKS)
    return any(network.subnet_of(candidate) for candidate in _INTERNAL_V6_NETWORKS)


class DeclaredEgressPolicy:
    """Allow exact manifest authorities and public connection addresses."""

    def __init__(
        self,
        *,
        manifest: EgressManifest,
        permitted_internal_networks: Iterable[str] = (),
    ) -> None:
        if not _is_runtime_instance(manifest, EgressManifest):
            raise ValueError("manifest must satisfy the egress manifest contract")
        networks = tuple(permitted_internal_networks)
        if len(networks) > _MAX_INTERNAL_NETWORKS:
            raise ValueError("internal network policy exceeds its hard maximum")
        parsed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for network in networks:
            try:
                parsed = ipaddress.ip_network(network, strict=True)
            except (TypeError, ValueError):
                raise ValueError("internal networks must use canonical CIDR notation") from None
            if not _is_internal_network(parsed):
                raise ValueError("internal networks must be narrow private CIDR ranges")
            if parsed not in parsed_networks:
                parsed_networks.append(parsed)
        self._destinations = frozenset(manifest.destinations)
        self._internal_networks = tuple(parsed_networks)

    def authorize_destination(self, destination: EgressDestination) -> None:
        if (
            not _is_runtime_instance(destination, EgressDestination)
            or destination not in self._destinations
        ):
            raise EgressPolicyViolation()

    def authorize_connection(
        self,
        destination: EgressDestination,
        addresses: tuple[str, ...],
    ) -> None:
        self.authorize_destination(destination)
        if not addresses or len(addresses) > _MAX_DNS_ADDRESSES:
            raise EgressPolicyViolation()
        for value in addresses:
            try:
                address = ipaddress.ip_address(value)
            except (TypeError, ValueError):
                raise EgressPolicyViolation() from None
            explicitly_permitted = any(
                address.version == network.version and address in network
                for network in self._internal_networks
            )
            if not explicitly_permitted and not _is_public(address):
                raise EgressPolicyViolation()


__all__ = [
    "DeclaredEgressPolicy",
    "EgressDestination",
    "EgressManifest",
    "EgressPolicy",
    "EgressPolicyViolation",
]
