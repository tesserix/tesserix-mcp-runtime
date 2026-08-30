from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tesserix_mcp_manifest.constants import AUTHORING_MANIFEST_VERSION
from tesserix_mcp_manifest.validation import validated_url
from tesserix_mcp_runtime import ToolManifest

_SERVER_NAME = r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$"
_VERSION = r"^\S{1,255}$"
_FINGERPRINT = r"^[a-f0-9]{64}$"
_OCI_DIGEST = r"^sha256:[a-f0-9]{64}$"


class _ManifestModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class ManifestVisibility(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    PRIVATE = "private"


class RuntimeAdapter(StrEnum):
    NATIVE = "native"
    ADK = "adk"


class ManifestLifecycle(StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"


class PackageRegistry(StrEnum):
    NPM = "npm"
    PYPI = "pypi"
    OCI = "oci"
    NUGET = "nuget"
    CARGO = "cargo"
    MCPB = "mcpb"


class Repository(_ManifestModel):
    url: str
    source: str = Field(min_length=1, max_length=64)
    id: str | None = Field(default=None, min_length=1, max_length=256)
    subfolder: str | None = Field(default=None, min_length=1, max_length=512)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return validated_url(value, https_only=True)


class RemoteEndpoint(_ManifestModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return validated_url(value, https_only=True)


class PackageTransport(_ManifestModel):
    type: Literal["stdio", "streamable-http"]
    url: str | None = None

    @model_validator(mode="after")
    def validate_transport(self) -> Self:
        if self.type == "streamable-http":
            if self.url is None:
                raise ValueError("streamable-http package transport requires a URL")
            validated_url(self.url, https_only=False)
        elif self.url is not None:
            raise ValueError("stdio package transport must not contain a URL")
        return self


class PackageIdentity(_ManifestModel):
    registry_type: PackageRegistry
    identifier: str = Field(min_length=1, max_length=2_048)
    transport: PackageTransport
    version: str | None = Field(default=None, pattern=_VERSION)
    registry_base_url: str | None = None
    runtime_hint: str | None = Field(default=None, min_length=1, max_length=64)
    file_sha256: str | None = Field(default=None, pattern=_FINGERPRINT)
    image_digest: str | None = Field(default=None, pattern=_OCI_DIGEST)

    @field_validator("identifier")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if "://" in value:
            return validated_url(value, https_only=True)
        if (
            value != value.strip()
            or any(not character.isprintable() or character.isspace() for character in value)
            or any(delimiter in value for delimiter in ("?", "#", "\\"))
        ):
            raise ValueError("package identifier must be bounded visible text")
        return value

    @field_validator("registry_base_url")
    @classmethod
    def validate_registry_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validated_url(value, https_only=True)

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value == "latest" or value[0] in "~^<>=*" or value.endswith((".x", ".*")):
            raise ValueError("package version must be exact")
        return value

    @model_validator(mode="after")
    def validate_image_identity(self) -> Self:
        if self.registry_type is PackageRegistry.OCI:
            if self.image_digest is None or "@" in self.identifier:
                raise ValueError("OCI package requires a separate image digest")
        elif self.image_digest is not None:
            raise ValueError("image digest is only valid for OCI packages")
        if self.registry_type is PackageRegistry.MCPB and self.file_sha256 is None:
            raise ValueError("MCPB package requires a file digest")
        return self


class CredentialReference(_ManifestModel):
    secret_name: str = Field(min_length=1, max_length=253)
    key: str = Field(min_length=1, max_length=253)


class Ownership(_ManifestModel):
    namespace: str = Field(min_length=1, max_length=63)
    tenant_id: str = Field(min_length=1, max_length=63)
    visibility: ManifestVisibility
    org_id: str | None = Field(default=None, min_length=1, max_length=128)
    team_id: str | None = Field(default=None, min_length=1, max_length=128)
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def tenant_matches_namespace(self) -> Self:
        if self.tenant_id != self.namespace:
            raise ValueError("tenant_id must equal namespace")
        return self


class RoutePolicy(_ManifestModel):
    gateway_path: str = Field(min_length=1, max_length=512)
    direct_access: bool = False


class SemanticMetadata(_ManifestModel):
    capabilities: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()


class ToolSummary(_ManifestModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=512)
    input_fingerprint: str = Field(pattern=_FINGERPRINT)
    output_fingerprint: str = Field(pattern=_FINGERPRINT)
    required_scopes: tuple[str, ...] = ()

    @classmethod
    def from_runtime(cls, manifest: ToolManifest) -> Self:
        return cls(
            name=manifest.normalized_name,
            description=manifest.metadata.description,
            input_fingerprint=manifest.input_fingerprint,
            output_fingerprint=manifest.output_fingerprint,
            required_scopes=manifest.metadata.required_scopes,
        )


class ServerAuthoringManifest(_ManifestModel):
    manifest_version: Literal["1.0"] = AUTHORING_MANIFEST_VERSION
    name: str = Field(min_length=3, max_length=200, pattern=_SERVER_NAME)
    version: str = Field(pattern=_VERSION)
    description: str = Field(min_length=1, max_length=100)
    title: str | None = Field(default=None, min_length=1, max_length=100)
    repository: Repository
    ownership: Ownership
    adapter: RuntimeAdapter
    protocol_versions: tuple[str, ...] = Field(min_length=1)
    lifecycle: ManifestLifecycle
    route_policy: RoutePolicy
    remote: RemoteEndpoint | None = None
    package: PackageIdentity | None = None
    credential_ref: CredentialReference | None = None
    semantic: SemanticMetadata = Field(default_factory=SemanticMetadata)
    egress_hosts: tuple[str, ...] = ()
    required_scopes: tuple[str, ...] = ()
    tools: tuple[ToolSummary, ...] = ()

    @model_validator(mode="after")
    def require_portable_delivery(self) -> Self:
        if self.remote is None and self.package is None:
            raise ValueError("remote or package delivery is required")
        return self


__all__ = [
    "CredentialReference",
    "ManifestLifecycle",
    "ManifestVisibility",
    "Ownership",
    "PackageIdentity",
    "PackageRegistry",
    "PackageTransport",
    "RemoteEndpoint",
    "Repository",
    "RoutePolicy",
    "RuntimeAdapter",
    "SemanticMetadata",
    "ServerAuthoringManifest",
    "ToolSummary",
]
