from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

from tesserix_mcp_manifest._annotations import is_reserved_annotation
from tesserix_mcp_manifest._discovery_text import validated_discovery_text
from tesserix_mcp_manifest._secret_fields import is_secret_key
from tesserix_mcp_manifest.constants import AUTHORING_MANIFEST_VERSION
from tesserix_mcp_manifest.validation import validated_url
from tesserix_mcp_runtime import ToolManifest

_SERVER_NAME = r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$"
_VERSION = r"^\S{1,255}$"
_FINGERPRINT = r"^[a-f0-9]{64}$"
_OCI_DIGEST = r"^sha256:[a-f0-9]{64}$"
_CAPABILITY = r"^cap/[a-z0-9]+(?:-[a-z0-9]+)*$"
_TOOL_NAME = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
_TOOL_INPUT_NAME = r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
_REGISTRY_ARN = (
    r"^arn:agentic:registry:[A-Za-z0-9._-]+:"
    r"(?:skills|tools|mcpservers|prompts|workflows|blueprints|agents|datasets|evalsuites)/"
    r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$"
)

type DiscoverySummary = Annotated[
    str, Field(min_length=3, max_length=200), AfterValidator(validated_discovery_text)
]
type DiscoveryPhrase = Annotated[
    str, Field(min_length=3, max_length=200), AfterValidator(validated_discovery_text)
]
type DiscoveryKeyword = Annotated[
    str, Field(min_length=2, max_length=64), AfterValidator(validated_discovery_text)
]
type ServerDiscoveryText = Annotated[
    str, Field(min_length=1, max_length=100), AfterValidator(validated_discovery_text)
]
type ToolDescription = Annotated[
    str, Field(min_length=1, max_length=512), AfterValidator(validated_discovery_text)
]
type ToolJsonType = Literal["array", "boolean", "integer", "null", "number", "object", "string"]
type CapabilityIdentifier = Annotated[str, Field(max_length=64, pattern=_CAPABILITY)]
type RegistryARN = Annotated[str, Field(max_length=512, pattern=_REGISTRY_ARN)]


class ManifestModel(BaseModel):
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


class DiscoveryRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PackageRegistry(StrEnum):
    NPM = "npm"
    PYPI = "pypi"
    OCI = "oci"
    NUGET = "nuget"
    CARGO = "cargo"
    MCPB = "mcpb"


class Repository(ManifestModel):
    url: str
    source: str = Field(min_length=1, max_length=64)
    id: str | None = Field(default=None, min_length=1, max_length=256)
    subfolder: str | None = Field(default=None, min_length=1, max_length=512)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return validated_url(value, https_only=True)


class RemoteEndpoint(ManifestModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return validated_url(value, https_only=True)


class PackageTransport(ManifestModel):
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


class PackageIdentity(ManifestModel):
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


class CredentialReference(ManifestModel):
    secret_name: str = Field(min_length=1, max_length=253)
    key: str = Field(min_length=1, max_length=253)


class Ownership(ManifestModel):
    namespace: str = Field(min_length=1, max_length=63)
    tenant_id: str = Field(min_length=1, max_length=63)
    visibility: ManifestVisibility
    org_id: str | None = Field(default=None, min_length=1, max_length=128)
    team_id: str | None = Field(default=None, min_length=1, max_length=128)
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)

    @field_validator("annotations")
    @classmethod
    def reject_reserved_annotations(cls, value: dict[str, str]) -> dict[str, str]:
        if any(is_reserved_annotation(key) for key in value):
            raise ValueError("registry-managed annotations must use typed authoring fields")
        return value

    @model_validator(mode="after")
    def tenant_matches_namespace(self) -> Self:
        if self.tenant_id != self.namespace:
            raise ValueError("tenant_id must equal namespace")
        return self


class RoutePolicy(ManifestModel):
    gateway_path: str = Field(min_length=1, max_length=512)
    direct_access: bool = False


class SemanticMetadata(ManifestModel):
    summary: DiscoverySummary | None = None
    when_to_use: tuple[DiscoveryPhrase, ...] = Field(default=(), max_length=8)
    not_for: tuple[DiscoveryPhrase, ...] = Field(default=(), max_length=8)
    examples: tuple[DiscoveryPhrase, ...] = Field(default=(), max_length=8)
    capabilities: tuple[CapabilityIdentifier, ...] = Field(default=(), max_length=32)
    requires: tuple[RegistryARN, ...] = Field(default=(), max_length=32)
    risk: DiscoveryRisk | None = None
    domains: tuple[DiscoveryKeyword, ...] = Field(default=(), max_length=16)
    keywords: tuple[DiscoveryKeyword, ...] = Field(default=(), max_length=32)


class ToolInputField(ManifestModel):
    name: str = Field(min_length=1, max_length=128, pattern=_TOOL_INPUT_NAME)
    json_type: ToolJsonType
    description: DiscoveryPhrase | None = None
    required: bool = False


def _tool_json_type(value: object) -> ToolJsonType | None:
    if value == "array":
        return "array"
    if value == "boolean":
        return "boolean"
    if value == "integer":
        return "integer"
    if value == "null":
        return "null"
    if value == "number":
        return "number"
    if value == "object":
        return "object"
    if value == "string":
        return "string"
    return None


def _runtime_tool_inputs(manifest: ToolManifest) -> tuple[ToolInputField, ...]:
    schema = manifest.input_schema
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return ()

    required_value = schema.get("required")
    required_names: frozenset[str] = (
        frozenset(value for value in required_value if isinstance(value, str))
        if isinstance(required_value, list)
        else frozenset[str]()
    )
    inputs: list[ToolInputField] = []
    for name in sorted(properties):
        if is_secret_key(name):
            continue
        definition = properties[name]
        if not isinstance(definition, dict):
            continue
        json_type = _tool_json_type(definition.get("type"))
        if json_type is None:
            continue
        description = definition.get("description")
        inputs.append(
            ToolInputField(
                name=name,
                json_type=json_type,
                description=description if isinstance(description, str) else None,
                required=name in required_names,
            )
        )
    if len(inputs) > 50:
        raise ValueError("tool discovery input projection exceeds 50 safe properties")
    return tuple(inputs)


def _runtime_semantic(manifest: ToolManifest) -> SemanticMetadata:
    discovery = manifest.metadata.discovery
    if discovery is None:
        return SemanticMetadata()
    return SemanticMetadata(
        summary=discovery.summary,
        when_to_use=(discovery.when_to_use,),
        examples=discovery.examples,
        capabilities=discovery.capabilities,
    )


def _runtime_lifecycle(manifest: ToolManifest) -> ManifestLifecycle:
    discovery = manifest.metadata.discovery
    if discovery is not None and discovery.lifecycle == "deprecated":
        return ManifestLifecycle.DEPRECATED
    return ManifestLifecycle.ACTIVE


class ToolSummary(ManifestModel):
    name: str = Field(min_length=1, max_length=128, pattern=_TOOL_NAME)
    description: ToolDescription
    input_fingerprint: str = Field(pattern=_FINGERPRINT)
    output_fingerprint: str = Field(pattern=_FINGERPRINT)
    required_scopes: tuple[str, ...] = ()
    semantic: SemanticMetadata = Field(default_factory=SemanticMetadata)
    lifecycle: ManifestLifecycle = ManifestLifecycle.ACTIVE
    inputs: tuple[ToolInputField, ...] = Field(default=(), max_length=50)

    @classmethod
    def from_runtime(
        cls,
        manifest: ToolManifest,
        *,
        semantic: SemanticMetadata | None = None,
        lifecycle: ManifestLifecycle | None = None,
    ) -> Self:
        return cls(
            name=manifest.normalized_name,
            description=manifest.metadata.description,
            input_fingerprint=manifest.input_fingerprint,
            output_fingerprint=manifest.output_fingerprint,
            required_scopes=manifest.metadata.required_scopes,
            semantic=semantic if semantic is not None else _runtime_semantic(manifest),
            lifecycle=lifecycle if lifecycle is not None else _runtime_lifecycle(manifest),
            inputs=_runtime_tool_inputs(manifest),
        )


class ServerAuthoringManifest(ManifestModel):
    manifest_version: Literal["1.0"] = AUTHORING_MANIFEST_VERSION
    name: str = Field(min_length=3, max_length=200, pattern=_SERVER_NAME)
    version: str = Field(pattern=_VERSION)
    description: ServerDiscoveryText
    title: ServerDiscoveryText | None = None
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
    "DiscoveryRisk",
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
    "ToolInputField",
    "ToolSummary",
]
