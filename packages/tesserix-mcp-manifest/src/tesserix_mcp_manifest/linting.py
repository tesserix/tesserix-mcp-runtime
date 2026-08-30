from __future__ import annotations

import re
from enum import StrEnum
from typing import Final

from pydantic import Field

from tesserix_mcp_manifest.models import (
    DiscoveryRisk,
    ManifestLifecycle,
    ManifestModel,
    SemanticMetadata,
    ServerAuthoringManifest,
)


class SemanticLintCode(StrEnum):
    DUPLICATE_INTENT = "duplicate-intent"
    DUPLICATES_DESCRIPTION = "duplicates-description"
    INSTRUCTION_LIKE = "instruction-like"
    MARKETING_LANGUAGE = "marketing-language"
    MISSING_SUMMARY = "missing-summary"
    MISSING_WHEN_TO_USE = "missing-when-to-use"
    TOKEN_BUDGET_EXCEEDED = "token-budget-exceeded"
    TOOL_CAPABILITY_NOT_DECLARED = "tool-capability-not-declared"
    TOOL_LIFECYCLE_EXCEEDS_SERVER = "tool-lifecycle-exceeds-server"
    TOOL_REQUIREMENT_NOT_DECLARED = "tool-requirement-not-declared"
    TOOL_RISK_EXCEEDS_SERVER = "tool-risk-exceeds-server"
    VAGUE_SUMMARY = "vague-summary"
    VAGUE_WHEN_TO_USE = "vague-when-to-use"


class SemanticLintFinding(ManifestModel):
    code: SemanticLintCode
    path: str = Field(min_length=1, max_length=512)


_WORDS = re.compile(r"[a-z0-9]+")
_VAGUE_WORDS = frozenset(
    {
        "action",
        "actions",
        "anything",
        "data",
        "do",
        "general",
        "generic",
        "handle",
        "help",
        "it",
        "manage",
        "need",
        "needed",
        "process",
        "purpose",
        "request",
        "requests",
        "stuff",
        "something",
        "task",
        "tasks",
        "thing",
        "things",
        "tool",
        "tools",
        "use",
        "user",
        "users",
        "various",
        "when",
    }
)
_IGNORED_WORDS = frozenset({"a", "an", "and", "for", "of", "the", "this", "to", "with"})
_MARKETING_LANGUAGE = re.compile(
    r"(?i)\b(?:amazing|best-in-class|cutting-edge|effortless(?:ly)?|game-changing|"
    r"industry-leading|innovative|powerful|revolutionary|seamless(?:ly)?|"
    r"state-of-the-art|superior|ultimate|unmatched|unparalleled|world-class)\b"
)
_INSTRUCTION_LIKE = re.compile(
    r"(?i)(?:\b(?:ignore|disregard|override)\b.{0,40}\b(?:instruction|message|prompt)s?\b|"
    r"\b(?:always|never|must|do\s+not)\s+(?:call|choose|select|use)\b|"
    r"\b(?:assistant|model|you)\s+(?:must|should)\b|"
    r"\b(?:developer|system)\s+(?:message|prompt)\b|"
    r"\bfollow\s+(?:the|these)\s+instructions\b|"
    r"\brespond\s+(?:only\s+)?with\b)"
)
SEMANTIC_MANIFEST_TOKEN_BUDGET: Final = 1_500
_RISK_ORDER: Final = (
    DiscoveryRisk.LOW,
    DiscoveryRisk.MEDIUM,
    DiscoveryRisk.HIGH,
    DiscoveryRisk.CRITICAL,
)


def _is_vague(value: str) -> bool:
    words = set(_WORDS.findall(value.lower())) - _IGNORED_WORDS
    return not words or words <= _VAGUE_WORDS


def _normalized_words(value: str) -> tuple[str, ...]:
    return tuple(_WORDS.findall(value.lower()))


def _semantic_text_fields(
    semantic: SemanticMetadata,
    *,
    path: str,
) -> tuple[tuple[str, str], ...]:
    fields: list[tuple[str, str]] = []
    if semantic.summary is not None:
        fields.append((f"{path}.summary", semantic.summary))
    for field_name, values in (
        ("when_to_use", semantic.when_to_use),
        ("not_for", semantic.not_for),
        ("examples", semantic.examples),
    ):
        fields.extend(
            (f"{path}.{field_name}[{index}]", value) for index, value in enumerate(values)
        )
    return tuple(fields)


def _semantic_values(semantic: SemanticMetadata) -> tuple[str, ...]:
    values = [value for _, value in _semantic_text_fields(semantic, path="semantic")]
    values.extend(semantic.capabilities)
    values.extend(semantic.requires)
    values.extend(semantic.domains)
    values.extend(semantic.keywords)
    return tuple(values)


def _estimated_tokens(values: tuple[str, ...]) -> int:
    return sum((len(value.encode("utf-8")) + 3) // 4 for value in values)


def _style_findings(value: str, *, path: str) -> list[SemanticLintFinding]:
    findings: list[SemanticLintFinding] = []
    if _MARKETING_LANGUAGE.search(value) is not None:
        findings.append(
            SemanticLintFinding(
                code=SemanticLintCode.MARKETING_LANGUAGE,
                path=path,
            )
        )
    if _INSTRUCTION_LIKE.search(value) is not None:
        findings.append(
            SemanticLintFinding(
                code=SemanticLintCode.INSTRUCTION_LIKE,
                path=path,
            )
        )
    return findings


def _intent_findings(
    semantic: SemanticMetadata,
    *,
    description: str,
    path: str,
) -> list[SemanticLintFinding]:
    findings: list[SemanticLintFinding] = []
    if semantic.summary is None:
        findings.append(
            SemanticLintFinding(
                code=SemanticLintCode.MISSING_SUMMARY,
                path=f"{path}.summary",
            )
        )
    elif _is_vague(semantic.summary):
        findings.append(
            SemanticLintFinding(
                code=SemanticLintCode.VAGUE_SUMMARY,
                path=f"{path}.summary",
            )
        )
    if semantic.summary is not None and _normalized_words(semantic.summary) == _normalized_words(
        description
    ):
        findings.append(
            SemanticLintFinding(
                code=SemanticLintCode.DUPLICATES_DESCRIPTION,
                path=f"{path}.summary",
            )
        )
    if not semantic.when_to_use:
        findings.append(
            SemanticLintFinding(
                code=SemanticLintCode.MISSING_WHEN_TO_USE,
                path=f"{path}.when_to_use",
            )
        )
    else:
        seen: set[tuple[str, ...]] = set()
        if semantic.summary is not None:
            seen.add(_normalized_words(semantic.summary))
        for index, trigger in enumerate(semantic.when_to_use):
            if _is_vague(trigger):
                findings.append(
                    SemanticLintFinding(
                        code=SemanticLintCode.VAGUE_WHEN_TO_USE,
                        path=f"{path}.when_to_use[{index}]",
                    )
                )
            normalized = _normalized_words(trigger)
            if normalized in seen:
                findings.append(
                    SemanticLintFinding(
                        code=SemanticLintCode.DUPLICATE_INTENT,
                        path=f"{path}.when_to_use[{index}]",
                    )
                )
            seen.add(normalized)
    for field_path, value in _semantic_text_fields(semantic, path=path):
        findings.extend(_style_findings(value, path=field_path))
    return findings


def lint_semantic_manifest(
    manifest: ServerAuthoringManifest,
) -> tuple[SemanticLintFinding, ...]:
    findings: list[SemanticLintFinding] = []
    if manifest.title is not None:
        findings.extend(_style_findings(manifest.title, path="title"))
    findings.extend(_style_findings(manifest.description, path="description"))
    findings.extend(
        _intent_findings(
            manifest.semantic,
            description=manifest.description,
            path="semantic",
        )
    )
    for index, tool in enumerate(manifest.tools):
        findings.extend(_style_findings(tool.description, path=f"tools[{index}].description"))
        findings.extend(
            _intent_findings(
                tool.semantic,
                description=tool.description,
                path=f"tools[{index}].semantic",
            )
        )
        for capability_index, capability in enumerate(tool.semantic.capabilities):
            if capability not in manifest.semantic.capabilities:
                findings.append(
                    SemanticLintFinding(
                        code=SemanticLintCode.TOOL_CAPABILITY_NOT_DECLARED,
                        path=f"tools[{index}].semantic.capabilities[{capability_index}]",
                    )
                )
        for requirement_index, requirement in enumerate(tool.semantic.requires):
            if requirement not in manifest.semantic.requires:
                findings.append(
                    SemanticLintFinding(
                        code=SemanticLintCode.TOOL_REQUIREMENT_NOT_DECLARED,
                        path=f"tools[{index}].semantic.requires[{requirement_index}]",
                    )
                )
        if tool.semantic.risk is not None and (
            manifest.semantic.risk is None
            or _RISK_ORDER.index(tool.semantic.risk) > _RISK_ORDER.index(manifest.semantic.risk)
        ):
            findings.append(
                SemanticLintFinding(
                    code=SemanticLintCode.TOOL_RISK_EXCEEDS_SERVER,
                    path=f"tools[{index}].semantic.risk",
                )
            )
        if (
            manifest.lifecycle is ManifestLifecycle.DEPRECATED
            and tool.lifecycle is ManifestLifecycle.ACTIVE
        ):
            findings.append(
                SemanticLintFinding(
                    code=SemanticLintCode.TOOL_LIFECYCLE_EXCEEDS_SERVER,
                    path=f"tools[{index}].lifecycle",
                )
            )
    budget_values = [manifest.description, *_semantic_values(manifest.semantic)]
    if manifest.title is not None:
        budget_values.append(manifest.title)
    for tool in manifest.tools:
        budget_values.append(tool.description)
        budget_values.extend(_semantic_values(tool.semantic))
        budget_values.extend(
            input_field.description
            for input_field in tool.inputs
            if input_field.description is not None
        )
    if _estimated_tokens(tuple(budget_values)) > SEMANTIC_MANIFEST_TOKEN_BUDGET:
        findings.append(
            SemanticLintFinding(
                code=SemanticLintCode.TOKEN_BUDGET_EXCEEDED,
                path="$",
            )
        )
    return tuple(findings)


__all__ = [
    "SEMANTIC_MANIFEST_TOKEN_BUDGET",
    "SemanticLintCode",
    "SemanticLintFinding",
    "lint_semantic_manifest",
]
