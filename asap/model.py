from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")

@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    title: str
    severity: str
    cwe: str
    masvs: str
    description: str
    remediation: str
    references: tuple[str, ...]

@dataclass
class Evidence:
    path: str
    line: int
    end_line: int
    snippet: str
    role: str = "observation"

@dataclass
class Finding:
    rule_id: str
    category: str
    title: str
    severity: str
    confidence: str
    kind: str
    message: str
    evidence: list[Evidence]
    remediation: str
    cwe: str
    masvs: str
    references: list[str]
    fingerprint: str = ""
    baseline_state: str = "new"
    suppressed: bool = False
    suppression_reason: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class Source:
    path: str
    text: str
    language: str
    sha256: str

@dataclass
class Manifest:
    path: str
    package: str
    min_sdk: int | None
    target_sdk: int | None
    application: dict[str, str]
    permissions: list[dict[str, str]]
    declared_permissions: dict[str, str]
    components: list[dict[str, Any]]
    binary: bool = False

@dataclass
class ScanResult:
    schema_version: str
    tool: dict[str, Any]
    scan: dict[str, Any]
    inventory: dict[str, Any]
    coverage: dict[str, Any]
    findings: list[Finding]
    diagnostics: list[dict[str, str]]
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
