from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[self.value]


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    severity: Severity
    entry_point: str               # human-readable, e.g. "CI workflow (ci.yml)"
    problem: str                   # what's wrong, specifically
    cloud_trust: str                # what the trust relationship allows
    result: str                     # the consequence, in plain English
    remediation: list[str] = field(default_factory=list)
    path: list[str] = field(default_factory=list)   # graph node ids, source ordered
    evidence: dict = field(default_factory=dict)     # raw facts backing the finding, for --json / audit

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "entry_point": self.entry_point,
            "problem": self.problem,
            "cloud_trust": self.cloud_trust,
            "result": self.result,
            "remediation": self.remediation,
            "path": self.path,
            "evidence": self.evidence,
        }
