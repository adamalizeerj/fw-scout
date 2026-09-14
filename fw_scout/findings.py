"""Finding data model shared across all fw-scout analysers.

A Finding is the single unit of output. Every analyser emits Findings, and
every reporter consumes them. Keeping one flat, well-typed structure means the
JSON and Markdown reporters never have to know which analyser produced a result.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Severity levels, ordered. `str` mixin makes them JSON-serialisable as-is."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order.index(self)


@dataclass
class Finding:
    """One observation about a firmware image.

    Fields mirror what the manual methodology recorded by hand in FINDINGS.md:
    what, where (path + optional offset), why it matters (severity + a weakness
    id), and enough evidence that a reader can verify it without re-running the
    scan.
    """

    id: str  # analyser-assigned short id, e.g. "SECRET-001"
    title: str
    severity: Severity
    analyser: str  # which analyser produced this (entropy, secrets, ...)
    path: str = ""  # file path or image-relative location
    offset: int | None = None  # byte offset when relevant (carved regions)
    evidence: str = ""  # short excerpt / matched value (redacted where needed)
    detail: str = ""  # human explanation of the finding and its bounds
    weakness: str = ""  # CWE id or category, when applicable
    confidence: str = "medium"  # low | medium | high
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


def redact_secret(value: str, keep: int = 4) -> str:
    """Redact a secret for safe inclusion in a report.

    We never want the full plaintext of a discovered credential sitting in a
    committed report. Show a short prefix and a hash so two findings referring
    to the same secret are correlatable without exposing it.
    """
    value = value.strip()
    if not value:
        return "(empty)"
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
    if len(value) <= keep:
        return f"…redacted (sha256:{digest})"
    return f"{value[:keep]}… ({len(value)} chars, sha256:{digest})"


def location(path: str | Path, offset: int | None = None) -> str:
    p = str(path)
    return f"{p}@{offset:#x}" if offset is not None else p
