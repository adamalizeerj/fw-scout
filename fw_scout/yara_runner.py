"""YARA scanning over extracted files.

Loads the bundled ruleset from fw_scout/rules/ and scans files. yara-python is
an optional dependency: if it is not installed, this analyser degrades to a
no-op and records that YARA scanning was skipped, rather than failing the run.
"""

from __future__ import annotations

from pathlib import Path

from .findings import Finding, Severity, location

try:
    import yara  # type: ignore

    _YARA = True
except Exception:  # pragma: no cover - depends on env
    _YARA = False

RULES_DIR = Path(__file__).parent / "rules"

# Map a YARA rule's declared severity meta to our Severity enum.
_SEV = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def available() -> bool:
    return _YARA


def _compile_rules() -> "yara.Rules | None":
    if not _YARA:
        return None
    rule_files = sorted(RULES_DIR.glob("*.yar")) + sorted(RULES_DIR.glob("*.yara"))
    if not rule_files:
        return None
    sources = {f.stem: str(f) for f in rule_files}
    try:
        return yara.compile(filepaths=sources)
    except yara.Error:
        return None


def scan_files(files: list[Path], max_bytes: int = 5_000_000) -> list[Finding]:
    findings: list[Finding] = []
    if not _YARA:
        return findings
    rules = _compile_rules()
    if rules is None:
        return findings

    for path in files:
        try:
            with path.open("rb") as fh:
                data = fh.read(max_bytes)
        except OSError:
            continue
        try:
            matches = rules.match(data=data)
        except Exception:
            continue
        for m in matches:
            meta = m.meta or {}
            sev = _SEV.get(str(meta.get("severity", "info")).lower(), Severity.INFO)
            findings.append(
                Finding(
                    id=f"YARA-{m.rule.upper()}",
                    title=meta.get("description", f"YARA match: {m.rule}"),
                    severity=sev,
                    analyser="yara",
                    path=location(path),
                    evidence=f"rule={m.rule} tags={','.join(m.tags)}",
                    detail=str(meta.get("detail", "")),
                    weakness=str(meta.get("weakness", "")),
                    confidence="medium",
                    tags=["yara", *m.tags],
                )
            )
    return findings
