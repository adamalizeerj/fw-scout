"""Secret and key material detection.

This analyser encodes two lessons learned the hard way during manual analysis:

  1. PEM markers are not always newline-delimited. A firmware image contained
     `-----BEGIN PRIVATE KEY-----` spliced into a base64 stream with no
     surrounding newlines, which a line-anchored grep missed entirely. We scan
     with a byte-oriented pattern that does not assume line structure.

  2. A `BEGIN PRIVATE KEY` string match is NOT a key finding. The same firmware
     shipped a structurally corrupted PEM whose bytes did not parse as a key
     (base64 broken by embedded markers, ASN.1 garbage). Reporting it as a
     hardcoded key would have been a false positive. fw-scout therefore attempts
     a structural parse (strip markers -> base64 -> DER -> minimal ASN.1 sanity)
     and only raises HIGH severity when the material actually parses.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path

from .findings import Finding, Severity, redact_secret, location

# --- credential / key regexes -------------------------------------------------
# Byte patterns (not line-anchored) so newline-free PEM markers are still caught.

PEM_MARKER = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
SSH_PUBKEY = re.compile(rb"ssh-(?:rsa|ed25519|dss)\s+AAAA[0-9A-Za-z+/=]{20,}")
AWS_ACCESS_KEY = re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
AWS_SECRET_KEY = re.compile(rb"(?i)aws_secret_access_key\s*[=:]\s*[\"']?([0-9A-Za-z/+]{40})")
GENERIC_API_KEY = re.compile(
    rb"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[=:]\s*[\"']?([^\s\"'#;]{6,120})"
)
PRIVATE_KEY_BLOCK = re.compile(
    rb"-----BEGIN[ A-Z]*PRIVATE KEY-----(.*?)-----END[ A-Z]*PRIVATE KEY-----",
    re.DOTALL,
)

# Values that look like credentials but are stock example/placeholder config.
# These caused a near-miss false positive (commented lighttpd example lines).
KNOWN_PLACEHOLDERS = {
    b"user@host", b"mysql://user@host/db", b"changeme", b"password",
    b"example", b"your_password_here", b"xxxxxxxx", b"42",
}


def _looks_like_real_private_key(block_bytes: bytes) -> tuple[bool, str]:
    """Attempt a structural parse of a candidate PEM private-key block.

    Returns (is_real, reason). We strip all ----- markers, base64-decode the
    remainder, and check the result begins like a DER SEQUENCE (0x30) of
    plausible length. This is deliberately lightweight (no crypto deps) but is
    enough to separate a real key from marker-scrambled garbage.
    """
    # Remove any embedded PEM marker lines / fragments.
    stripped = re.sub(rb"-----[A-Z ]*-----", b"", block_bytes)
    stripped = re.sub(rb"\s+", b"", stripped)
    if len(stripped) < 64:
        return False, "too short to be a key"
    try:
        der = base64.b64decode(stripped, validate=False)
    except Exception:
        return False, "base64 decode failed"
    if len(der) < 64:
        return False, f"decoded only {len(der)} bytes"
    # DER private keys begin with a SEQUENCE tag (0x30).
    if der[0] != 0x30:
        return False, "not a DER SEQUENCE (structural mismatch)"
    return True, f"parses as DER SEQUENCE, {len(der)} bytes"


def _is_placeholder(value: bytes) -> bool:
    v = value.strip().strip(b"\"'").lower()
    return v in KNOWN_PLACEHOLDERS or v.startswith(b"your_")


def scan_bytes(data: bytes, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    loc = str(path)

    # --- private key blocks: structural validation before claiming a finding ---
    for m in PRIVATE_KEY_BLOCK.finditer(data):
        block = m.group(0)
        is_real, reason = _looks_like_real_private_key(m.group(1))
        offset = m.start()
        if is_real:
            findings.append(
                Finding(
                    id="SECRET-PRIVKEY",
                    title="Hardcoded private key in firmware",
                    severity=Severity.HIGH,
                    analyser="secrets",
                    path=location(loc, offset),
                    offset=offset,
                    evidence=redact_secret(block[:60].decode("latin-1")),
                    detail=(
                        "A PEM private-key block is present and parses "
                        f"structurally ({reason}). If this key is used for TLS "
                        "or SSH and is shared across units, it is directly "
                        "exploitable. Confirm what service uses it."
                    ),
                    weakness="CWE-321",
                    confidence="high",
                    tags=["secret", "private-key"],
                )
            )
        else:
            findings.append(
                Finding(
                    id="SECRET-PRIVKEY-MALFORMED",
                    title="PRIVATE KEY marker present but does not parse as a key",
                    severity=Severity.INFO,
                    analyser="secrets",
                    path=location(loc, offset),
                    offset=offset,
                    evidence=f"structural check failed: {reason}",
                    detail=(
                        "A BEGIN PRIVATE KEY marker was found but the bytes do "
                        "not decode to a valid key (likely a corrupted/placeholder "
                        "PEM). Reported as informational, NOT a key exposure. "
                        "This is the false-positive that naive string matching "
                        "would misreport as HIGH."
                    ),
                    confidence="high",
                    tags=["secret", "false-positive-guard"],
                )
            )

    # --- lone PEM markers not inside a full block (newline-free splice case) ---
    for m in PEM_MARKER.finditer(data):
        # Skip if this marker is already covered by a full block above.
        if PRIVATE_KEY_BLOCK.search(data[max(0, m.start() - 5): m.end() + 4000]):
            continue
        findings.append(
            Finding(
                id="SECRET-PEM-MARKER",
                title="Isolated PEM private-key marker (no complete block)",
                severity=Severity.LOW,
                analyser="secrets",
                path=location(loc, m.start()),
                offset=m.start(),
                evidence=m.group(0).decode("latin-1"),
                detail=(
                    "A PEM private-key BEGIN marker was found without a matching "
                    "END/valid block, possibly spliced into surrounding data. "
                    "Worth manual inspection; may indicate obfuscated key material."
                ),
                confidence="medium",
                tags=["secret", "pem-marker"],
            )
        )

    # --- SSH public keys in authorized_keys context -----------------------------
    if path.name == "authorized_keys" or b"authorized_keys" in loc.encode():
        for m in SSH_PUBKEY.finditer(data):
            findings.append(
                Finding(
                    id="SECRET-SSH-AUTHKEY",
                    title="Hardcoded SSH authorized_keys entry",
                    severity=Severity.MEDIUM,
                    analyser="secrets",
                    path=location(loc, m.start()),
                    offset=m.start(),
                    evidence=redact_secret(m.group(0).decode("latin-1")),
                    detail=(
                        "A fixed SSH public key ships in authorized_keys, granting "
                        "access to any holder of the matching private key. Security "
                        "depends entirely on the private key remaining secret; the "
                        "same trust anchor across all units is a weakness."
                    ),
                    weakness="CWE-798",
                    confidence="high",
                    tags=["secret", "ssh-authorized-keys"],
                )
            )

    # --- AWS keys ---------------------------------------------------------------
    for m in AWS_ACCESS_KEY.finditer(data):
        findings.append(
            Finding(
                id="SECRET-AWS-AKID",
                title="AWS access key id",
                severity=Severity.HIGH,
                analyser="secrets",
                path=location(loc, m.start()),
                offset=m.start(),
                evidence=redact_secret(m.group(0).decode("latin-1")),
                detail="An AWS access key id pattern was found in firmware.",
                weakness="CWE-798",
                confidence="high",
                tags=["secret", "aws"],
            )
        )

    # --- generic key=value credentials (with placeholder guard) -----------------
    for pat, sid, title in (
        (AWS_SECRET_KEY, "SECRET-AWS-SECRET", "AWS secret access key"),
        (GENERIC_API_KEY, "SECRET-GENERIC", "Generic credential assignment"),
    ):
        for m in pat.finditer(data):
            value = m.group(1) if m.groups() else m.group(0)
            if _is_placeholder(value):
                continue
            findings.append(
                Finding(
                    id=sid,
                    title=title,
                    severity=Severity.MEDIUM,
                    analyser="secrets",
                    path=location(loc, m.start()),
                    offset=m.start(),
                    evidence=redact_secret(value.decode("latin-1")),
                    detail=(
                        "A credential-like assignment was found. Placeholder/"
                        "example values are filtered; this one is not a known "
                        "placeholder. Verify it is a real secret."
                    ),
                    weakness="CWE-798",
                    confidence="low",
                    tags=["secret", "credential"],
                )
            )

    return findings


def scan_file(path: Path, max_bytes: int = 5_000_000) -> list[Finding]:
    try:
        with path.open("rb") as fh:
            data = fh.read(max_bytes)
    except OSError:
        return []
    return scan_bytes(data, path)
