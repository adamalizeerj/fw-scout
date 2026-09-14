"""Account and credential analysis of /etc/passwd and /etc/shadow.

Codifies the manual backdoor-account hunt:
  - secondary UID-0 accounts (a second root == backdoor structure)
  - service accounts with an interactive login shell
  - set password hashes, classified by crypt scheme (MD5crypt is broken)
  - empty password fields (flagged, but with the caveat that firmware often
    populates them at first boot -- so this is a lead, not a proven vuln)
  - duplicate account entries (a config anomaly worth noting)
"""

from __future__ import annotations

from pathlib import Path

from .findings import Finding, Severity, location

INTERACTIVE_SHELLS = {"/bin/sh", "/bin/ash", "/bin/bash", "/bin/dash", "/bin/zsh"}

# crypt id -> (scheme, is_weak)
CRYPT_SCHEMES = {
    "1": ("MD5crypt", True),
    "2a": ("bcrypt", False),
    "2y": ("bcrypt", False),
    "5": ("SHA-256crypt", False),
    "6": ("SHA-512crypt", False),
    "y": ("yescrypt", False),
}


def _parse_passwd(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 7:
            rows.append(parts)
    return rows


def _parse_shadow(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            rows.append(parts)
    return rows


def _classify_hash(field: str) -> tuple[str, bool] | None:
    """Return (scheme, is_weak) for a shadow hash field, or None if no real hash."""
    if field in ("", "*", "!", "!!", "x"):
        return None
    if field.startswith("$"):
        cid = field.split("$")[1]
        return CRYPT_SCHEMES.get(cid, (f"crypt-${cid}$", False))
    # A non-empty, non-marker field that isn't $-prefixed: legacy DES or unknown.
    return ("legacy/DES-or-unknown", True)


def scan_rootfs(rootfs: Path) -> list[Finding]:
    findings: list[Finding] = []
    passwd_path = rootfs / "etc" / "passwd"
    shadow_path = rootfs / "etc" / "shadow"

    if not passwd_path.exists():
        return findings

    passwd = _parse_passwd(passwd_path.read_text(errors="replace"))

    # --- UID-0 accounts ---------------------------------------------------------
    uid0 = [r for r in passwd if r[2] == "0"]
    if len(uid0) > 1:
        names = ", ".join(r[0] for r in uid0)
        findings.append(
            Finding(
                id="ACCT-MULTI-UID0",
                title="Multiple UID-0 (superuser) accounts",
                severity=Severity.HIGH,
                analyser="accounts",
                path=location(passwd_path),
                evidence=f"UID-0 accounts: {names}",
                detail=(
                    "More than one account has UID 0. A second superuser account "
                    "is a classic backdoor structure. Confirm whether the extra "
                    "account is an intended admin login (some vendors ship 'admin' "
                    "as the real admin, with root shell disabled)."
                ),
                weakness="CWE-1188",
                confidence="high",
                tags=["accounts", "uid0"],
            )
        )

    # --- service accounts with interactive shells -------------------------------
    for r in passwd:
        name, _, uid, _, _, _, shell = r[0], r[1], r[2], r[3], r[4], r[5], r[6]
        if shell in INTERACTIVE_SHELLS and name not in ("root", "admin"):
            # heuristic: system/service accounts (low uid) shouldn't get a shell
            try:
                uid_n = int(uid)
            except ValueError:
                uid_n = -1
            if 0 < uid_n < 1000:
                findings.append(
                    Finding(
                        id="ACCT-SVC-SHELL",
                        title=f"Service account '{name}' has an interactive shell",
                        severity=Severity.LOW,
                        analyser="accounts",
                        path=location(passwd_path),
                        evidence=f"{name}:uid={uid}:shell={shell}",
                        detail=(
                            "A system/service account is configured with an "
                            "interactive login shell instead of nologin/false."
                        ),
                        weakness="CWE-250",
                        confidence="medium",
                        tags=["accounts", "shell"],
                    )
                )

    # --- shadow hash analysis ---------------------------------------------------
    if shadow_path.exists():
        shadow = _parse_shadow(shadow_path.read_text(errors="replace"))
        seen: dict[str, int] = {}
        for r in shadow:
            user = r[0]
            hashfield = r[1] if len(r) > 1 else ""
            seen[user] = seen.get(user, 0) + 1

            if hashfield == "":
                findings.append(
                    Finding(
                        id="ACCT-EMPTY-PW",
                        title=f"Empty password field for '{user}'",
                        severity=Severity.MEDIUM,
                        analyser="accounts",
                        path=location(shadow_path),
                        evidence=f"{user}::",
                        detail=(
                            "The shadow password field is empty. This CAN mean "
                            "passwordless login, but firmware images frequently "
                            "populate the field from NVRAM/config at first boot, "
                            "so an empty field in the image is not proof of a "
                            "passwordless account. Confirm the runtime behaviour "
                            "(PAM nullok, dropbear config, first-boot password set)."
                        ),
                        weakness="CWE-258",
                        confidence="low",
                        tags=["accounts", "empty-password"],
                    )
                )
                continue

            classified = _classify_hash(hashfield)
            if classified is None:
                continue
            scheme, is_weak = classified
            sev = Severity.HIGH if is_weak else Severity.MEDIUM
            findings.append(
                Finding(
                    id="ACCT-SET-HASH",
                    title=f"Set password hash for '{user}' ({scheme})",
                    severity=sev,
                    analyser="accounts",
                    path=location(shadow_path),
                    evidence=f"{user}: {scheme} hash present",
                    detail=(
                        f"Account '{user}' ships with a set password hash using "
                        f"{scheme}. A hardcoded credential in shipped firmware is a "
                        "vulnerability regardless of whether the plaintext is "
                        + ("recoverable; note this scheme is cryptographically weak."
                           if is_weak else "recoverable.")
                    ),
                    weakness="CWE-798",
                    confidence="high",
                    tags=["accounts", "hardcoded-credential"],
                )
            )

        for user, count in seen.items():
            if count > 1:
                findings.append(
                    Finding(
                        id="ACCT-DUP",
                        title=f"Duplicate shadow entry for '{user}'",
                        severity=Severity.INFO,
                        analyser="accounts",
                        path=location(shadow_path),
                        evidence=f"{user} appears {count} times",
                        detail="Duplicate account entry -- a configuration anomaly.",
                        confidence="high",
                        tags=["accounts", "anomaly"],
                    )
                )

    return findings
