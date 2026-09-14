"""Tests for fw-scout analysers.

These lock in the two most important behaviours learned during manual research:
  - encryption-like data is distinguished from compressed data by serial
    correlation, not entropy alone
  - a PEM marker only becomes a HIGH key finding when the bytes structurally
    parse as a key (guards the false positive that would discredit a report)
"""

from __future__ import annotations

import os
import zlib
from pathlib import Path

import pytest

from fw_scout import accounts, entropy, secrets


def test_random_is_encryption_like():
    cls, st = entropy.classify(os.urandom(200_000))
    assert cls == "encryption-like"
    assert st.entropy >= 7.95
    assert abs(st.serial_correlation) < 0.05


def test_compressed_is_not_encryption_like():
    comp = zlib.compress(b"A" * 100_000 + os.urandom(50_000))
    cls, _ = entropy.classify(comp)
    assert cls == "compressed"


def test_text_is_low_entropy():
    cls, _ = entropy.classify(b"the quick brown fox " * 5000)
    assert cls == "low-entropy"


def test_media_extension_is_expected():
    cls, _ = entropy.classify(os.urandom(50_000), hint_ext=".png")
    assert cls == "expected-media"


def test_malformed_pem_is_not_a_key(tmp_path: Path):
    malformed = (
        b"KoVINPiXv4-----BEGIN PRIVATE KEY-----"
        b"garbage!!not-valid-base64-----END PRIVATE KEY-----"
    )
    findings = secrets.scan_bytes(malformed, tmp_path / "x.pem")
    ids = {f.id for f in findings}
    assert "SECRET-PRIVKEY-MALFORMED" in ids
    assert "SECRET-PRIVKEY" not in ids  # must NOT be a HIGH key finding


def test_placeholder_credentials_filtered(tmp_path: Path):
    findings = secrets.scan_bytes(b'password = "changeme"', tmp_path / "c")
    assert not any("GENERIC" in f.id for f in findings)


def test_second_uid0_flagged(tmp_path: Path):
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/false\n"
        "admin:x:0:0:admin:/root:/bin/ash\n"
    )
    findings = accounts.scan_rootfs(root)
    assert any(f.id == "ACCT-MULTI-UID0" for f in findings)


def test_empty_password_is_low_confidence(tmp_path: Path):
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    (root / "etc" / "shadow").write_text("root::0:0:99999:7:::\n")
    findings = accounts.scan_rootfs(root)
    empty = [f for f in findings if f.id == "ACCT-EMPTY-PW"]
    assert empty and empty[0].confidence == "low"
