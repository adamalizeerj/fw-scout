"""Scan orchestrator: run the full fw-scout pipeline over one firmware image.

Pipeline stages (mirrors the manual methodology):
  0. hash the input image (provenance)
  1. extract filesystem(s)  (binwalk/unblob, or use a pre-extracted dir)
  2. entropy analysis        (raw image + high-entropy files)
  3. secrets sweep           (all text-ish files in the rootfs)
  4. account/backdoor hunt   (etc/passwd, etc/shadow per rootfs)
  5. YARA ruleset            (all files)
Findings from every stage are merged and handed to the reporters.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import accounts, entropy, extract, secrets, yara_runner
from .findings import Finding

# Files we skip for the byte-heavy analysers (avoid rescanning huge blobs).
_SKIP_SUFFIXES = {".squashfs", ".jffs2", ".ubi", ".ubifs"}
_MAX_FILE = 5_000_000


@dataclass
class ScanResult:
    image: str
    image_sha256: str
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


def _sha256(path: Path) -> str:
    if not path.is_file():
        return "(not a file)"
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_files(root: Path):
    """Yield regular files under root, skipping symlinks (extraction may have
    neutralised them, and we never want to follow one out of the tree)."""
    for p in root.rglob("*"):
        if p.is_symlink():
            continue
        if p.is_file():
            yield p


def scan(source: Path, workdir: Path,
         entropy_threshold_files: int = 5000) -> ScanResult:
    source = source.resolve()
    result = ScanResult(image=source.name, image_sha256=_sha256(source))

    # --- stage 1: extraction ---------------------------------------------------
    ex = extract.extract(source, workdir)
    result.meta["extraction_tool"] = ex.tool
    result.meta["rootfs_count"] = len(ex.rootfs_dirs)
    result.meta["rootfs_dirs"] = [str(d) for d in ex.rootfs_dirs]

    # --- stage 2: entropy on the raw image ------------------------------------
    if source.is_file():
        result.findings += entropy.scan_file(source)

    # Collect the file set to analyse (union across all rootfs roots).
    all_files: list[Path] = []
    for root in ex.rootfs_dirs:
        all_files.extend(_iter_files(root))
    # If nothing extracted but source is a dir, walk it directly.
    if not all_files and source.is_dir():
        all_files.extend(_iter_files(source))

    # De-duplicate while preserving order.
    seen: set[Path] = set()
    files: list[Path] = []
    for f in all_files:
        if f not in seen:
            seen.add(f)
            files.append(f)
    result.meta["files_analysed"] = len(files)

    # --- stage 2b: entropy on files (guard against scanning too many) ---------
    for f in files[:entropy_threshold_files]:
        if f.suffix.lower() in _SKIP_SUFFIXES:
            continue
        result.findings += entropy.scan_file(f)

    # --- stage 3: secrets sweep -----------------------------------------------
    for f in files:
        if f.suffix.lower() in _SKIP_SUFFIXES:
            continue
        try:
            if f.stat().st_size > _MAX_FILE:
                continue
        except OSError:
            continue
        result.findings += secrets.scan_file(f)

    # --- stage 4: account / backdoor hunt -------------------------------------
    for root in ex.rootfs_dirs:
        result.findings += accounts.scan_rootfs(root)

    # --- stage 5: YARA ---------------------------------------------------------
    result.meta["yara_available"] = yara_runner.available()
    if yara_runner.available():
        result.findings += yara_runner.scan_files(
            [f for f in files if f.suffix.lower() not in _SKIP_SUFFIXES]
        )

    return result
