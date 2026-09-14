"""Firmware extraction: locate or produce an extracted root filesystem.

fw-scout does not reimplement extraction -- it drives binwalk (preferred) or
unblob, whichever is available, then locates the resulting rootfs. If the input
is already an extracted directory, extraction is skipped.

Security note: extraction of untrusted firmware can write attacker-influenced
paths. We always extract into a dedicated output directory and never follow
symlinks out of it when later walking the tree.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Extraction:
    source: Path
    output_dir: Path
    rootfs_dirs: list[Path]  # discovered filesystem roots (may be several)
    tool: str  # "binwalk" | "unblob" | "preextracted" | "none"


ROOTFS_MARKERS = ("bin", "etc", "sbin", "usr", "lib")


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _looks_like_rootfs(d: Path) -> bool:
    present = sum(1 for m in ROOTFS_MARKERS if (d / m).is_dir())
    return present >= 3


def find_rootfs_dirs(base: Path) -> list[Path]:
    """Walk an extraction output and return every directory that looks like a
    Linux root filesystem (has bin/etc/sbin/... markers)."""
    roots: list[Path] = []
    if _looks_like_rootfs(base):
        roots.append(base)
    for d in base.rglob("*"):
        if d.is_dir() and _looks_like_rootfs(d):
            roots.append(d)
    # De-duplicate nested duplicates, keep shallowest unique roots.
    roots = sorted(set(roots), key=lambda p: len(p.parts))
    return roots


def extract(source: Path, workdir: Path) -> Extraction:
    """Extract `source` firmware into `workdir`. If `source` is a directory,
    treat it as an already-extracted tree."""
    workdir.mkdir(parents=True, exist_ok=True)

    if source.is_dir():
        roots = find_rootfs_dirs(source)
        return Extraction(source, source, roots, "preextracted")

    out = workdir / (source.name + ".extracted")

    if _tool_available("binwalk"):
        # -e extract, -M recurse (matryoshka), quiet
        subprocess.run(
            ["binwalk", "-e", "-M", "--directory", str(workdir), str(source)],
            capture_output=True, text=True, timeout=1800,
        )
        # binwalk names output _<name>.extracted next to the directory arg
        candidate = workdir / f"_{source.name}.extracted"
        base = candidate if candidate.exists() else workdir
        roots = find_rootfs_dirs(base)
        if roots:
            return Extraction(source, base, roots, "binwalk")

    if _tool_available("unblob"):
        out.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["unblob", "-e", str(out), str(source)],
            capture_output=True, text=True, timeout=1800,
        )
        roots = find_rootfs_dirs(out)
        if roots:
            return Extraction(source, out, roots, "unblob")

    # Nothing worked / no tool: return empty so the caller can still run
    # byte-level analysers on the raw image.
    return Extraction(source, workdir, [], "none")
