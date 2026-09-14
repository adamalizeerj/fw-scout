"""Entropy analysis: find and classify high-entropy regions.

This module codifies the manual method used during the research phase. The
central lesson from that work: **high entropy alone does not distinguish
encrypted data from compressed data**. Both sit near 8.0 bits/byte. The
discriminators are:

  1. A recognisable signature / successful decompression  -> compressed (benign)
  2. Flat maximal entropy + serial correlation ~= 0        -> encryption-like
  3. High entropy + non-trivial serial correlation         -> structured/unknown

A naive "entropy > 7.5 == suspicious" scanner floods on every PNG, font and
compressed filesystem. fw-scout therefore only flags a region as an
encryption-like candidate when it is high-entropy AND undecompressable AND
serially uncorrelated AND not an already-compressed media/asset type.
"""

from __future__ import annotations

import math
import zlib
import lzma
import bz2
from dataclasses import dataclass
from pathlib import Path

from .findings import Finding, Severity, location

# File extensions whose high entropy is expected (already compressed / media).
# Regions or files matching these are not treated as hidden-blob candidates.
EXPECTED_HIGH_ENTROPY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf",
    ".gz", ".xz", ".bz2", ".lzma", ".zip", ".7z", ".zst", ".lz4",
    ".squashfs", ".jffs2", ".cramfs",
    ".mp3", ".mp4", ".ogg", ".webm", ".pdf",
}

HIGH_ENTROPY = 7.5          # bits/byte: above this a region is "high entropy"
ENCRYPTION_ENTROPY = 7.95   # bits/byte: near-maximal, cipher/random-like
LOW_SERIAL_CORR = 0.05      # |serial correlation| below this == uncorrelated


@dataclass
class EntropyStats:
    entropy: float           # Shannon entropy, bits per byte (0..8)
    serial_correlation: float  # lag-1 serial correlation coefficient (-1..1)
    size: int

    @property
    def is_high_entropy(self) -> bool:
        return self.entropy >= HIGH_ENTROPY

    @property
    def looks_encrypted(self) -> bool:
        """Encryption-like: near-maximal entropy AND ~zero serial correlation."""
        return (
            self.entropy >= ENCRYPTION_ENTROPY
            and abs(self.serial_correlation) < LOW_SERIAL_CORR
        )


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte. 8.0 == uniform random."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def serial_correlation(data: bytes) -> float:
    """Lag-1 serial correlation coefficient of the byte stream.

    Mirrors `ent`'s "serial correlation coefficient". Encrypted/random data is
    ~0 (each byte independent of its neighbour); compressed data retains
    structure and shows a measurably non-zero value.
    """
    n = len(data)
    if n < 2:
        return 0.0
    # Pair each byte with the next (wrapping the last to the first, as ent does).
    sum_x = sum_y = sum_xy = sum_x2 = sum_y2 = 0.0
    for i in range(n):
        x = data[i]
        y = data[(i + 1) % n]
        sum_x += x
        sum_y += y
        sum_xy += x * y
        sum_x2 += x * x
        sum_y2 += y * y
    numerator = n * sum_xy - sum_x * sum_y
    denom = math.sqrt((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y))
    if denom == 0:
        return 0.0
    return numerator / denom


def analyse_bytes(data: bytes) -> EntropyStats:
    return EntropyStats(
        entropy=shannon_entropy(data),
        serial_correlation=serial_correlation(data),
        size=len(data),
    )


def try_decompress(data: bytes) -> str | None:
    """Attempt common firmware decompressors. Returns the format name on the
    first that yields output, else None. Compressed data (even without a clean
    header) will usually partially inflate; encrypted data will not.
    """
    for name, fn in (
        ("zlib/gzip", lambda d: zlib.decompressobj().decompress(d)),
        ("raw-deflate", lambda d: zlib.decompressobj(-zlib.MAX_WBITS).decompress(d)),
        ("xz/lzma", lambda d: lzma.decompress(d)),
        ("bz2", lambda d: bz2.decompress(d)),
    ):
        try:
            out = fn(data)
            if out:
                return name
        except Exception:
            continue
    return None


def classify(data: bytes, hint_ext: str = "") -> tuple[str, EntropyStats]:
    """Classify a byte region.

    Returns (classification, stats) where classification is one of:
      "compressed", "encryption-like", "structured-unknown", "low-entropy",
      "expected-media".
    """
    stats = analyse_bytes(data)

    if not stats.is_high_entropy:
        return "low-entropy", stats

    if hint_ext.lower() in EXPECTED_HIGH_ENTROPY_EXT:
        return "expected-media", stats

    if try_decompress(data) is not None:
        return "compressed", stats

    if stats.looks_encrypted:
        return "encryption-like", stats

    return "structured-unknown", stats


def scan_file(path: Path, sample_size: int = 262_144) -> list[Finding]:
    """Analyse a single file's entropy character.

    Reads up to `sample_size` bytes (a 256 KiB sample is plenty to classify
    byte character and keeps memory low on constrained VMs). Only emits a
    Finding when the region is genuinely interesting (encryption-like or an
    unexplained structured-unknown high-entropy blob).
    """
    findings: list[Finding] = []
    try:
        with path.open("rb") as fh:
            data = fh.read(sample_size)
    except OSError:
        return findings

    if not data:
        return findings

    classification, stats = classify(data, hint_ext=path.suffix)

    if classification == "encryption-like":
        findings.append(
            Finding(
                id="ENTROPY-ENC",
                title="Encryption-like high-entropy region",
                severity=Severity.MEDIUM,
                analyser="entropy",
                path=location(path),
                evidence=(
                    f"entropy={stats.entropy:.4f} bit/byte, "
                    f"serial_corr={stats.serial_correlation:.4f}, "
                    f"size={stats.size}"
                ),
                detail=(
                    "Near-maximal entropy with ~zero serial correlation and no "
                    "successful decompression. Statistically indistinguishable "
                    "from encrypted or random data. Not proof of a secret: "
                    "verify by locating this region in the filesystem (it may be "
                    "a pre-encrypted asset or padding)."
                ),
                weakness="CWE-311",
                confidence="medium",
                tags=["entropy", "encryption-candidate"],
            )
        )
    elif classification == "structured-unknown":
        findings.append(
            Finding(
                id="ENTROPY-UNK",
                title="Unexplained high-entropy region",
                severity=Severity.INFO,
                analyser="entropy",
                path=location(path),
                evidence=(
                    f"entropy={stats.entropy:.4f} bit/byte, "
                    f"serial_corr={stats.serial_correlation:.4f}, "
                    f"size={stats.size}"
                ),
                detail=(
                    "High entropy that did not decompress but retains non-trivial "
                    "serial correlation. Could be a filesystem or packed resource "
                    "the extractor missed. Worth manual inspection."
                ),
                confidence="low",
                tags=["entropy", "unknown"],
            )
        )

    return findings
