"""Command-line interface for fw-scout.

Usage:
    python -m fw_scout.cli IMAGE [-o OUTDIR] [--workdir DIR]

IMAGE may be a firmware file (extracted with binwalk/unblob) or an
already-extracted directory. Writes report.json and report.md to OUTDIR.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from . import __version__
from .reporters import build_summary, write_json, write_markdown
from .scanner import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fw-scout",
        description="Firmware hidden-region and backdoor scanner.",
    )
    parser.add_argument("image", type=Path,
                        help="firmware image file or extracted directory")
    parser.add_argument("-o", "--outdir", type=Path, default=Path("fw-scout-report"),
                        help="output directory for report.json / report.md")
    parser.add_argument("--workdir", type=Path, default=None,
                        help="working directory for extraction (default: temp)")
    parser.add_argument("--version", action="version",
                        version=f"fw-scout {__version__}")
    args = parser.parse_args(argv)

    if not args.image.exists():
        print(f"error: {args.image} does not exist", file=sys.stderr)
        return 2

    args.outdir.mkdir(parents=True, exist_ok=True)
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="fw-scout-"))
    workdir.mkdir(parents=True, exist_ok=True)

    print(f"[fw-scout] scanning {args.image} ...", file=sys.stderr)
    result = scan(args.image, workdir)

    summary = build_summary(
        image=result.image,
        image_sha256=result.image_sha256,
        findings=result.findings,
        meta=result.meta,
    )
    json_path = args.outdir / "report.json"
    md_path = args.outdir / "report.md"
    write_json(json_path, summary, result.findings)
    write_markdown(md_path, summary, result.findings)

    counts = summary["severity_counts"]
    print(
        f"[fw-scout] {summary['finding_count']} findings "
        f"(critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']} info={counts['info']})",
        file=sys.stderr,
    )
    print(f"[fw-scout] wrote {json_path} and {md_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
