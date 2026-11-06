#!/usr/bin/env python3
"""Report frontend files exceeding the maintainability budget.

Legacy files are tracked as baseline debt; new files must respect the limit.
Run with --strict to enforce the limit on every scanned file after migration.
"""
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = (ROOT / "static", ROOT / "templates")
EXTENSIONS = {".js", ".css", ".html"}
LEGACY = {"static/dashboard.js", "static/dashboard.css", "templates/dashboard.html"}


def violations(limit=300, strict=False, root=ROOT):
    result = []
    for directory in ("static", "templates"):
        base = root / directory
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix not in EXTENSIONS:
                continue
            relative = path.relative_to(root).as_posix()
            lines = sum(1 for _ in path.open(encoding="utf-8"))
            if lines > limit:
                result.append((relative, lines, strict or relative not in LEGACY))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=300)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be positive")
    items = violations(args.limit, args.strict)
    for path, lines, blocking in items:
        print(f"{'FAIL' if blocking else 'LEGACY'} {path}: {lines} lines (limit {args.limit})")
    failures = sum(blocking for _, _, blocking in items)
    print(f"Frontend size budget: {failures} new violation(s), {len(items) - failures} legacy file(s) to split")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
