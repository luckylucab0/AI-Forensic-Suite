#!/usr/bin/env python3
"""Compare collect.ps1 -SelfTest output against Python's json.dumps.

Run by the Windows CI job, where the output comes from real Windows PowerShell 5.1 rather
than from whatever PowerShell happens to be on a contributor's machine. That is the point:
the serializer exists because ConvertTo-Json does not match Python, and 5.1 is the runtime
whose behaviour the collector actually depends on.

    python tests/conformance/check_selftest.py selftest.txt
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from selftest_cases import compare


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        sys.stderr.write("usage: check_selftest.py <selftest output file>\n")
        return 2
    text = Path(args[0]).read_text(encoding="utf-8")
    problems = compare(text)
    if problems:
        sys.stderr.write("check-selftest: the PowerShell serializer and json.dumps disagree\n")
        for problem in problems:
            sys.stderr.write(f"  {problem}\n")
        return 1
    sys.stderr.write("check-selftest: byte for byte identical\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
