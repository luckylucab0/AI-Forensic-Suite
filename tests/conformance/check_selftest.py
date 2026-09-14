#!/usr/bin/env python3
"""Compare collect.ps1 -SelfTest output against Python's json.dumps.

Run by the Windows CI job, where the output comes from real Windows PowerShell 5.1 rather
than from whatever PowerShell happens to be on a contributor's machine. That is the point:
the serializer exists because ConvertTo-Json does not match Python, and 5.1 is the runtime
whose behaviour the collector actually depends on.

    python tests/conformance/check_selftest.py selftest.txt
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from selftest_cases import compare


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) == 2 and args[0] == "--powershell":
        # Running the collector from here rather than redirecting its output in the shell.
        # PowerShell 5.1's `>` operator writes UTF-16LE, so a redirected self test could not
        # be read back as UTF-8 at all, and that is the same class of bug the collector
        # documents about Set-Content. A subprocess pipe has one decoding, stated here.
        collector = Path(__file__).resolve().parents[2] / "collector" / "collect.ps1"
        result = subprocess.run(
            [args[1], "-NoLogo", "-NoProfile", "-File", str(collector), "-SelfTest"],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            sys.stderr.write(result.stderr.decode("utf-8", errors="replace"))
            return 1
        text = result.stdout.decode("utf-8")
    elif len(args) == 1:
        text = Path(args[0]).read_text(encoding="utf-8")
    else:
        sys.stderr.write(
            "usage: check_selftest.py <selftest output file>\n"
            "       check_selftest.py --powershell <interpreter>\n"
        )
        return 2
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
