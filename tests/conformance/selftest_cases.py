"""The structures collect.ps1 -SelfTest prints, and the one definition of what they mean.

Two callers: the conformance test, which runs the collector itself, and
check_selftest.py, which the Windows CI job points at output from real PowerShell 5.1.
Keeping the expectations here means those two cannot disagree about what parity is.

The cases are the ones that have actually gone wrong. An empty array and a one-element
array, because PowerShell unwraps both across a function boundary and a one-file manifest
would serialize as an object. A string full of backslashes, because catalogue paths are.
Non-ASCII, because ensure_ascii=False has to be matched rather than escaped. Control
characters, because Python uses short escapes for some and \\uXXXX for the rest.
"""

from __future__ import annotations

import json

CASES: dict[str, object] = {
    "dict_mixed": {"b": 1, "a": "two", "c": True, "d": None},
    "empty_dict": {},
    "empty_list": [],
    "one_element_list": ["only"],
    "nested": [[1, 2], {"k": ["x"]}],
    "unicode": "Grüezi ünd ãçcents 日本語 emoji",
    "control": "tab\there\nnewline\r\bback\fform",
    "quotes": 'he said "hi" and C:\\path\\to',
    "numbers": [0, 1, -1, 268435456, 9007199254740991],
    "bools": [True, False],
    "nulls_in_list": [None, "x", None],
}


def parse_blocks(text: str) -> dict[str, str]:
    """Split -SelfTest output into {case name: rendered JSON}."""
    blocks: dict[str, list[str]] = {}
    name: str | None = None
    for line in text.replace("\r\n", "\n").split("\n"):
        if line.startswith("==="):
            name = line[3:].strip()
            blocks[name] = []
        elif name is not None:
            blocks[name].append(line)
    return {key: "\n".join(value).strip("\n") for key, value in blocks.items()}


def compare(text: str) -> list[str]:
    """Return one problem string per disagreement, empty when the two agree exactly."""
    rendered = parse_blocks(text)
    problems = []
    missing = sorted(set(CASES) - set(rendered))
    extra = sorted(set(rendered) - set(CASES))
    if missing:
        problems.append("the self test did not print: " + ", ".join(missing))
    if extra:
        problems.append("the self test printed unknown cases: " + ", ".join(extra))
    for case, value in CASES.items():
        if case not in rendered:
            continue
        want = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)
        got = rendered[case]
        if got != want:
            # ascii() on both sides, and code points where they diverge. The first version
            # of this message used %r, and a Windows console encodes stderr as cp1252 with
            # backslashreplace: one side came out as replacement characters and the other
            # as \uXXXX escapes, for strings that may or may not have differed. A
            # diagnostic that cannot survive the log it is written to is not a diagnostic.
            problems.append(f"{case}: python {want!a}, powershell {got!a}")
            for index, (left, right) in enumerate(zip(want, got, strict=False)):
                if left != right:
                    problems.append(
                        f"{case}: first difference at index {index}: "
                        f"python U+{ord(left):04X}, powershell U+{ord(right):04X}"
                    )
                    break
            else:
                problems.append(
                    f"{case}: same prefix, different length: "
                    f"python {len(want)}, powershell {len(got)}"
                )
    return problems
