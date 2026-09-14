"""Bundle reading and verification.

Design constraint served: a bundle has to be checkable offline, by someone who did not
collect it, years later. So verification re-derives everything from the bytes on disk and
compares against the manifest, rather than trusting any value in it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MANIFEST_NAME = "manifest.json"
CUSTODY_NAME = "chain_of_custody.jsonl"
FILES_DIR = "files"

SUPPORTED_FORMAT_VERSIONS = (1,)


class BundleError(Exception):
    """The bundle is missing, unreadable, or not a bundle."""


@dataclass(frozen=True, slots=True)
class Manifest:
    path: Path
    data: dict[str, Any]

    @property
    def format_version(self) -> int:
        return int(self.data.get("format_version", 0))

    @property
    def collection_uuid(self) -> str:
        return str(self.data.get("collection", {}).get("uuid", ""))

    @property
    def files(self) -> list[dict[str, Any]]:
        entries = self.data.get("files", [])
        return list(entries) if isinstance(entries, list) else []

    @property
    def sha256(self) -> str:
        """Hash of the manifest exactly as stored, which is what custody records commit to."""
        return hashlib.sha256(self.path.read_bytes()).hexdigest()


@dataclass
class VerifyReport:
    """What verification found. Empty lists mean the bundle is intact."""

    bundle: Path
    format_version: int = 0
    collection_uuid: str = ""
    checked: int = 0
    # A file the manifest lists as collected but which is not in the bundle. The most
    # serious finding: evidence that was recorded as present and is not.
    missing: list[str] = field(default_factory=list)
    # A file whose bytes no longer hash to the recorded value.
    mismatched: list[str] = field(default_factory=list)
    # A file in files/ that no manifest entry claims. Something was added after collection.
    unexpected: list[str] = field(default_factory=list)
    # Entries that are internally inconsistent, for example collected without a hash.
    inconsistent: list[str] = field(default_factory=list)
    custody_problems: list[str] = field(default_factory=list)
    # Recorded, not a failure: the collector already flagged these at collection time.
    changed_while_reading: list[str] = field(default_factory=list)
    skipped_by_policy: int = 0

    @property
    def ok(self) -> bool:
        return not (
            self.missing
            or self.mismatched
            or self.unexpected
            or self.inconsistent
            or self.custody_problems
        )

    def summary(self) -> str:
        if self.ok:
            extra = ""
            if self.changed_while_reading:
                n = len(self.changed_while_reading)
                extra = f", {n} file(s) were changing while they were read"
            return f"intact: {self.checked} file(s) verified{extra}"
        parts = []
        for label, items in (
            ("missing", self.missing),
            ("hash mismatch", self.mismatched),
            ("unexpected", self.unexpected),
            ("inconsistent", self.inconsistent),
            ("custody", self.custody_problems),
        ):
            if items:
                parts.append(f"{len(items)} {label}")
        return "NOT intact: " + ", ".join(parts)


def read_manifest(bundle: Path) -> Manifest:
    path = bundle / MANIFEST_NAME
    if not path.is_file():
        raise BundleError(f"{bundle} has no {MANIFEST_NAME}, so it is not a bundle")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BundleError(f"cannot read {path}: {exc}") from exc
    except ValueError as exc:
        raise BundleError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BundleError(f"{path} does not contain an object")
    version = data.get("format_version")
    if version not in SUPPORTED_FORMAT_VERSIONS:
        raise BundleError(
            f"{path} declares format_version {version!r}, and this build reads "
            f"{SUPPORTED_FORMAT_VERSIONS}. Refusing to guess: a format change could mean a "
            f"field means something different now."
        )
    return Manifest(path=path, data=data)


def decode_bundle_path(bundle_path: str, os_name: str) -> str:
    """Invert the path mapping, as far as it inverts.

    Only steps 1 to 4 of the mapping in docs/BUNDLE_FORMAT.md are reversible. Truncation
    of an over-long component and the suffix that breaks a case collision are not, and
    this function makes no attempt to hide that. Callers that need the original path read
    `original_path` from the manifest, which is mandatory precisely so that the encoding is
    never the only record of where a file came from. This exists for display and for tests.
    """
    relative = (
        bundle_path[len(FILES_DIR) + 1 :]
        if bundle_path.startswith(FILES_DIR + "/")
        else bundle_path
    )
    segments = relative.split("/")
    decoded = [
        re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), seg) for seg in segments
    ]
    if os_name == "windows" and decoded:
        if decoded[0] == "UNC":
            return "\\\\" + "\\".join(decoded[1:])
        if len(decoded[0]) == 1 and decoded[0].isalpha():
            return decoded[0] + ":\\" + "\\".join(decoded[1:])
        return "\\".join(decoded)
    return "/" + "/".join(decoded)


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_custody(bundle: Path, manifest: Manifest) -> list[str]:
    """Check the hash chain, and that it commits to this manifest.

    Tamper-evident, not tamper-proof: whoever can write the file can rewrite the whole
    chain. What this catches is a single record removed or edited, which is the realistic
    case, and a chain that describes a different manifest than the one present.
    """
    path = bundle / CUSTODY_NAME
    problems: list[str] = []
    if not path.is_file():
        return [f"{CUSTODY_NAME} is missing"]

    previous: str | None = None
    manifest_sha = manifest.sha256
    seen_manifest_hash = False
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError as exc:
            problems.append(f"record {index} is not valid JSON: {exc}")
            return problems
        stated = record.pop("sha256", None)
        recomputed = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if stated != recomputed:
            problems.append(
                f"record {index} ({record.get('event')}) does not hash to its stated value, "
                "so it was edited after it was written"
            )
        if record.get("prev_sha256") != previous:
            problems.append(
                f"record {index} does not link to record {index - 1}, so a record was "
                "removed, reordered or inserted"
            )
        if record.get("manifest_sha256") == manifest_sha:
            seen_manifest_hash = True
        if record.get("seq") != index:
            problems.append(f"record {index} claims seq {record.get('seq')!r}")
        previous = stated

    if previous is None:
        problems.append(f"{CUSTODY_NAME} contains no records")
    elif not seen_manifest_hash:
        problems.append(
            "no custody record commits to this manifest's hash, so the chain describes a "
            "different manifest than the one in this bundle"
        )
    return problems


def verify_bundle(bundle: Path) -> VerifyReport:
    """Re-derive every hash and compare against the manifest."""
    manifest = read_manifest(bundle)
    report = VerifyReport(
        bundle=bundle,
        format_version=manifest.format_version,
        collection_uuid=manifest.collection_uuid,
    )

    expected: dict[str, dict[str, Any]] = {}
    for entry in manifest.files:
        original = str(entry.get("original_path", "<unknown>"))
        if not entry.get("collected"):
            if entry.get("reason") == "secret_policy":
                report.skipped_by_policy += 1
            # A skipped entry must not claim a place in files/.
            if entry.get("bundle_path"):
                report.inconsistent.append(
                    f"{original}: not collected but claims {entry['bundle_path']}"
                )
            continue
        bundle_path = entry.get("bundle_path")
        if not bundle_path:
            # A collected entry with no bundle path is only valid for a dry run, which
            # writes no bundle at all, so inside a bundle it is a contradiction.
            report.inconsistent.append(f"{original}: collected but has no bundle_path")
            continue
        if not entry.get("sha256"):
            report.inconsistent.append(f"{original}: collected but has no sha256")
            continue
        expected[str(bundle_path)] = entry
        if entry.get("changed_while_reading"):
            report.changed_while_reading.append(original)

    files_root = bundle / FILES_DIR
    for bundle_path, entry in sorted(expected.items()):
        target = bundle / Path(*bundle_path.split("/"))
        if not target.is_file():
            report.missing.append(bundle_path)
            continue
        report.checked += 1
        if _sha256_of(target) != entry["sha256"]:
            report.mismatched.append(bundle_path)

    if files_root.is_dir():
        for path in sorted(files_root.rglob("*")):
            if not path.is_file():
                continue
            relative = FILES_DIR + "/" + path.relative_to(files_root).as_posix()
            if relative not in expected:
                report.unexpected.append(relative)

    report.custody_problems = verify_custody(bundle, manifest)
    return report
