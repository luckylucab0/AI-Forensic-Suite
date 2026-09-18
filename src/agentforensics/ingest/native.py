"""Ingest a bundle this suite's own collectors wrote.

The easy case, and the one everything else is measured against: the manifest already names
the catalogue entry, the hash and the endpoint's own timestamps for every file, because the
collector had the endpoint in front of it. Nothing here has to infer anything, so every
entry is attributed to the collector rather than to a path match.

Two things this adapter does that a caller might not expect. It reads the manifest's
not-collected entries as well, because a credential store recorded as metadata only, or a
file that could not be read, is a real part of the record. And it carries the manifest's
refused patterns and errors into the case as gaps, since those are the holes in the
evidence and they have to be visible from the case rather than only from the bundle.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from agentforensics.bundle import BundleError
from agentforensics.ingest.source import Gap, SourceEntry
from agentforensics.model import BundleRecord


class NativeBundle:
    """A bundle directory written by collect.py or collect.ps1."""

    source_kind = "native"

    def __init__(self, root: Path) -> None:
        self.root = root
        manifest_path = root / "manifest.json"
        if not manifest_path.is_file():
            raise BundleError(f"{root} has no manifest.json")
        try:
            raw = manifest_path.read_bytes()
            self._manifest: dict[str, Any] = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BundleError(f"{manifest_path} could not be read: {exc}") from exc
        # Hashed from the bytes in hand rather than read out of the manifest, which cannot
        # state its own hash. This is the value the bundle's custody records commit to, so
        # carrying it into the case is what lets somebody a year later check the case
        # against the bundle it came from without re-running verify.
        self._manifest_sha256 = hashlib.sha256(raw).hexdigest()
        if "files" not in self._manifest or "collection" not in self._manifest:
            raise BundleError(f"{manifest_path} is not a bundle manifest")

    @staticmethod
    def looks_like(root: Path) -> bool:
        return (root / "manifest.json").is_file() and (root / "files").is_dir()

    def bundle(self) -> BundleRecord:
        collection = self._manifest.get("collection", {})
        tool = self._manifest.get("tool", {})
        return BundleRecord(
            bundle_uuid=str(collection.get("uuid") or ""),
            source_kind=self.source_kind,
            source_path=str(self.root),
            tool_name=tool.get("name"),
            tool_version=tool.get("version"),
            format_version=self._manifest.get("format_version"),
            collected_os=collection.get("os"),
            collected_host=collection.get("hostname"),
            collector_user=collection.get("collector_user"),
            elevated=collection.get("elevated"),
            started_utc=collection.get("started_utc"),
            finished_utc=collection.get("finished_utc"),
            local_timezone=collection.get("local_timezone"),
            local_timezone_name=collection.get("local_timezone_name"),
            manifest_sha256=self._manifest_sha256,
        )

    def entries(self) -> Iterator[SourceEntry]:
        for entry in self._manifest["files"]:
            bundle_path = entry.get("bundle_path")
            local: Path | None = None
            if bundle_path and entry.get("collected"):
                candidate = self.root / bundle_path
                # A manifest entry whose file is missing is not skipped: verify exists to
                # report that, and an entry with no bytes still tells the case that this
                # path was on the endpoint.
                local = candidate if candidate.is_file() else None
            yield SourceEntry(
                original_path=entry["original_path"],
                local_path=local,
                sha256=entry.get("sha256"),
                size=entry.get("size"),
                agent=entry.get("agent"),
                artifact_id=entry.get("artifact_id"),
                category=entry.get("category"),
                status=entry.get("status"),
                attribution="collector" if entry.get("artifact_id") else "none",
                user=entry.get("user"),
                collected=bool(entry.get("collected")),
                reason=entry.get("reason"),
                mtime_utc=entry.get("mtime_utc"),
                atime_utc=entry.get("atime_utc"),
                ctime_utc=entry.get("ctime_utc"),
                birthtime_utc=entry.get("birthtime_utc"),
                symlink=entry.get("symlink"),
                reparse_point=entry.get("reparse_point"),
                changed_while_reading=entry.get("changed_while_reading"),
                also_claimed_by=tuple(entry.get("artifact_ids", ()) or ()),
            )

    def gaps(self) -> Iterator[Gap]:
        for refused in self._manifest.get("refused_patterns", ()) or ():
            if isinstance(refused, dict):
                yield Gap(
                    "refused_pattern",
                    str(refused.get("pattern") or refused.get("expanded") or refused),
                    refused.get("reason"),
                )
            else:
                yield Gap("refused_pattern", str(refused), None)
        for error in self._manifest.get("errors", ()) or ():
            if isinstance(error, dict):
                yield Gap(
                    str(error.get("kind") or "error"),
                    str(error.get("path") or error.get("detail") or error),
                    error.get("reason") or error.get("message"),
                )
            else:
                yield Gap("error", str(error), None)

    @property
    def project_roots(self) -> list[str]:
        """The working copies the collector found by reading the agents' own state files.

        Worth carrying because it is information no adapter over a plain tree can recover:
        which directories the user actually had open, which is what the project-anchored
        half of the catalogue depends on.
        """
        out = []
        for root in self._manifest.get("project_roots") or []:
            # Both collectors write an object per root, {path, source}, so that the manifest
            # says which agent's state file revealed it. Reading the object as a string
            # produced its repr, which matched nothing and silently turned every project
            # file into a profile one. A bare string is accepted as well, because an older
            # bundle or another producer may write one.
            if isinstance(root, dict):
                path = root.get("path")
                if path:
                    out.append(str(path))
            elif root:
                out.append(str(root))
        return out


__all__ = ["NativeBundle"]
