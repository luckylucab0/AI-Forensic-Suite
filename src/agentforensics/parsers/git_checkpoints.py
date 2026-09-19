"""Read the checkpoint references two agents write into a git repository.

An agent that can undo its own edits keeps a snapshot of the files it is about to change.
Two of the agents here do it with git, and the modern shape is the one worth reading: the
extension runs `git stash create` in the user's own repository and then writes the commit
it got under a private reference namespace, `refs/cline/checkpoints/<session>/<run>`. So a
checkpoint is a commit in the developer's own object store, pointed at by a file of
forty-one bytes that nothing else on the endpoint explains.

What this reader takes from a collection depends on which of the two shapes it is, and
getting that wrong is what this reader used to do. Where only the references are in the
user's own repository, the objects they name are in that repository's store and the
catalogue does not collect it, so the event says the content is elsewhere. Where the agent
keeps a repository of its own, the catalogue collects it whole, objects included, and the
commit, the tree and the file contents behind every checkpoint are in the bundle already.
The old text said the second case was the first, on every event of both, and sent an
analyst back to the endpoint for something they were holding.

So the events here answer when a checkpoint was taken, for which session and which run of
it, which commit it is, and, where the objects travelled, what was in the files at that
moment. That is a timeline no other artifact carries: the reference log is the only record
on the endpoint that dates an agent's edits to a repository, it survives the deletion of
the conversation that made them, and a commit beside it dates the capture by the clock of
the machine that made it.

The files, and what each one is:

- a reference file, which holds one object id, or a symbolic reference to another name
- the reference log beside it, one line per write, each carrying the previous and the new
  object id, who wrote it, when, and a message the tool chose
- the packed references file, where git moves a reference once it packs them, which is why
  a checkpoint can be absent from `refs/` and still exist
- an object under `objects/`, in a repository the agent owns: a commit, a tree or a file,
  read by the module beside this one. A pack file is named and not expanded, and says so

The identity in a reference log is the repository's own git identity, which is a person's
name and address. It is carried because it is evidence of who the commit was attributed to
and because the case is evidence, and an examiner handling it is handling a device's data
either way.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event, unparsed
from agentforensics.parsers import git_objects
from agentforensics.parsers.base import ParseContext, looks_binary, normalise_ts, text_lines
from agentforensics.parsers.instructions import BINARY_FILE, MAX_TEXT

# The artifacts this reader claims. The two shadow repositories are the older mechanism,
# where the whole repository including its objects sits under the extension's storage; the
# third is the modern one, where only the references are in the user's own repository.
STORES = frozenset(
    {
        "amazonq.cli_checkpoints",
        "cline.checkpoint_refs_in_workspace",
        "cline.checkpoints_shadow_git_legacy",
        "roo_code.checkpoints",
    }
)

# The entries whose repository the agent owns, and which the catalogue therefore collects
# whole. For these the objects are in the bundle and an event must not say otherwise. The
# one left out keeps its references in the user's own repository, whose object store this
# catalogue does not take, which is the case NO_CONTENT below is for.
OWN_REPOSITORY = frozenset(
    {
        "amazonq.cli_checkpoints",
        "cline.checkpoints_shadow_git_legacy",
        "roo_code.checkpoints",
    }
)

# Said on every event, because the difference decides what an analyst can do next. A
# reference names a commit; the commit's content is in the repository's object store, which
# this collection does not take.
NO_CONTENT = (
    "this is the reference to a checkpoint and not its content: the commit it names lives "
    "in the user's own repository, whose object store a collection of these paths does not "
    "carry. Recover it from the endpoint or from a disk image with the object id on this "
    "event"
)

# The same sentence for the other shape, where saying the first one would be wrong.
IN_THE_BUNDLE = (
    "this is the reference to a checkpoint. The agent owns this repository and the "
    "collection took it whole, so the commit this names, the files it held and their "
    "contents are in this case: look for the object id on this event"
)

# A pack file. Reported rather than expanded, because resolving a packed object needs the
# pack format and its two delta encodings, which this suite does not implement and will not
# guess at. Said out loud because a repository whose objects are packed and unread is a
# different answer from a repository that held nothing.
PACKED = (
    "this is a git pack file and its objects are not expanded here: they are deltas "
    "addressed by the index beside them, and this suite reads loose objects only. The "
    "objects are in this file, in the bundle, under this event's hash. These repositories "
    "are normally never garbage collected, so a pack in one is itself worth a look"
)

NOT_AN_OBJECT = (
    "this file sits under a repository's objects directory and is not a loose object: {reason}"
)

# What a repository holds besides its references and its objects. Named rather than read,
# because an agent's own repository carries the same bookkeeping as any other and none of
# it is the evidence this artifact is collected for.
BOOKKEEPING = (
    "this is a git repository's own bookkeeping rather than a checkpoint. It is recorded "
    "so the case says the repository was there and what shape it was in"
)

TEMPLATE_HOOK = (
    "this is one of the disabled hook templates git writes into every repository it "
    "creates. The suffix is what keeps it from running, and its presence says nothing "
    "except that a repository was created here"
)

ENABLED_HOOK = (
    "this is a git hook that is not one of the templates git ships: it is a script that "
    "runs on a repository operation, in a repository an agent created for its own undo, so "
    "somebody put it somewhere it executes. Read it"
)

# How much of a small text file is carried. The bookkeeping files are a few lines each, and
# the one that matters is the configuration, which can name a remote the checkpoints were
# pushed to. A larger file is recorded by size alone: the index is a binary listing and the
# reader for it is a different piece of work.
SMALL_TEXT = 64 * 1024

# One line of a git reference log. The format is the one git writes: the previous object,
# the new object, the identity, the time as seconds since the epoch and a zone, then a tab
# and whatever the tool that wrote it had to say.
_REFLOG = re.compile(
    r"^(?P<old>[0-9a-f]{40}|[0-9a-f]{64})\s+"
    r"(?P<new>[0-9a-f]{40}|[0-9a-f]{64})\s+"
    r"(?P<who>.*?)\s+"
    r"(?P<when>\d+)\s+(?P<zone>[+-]\d{4})"
    r"(?:\t(?P<message>.*))?$"
)

# A loose object's path: a two character directory named for the first byte of its id, and
# a file named for the rest. Both hash lengths, so a repository written with either reads.
_LOOSE_PREFIX = re.compile(r"^[0-9a-f]{2}$")
_LOOSE_REST = re.compile(r"^[0-9a-f]{38}$|^[0-9a-f]{62}$")

# An object id on its own, which is what a loose reference file holds.
_OBJECT_ID = re.compile(r"^(?P<id>[0-9a-f]{40}|[0-9a-f]{64})$")

# A line of the packed references file. The peeled lines beginning with a caret belong to
# the reference above them and are not references of their own.
_PACKED = re.compile(r"^(?P<id>[0-9a-f]{40}|[0-9a-f]{64})\s+(?P<ref>\S+)$")

# The private namespaces these agents write. A packed references file holds every reference
# in the repository, and the branches a developer works on are not this artifact's evidence.
_NAMESPACES = ("refs/cline/", "refs/roo/", "refs/checkpoints/")


class GitCheckpointsParser:
    """The checkpoint references, read as the timeline they are."""

    name = "git_checkpoints"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in STORES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        """Dispatch on where in the repository the file sits.

        The path and not the content, because that is what git itself goes by: a file under
        `refs/` is a reference whatever is in it, and a file under `objects/` is an object.
        A repository an agent owns arrives here file by file, so every part of it reaches
        this method, the bookkeeping included.
        """
        name = context.original_path.replace("\\", "/")
        if name.endswith("/packed-refs"):
            yield from self._packed(context)
            return
        if "/logs/refs/" in name:
            yield from self._reflog(context)
            return
        if "/objects/" in name:
            yield from self._object(context, name)
            return
        if "/refs/" in name:
            yield from self._ref(context)
            return
        yield from self._bookkeeping(context, name)

    # -------------------------------------------------------------- bookkeeping

    def _bookkeeping(self, context: ParseContext, name: str) -> Iterator[Event]:
        """Everything else in a repository: HEAD, config, the index, the hooks.

        A configuration event and not an unread record, because this is how the repository
        was set up and the suite does understand that. Filing git's own boilerplate as
        something nothing could read would put fifteen template hooks per repository into
        the one number a case's reliability is judged by.

        One thing here is evidence rather than boilerplate. A hook is a script git runs on
        a repository operation, every repository is created with a directory of disabled
        templates, and a hook that is not one of those templates is code somebody put in a
        place where it runs. The two are told apart by the suffix git gives its own, which
        is the only thing that distinguishes them on disk.
        """
        text, note = _small_text(context)
        hook = "/hooks/" in name
        enabled = hook and not name.endswith(".sample")
        reason = ENABLED_HOOK if enabled else TEMPLATE_HOOK if hook else BOOKKEEPING
        payload: dict[str, Any] = {
            "key": f"git:{context.local_path.name}",
            "text": text or reason,
        }
        if enabled:
            # The same facet the instruction reader puts on a hook script, because this is
            # the same thing: a file the endpoint will execute on its own. Without it the
            # rule about a hook that fetches code and runs it cannot see this one, and a
            # hook planted in a repository an agent created for its own undo is exactly
            # the placement that rule exists for.
            payload["executable"] = True
        yield Event(
            # An enabled hook is an instruction the endpoint will obey, which is what this
            # kind is for and what its own definition names as an example. The templates
            # and the rest of the repository are configuration: that is how it was set up.
            kind="instruction.source" if enabled else "config.snapshot",
            provenance=context.provenance("file"),
            agent=context.agent,
            actor="system",
            user=context.user,
            host=context.host,
            raw={
                "file": context.local_path.name,
                "bytes": _size(context),
                **({"content": text} if text is not None else {}),
            },
            payload=payload,
            parse_problem=" ".join(part for part in (reason, note) if part),
        )

    # ------------------------------------------------------------------ objects

    def _object(self, context: ParseContext, name: str) -> Iterator[Event]:
        """One file under a repository's object store, read for what it is."""
        if "/objects/pack/" in name:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": context.local_path.name, "bytes": _size(context)},
                PACKED,
                user=context.user,
                host=context.host,
            )
            return
        try:
            raw = context.local_path.read_bytes()
        except OSError as error:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                None,
                f"this file could not be read: {error}",
                user=context.user,
                host=context.host,
            )
            return
        try:
            found = git_objects.read(raw)
        except git_objects.GitObjectError as error:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": context.local_path.name, "bytes": len(raw)},
                NOT_AN_OBJECT.format(reason=error),
                user=context.user,
                host=context.host,
            )
            return
        yield self._read_object(context, found, _object_id(name))

    def _read_object(
        self, context: ParseContext, found: git_objects.GitObject, object_id: str | None
    ) -> Event:
        """One object as an event, with the time a commit carries and the content a blob is."""
        record: dict[str, Any] = {"type": found.kind, "size": found.size}
        if object_id:
            record["object_id"] = object_id
        when = precision = source = None
        timing = None
        text: str | None = None

        if found.kind == "commit":
            record.update(
                {
                    "tree": found.tree,
                    "parents": list(found.parents),
                    "author": found.author,
                    "committer": found.committer,
                    "zone": found.commit_zone or found.author_zone,
                    "message": found.message,
                }
            )
            # The commit's own clock, which is the machine's at the moment the content was
            # captured. The reference log dates the write; this dates the capture, and a
            # difference between the two is worth an analyst's attention.
            seconds = found.commit_time or found.author_time
            if seconds is not None:
                when, precision, timing = normalise_ts(int(seconds))
                source = "the commit's own timestamp"
            text = found.message
        elif found.kind == "tree":
            record["entries"] = [
                {"mode": entry.mode, "name": entry.name, "object_id": entry.object_id}
                for entry in found.entries
            ]
            # The listing, as one block, so a search for a file name finds the checkpoint
            # that held it.
            text = "\n".join(entry.name for entry in found.entries) or None
        elif found.kind == "tag":
            record.update({"target": found.target, "message": found.message})
            text = found.message
        else:
            content, note = _blob_text(found.body)
            record["content"] = content
            if note:
                record["problem"] = note
            text = content

        return self._event(
            context,
            f"object:{object_id}" if object_id else "file",
            record,
            when=when,
            precision=precision or "absent",
            source=source,
            note=timing,
            text=text,
        )

    def _ref(self, context: ParseContext) -> Iterator[Event]:
        """A loose reference file: one object id, or a pointer to another name."""
        lines = [line for line in text_lines(context.local_path) if line.text.strip()]
        if not lines:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": context.local_path.name},
                "this reference file is empty, which is what a partially written or a "
                "deleted reference leaves behind",
                user=context.user,
                host=context.host,
            )
            return
        text = lines[0].text.strip()
        found = _OBJECT_ID.match(text)
        if not found:
            if text.startswith("ref: "):
                yield self._event(
                    context,
                    "file",
                    {"symbolic_ref": text[len("ref: ") :].strip()},
                    note="this reference points at another reference rather than at a "
                    "commit, so the checkpoint is whatever that one names",
                )
                return
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"text": text},
                "this file is under a reference path and does not hold an object id",
                user=context.user,
                host=context.host,
            )
            return
        yield self._event(
            context,
            "file",
            {"object_id": found.group("id"), **_ref_parts(context.original_path)},
        )

    def _reflog(self, context: ParseContext) -> Iterator[Event]:
        """The log beside a reference: one line per write, and the only clock here."""
        for line in text_lines(context.local_path):
            if not line.text.strip():
                continue
            found = _REFLOG.match(line.text)
            if not found:
                yield unparsed(
                    context.provenance(line.locator),
                    context.agent,
                    line.text,
                    line.problem or "this line is not in the shape a reference log is written in",
                    user=context.user,
                    host=context.host,
                )
                continue
            when, precision, timing = normalise_ts(int(found.group("when")))
            yield self._event(
                context,
                line.locator,
                {
                    "object_id": found.group("new"),
                    "previous_object_id": found.group("old"),
                    # The identity git recorded for the write. It is a person, and it is
                    # evidence of attribution rather than decoration.
                    "written_by": found.group("who"),
                    "message": found.group("message") or None,
                    "zone": found.group("zone"),
                    **_ref_parts(context.original_path),
                },
                when=when,
                precision=precision,
                source="the reference log's own timestamp",
                note=timing,
            )

    def _packed(self, context: ParseContext) -> Iterator[Event]:
        """The packed references file, narrowed to the namespaces these agents write."""
        for line in text_lines(context.local_path):
            text = line.text.strip()
            if not text or text.startswith("#") or text.startswith("^"):
                continue
            found = _PACKED.match(text)
            if not found:
                continue
            ref = found.group("ref")
            if not ref.startswith(_NAMESPACES):
                # Every branch and tag in the repository is in this file. Only the private
                # namespaces are this artifact's evidence, and carrying the rest would put
                # a developer's whole branch list into a case that did not ask for it.
                continue
            yield self._event(
                context,
                line.locator,
                {"object_id": found.group("id"), **_ref_parts(ref)},
            )

    def _event(
        self,
        context: ParseContext,
        locator: str,
        record: dict[str, Any],
        *,
        when: str | None = None,
        precision: str = "absent",
        source: str | None = None,
        note: str | None = None,
        text: str | None = None,
    ) -> Event:
        # Which of the two sentences is true depends on the artifact and not on the file:
        # one shape keeps its references in the user's own repository and the other owns
        # the repository outright. Saying the first on both is what this reader used to do.
        carried = context.artifact_id in OWN_REPOSITORY
        return Event(
            kind="file.snapshot",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw=record,
            ts_utc=when,
            ts_precision=precision,  # type: ignore[arg-type]
            ts_source=source if when else None,
            # The agent wrote the reference, not the person: the extension creates the
            # stash and updates the reference by itself around an edit it is making.
            actor="assistant",
            user=context.user,
            host=context.host,
            session_id=record.get("session_id"),
            payload={
                "checkpoint": record,
                "text": text if text is not None else record.get("message"),
            },
            parse_problem=" ".join(
                part for part in (note, IN_THE_BUNDLE if carried else NO_CONTENT) if part
            ),
        )


# How much of a blob is carried into the case. The same limit the other whole-file readers
# use, so a checkpoint of a large file behaves the way a copy of one does.
MAX_BLOB = MAX_TEXT


def _size(context: ParseContext) -> int | None:
    try:
        return context.local_path.stat().st_size
    except OSError:
        return None


def _object_id(name: str) -> str | None:
    """The object id a loose object's own path spells: two characters, then the rest.

    Read from the path because the object does not carry its own id; git derives it by
    hashing the object, and recomputing it here would be a second implementation of the
    hash for no gain. A file under objects/ whose path is not in that shape returns
    nothing rather than a guess.
    """
    parts = name.rsplit("/objects/", 1)
    if len(parts) != 2:
        return None
    tail = parts[1].split("/")
    if len(tail) == 2 and _LOOSE_PREFIX.match(tail[0]) and _LOOSE_REST.match(tail[1]):
        return tail[0] + tail[1]
    return None


def _small_text(context: ParseContext) -> tuple[str | None, str | None]:
    """A bookkeeping file's own text, where it is small and is text."""
    try:
        raw = context.local_path.read_bytes()
    except OSError as error:
        return None, f"this file could not be read: {error}"
    if len(raw) > SMALL_TEXT:
        return None, f"this file is larger than {SMALL_TEXT} bytes and is recorded by size"
    if looks_binary(raw):
        return None, BINARY_FILE
    return raw.decode("utf-8", "replace"), None


def _blob_text(body: bytes) -> tuple[str | None, str | None]:
    """A blob as text, or nothing with the reason when it is not text.

    A checkpoint of a compiled file or an image is a real checkpoint and a page of
    replacement characters would read as its content, which is the mistake every reader in
    this package is written to avoid.
    """
    if looks_binary(body):
        return None, BINARY_FILE
    text = body.decode("utf-8", "replace")
    problems = []
    if "\ufffd" in text:
        problems.append(
            "the file did not decode as UTF-8 and was read with replacement characters, so "
            "its content is not exact"
        )
    if len(text) > MAX_BLOB:
        problems.append(
            f"the content is longer than the ingest limit of {MAX_BLOB} characters and is "
            "carried truncated. The whole object is in the bundle, at the path in this "
            "event's provenance"
        )
        text = text[:MAX_BLOB]
    return text, " ".join(problems) or None


def _ref_parts(path: str) -> dict[str, Any]:
    """The session and the run a checkpoint reference names, where it names them.

    The namespace one of these agents documents is `refs/cline/checkpoints/<session>/<run>`,
    so the last two segments carry the conversation the snapshot belongs to and which turn
    of it. Read positionally and only from that shape: a reference under another layout
    keeps its name and claims nothing.
    """
    text = path.replace("\\", "/")
    at = text.find("refs/")
    ref = text[at:] if at >= 0 else text
    # The reference log lives under .git/logs/refs/..., and the reference it logs is the
    # same name with the logs segment removed.
    ref = ref.replace("logs/refs/", "refs/", 1)
    out: dict[str, Any] = {"ref": ref}
    parts = ref.split("/")
    if len(parts) >= 5 and parts[2] == "checkpoints":
        out["session_id"] = parts[3]
        out["run"] = parts[4]
    return out


__all__ = ["NO_CONTENT", "STORES", "GitCheckpointsParser"]
