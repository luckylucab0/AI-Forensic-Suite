"""Read the checkpoint references three agents write into a git repository.

An agent that can undo its own edits keeps a snapshot of the files it is about to change.
Three of the agents here do it with git, in three shapes. The one worth reading first is
the modern extension shape: it runs `git stash create` in the user's own repository and
then writes the commit it got under a private reference namespace,
`refs/cline/checkpoints/<session>/<run>`. So a checkpoint is a commit in the developer's
own object store, pointed at by a file of forty-one bytes that nothing else on the
endpoint explains.

The third shape is one shared bare repository under the agent's home for every project it
has ever worked in, with one reference per project named after a hash of that project's
absolute path, `refs/hermes/<hash>`. It reads like the second shape, because the agent
owns the repository and the collection takes it whole, and the hash is carried on the
events so the store's own project index can name the directory behind it.

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
  read by the module beside this one, whether it sits there loose or inside a pack file,
  which is expanded by the module beside that one

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
from agentforensics.parsers import git_index, git_objects, git_pack
from agentforensics.parsers.base import ParseContext, looks_binary, normalise_ts, text_lines
from agentforensics.parsers.instructions import BINARY_FILE, MAX_TEXT

# The artifacts this reader claims. The two shadow repositories are the older mechanism,
# where the whole repository including its objects sits under the extension's storage; the
# third is the modern one, where only the references are in the user's own repository.
STORES = frozenset(
    {
        "amazonq.cli_checkpoints",
        "cline.checkpoint_refs_in_workspace",
        "cline.checkpoint_scratch",
        "cline.checkpoints_shadow_git_legacy",
        "hermes.checkpoints",
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
        "hermes.checkpoints",
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

# Said on every object that came out of a pack, because a packed object is evidence with a
# step in front of it: the bundle holds the pack and the content on the event was computed
# from it here. An analyst who wants to reproduce it needs to know that.
FROM_A_PACK = (
    "this object was expanded out of the pack file at this event's path, at the byte "
    "offset in this event's locator. It is not a file of its own in the bundle: git "
    "stores it as a difference against another object in the same pack, and what is on "
    "this event is the result of applying it"
)

# What else lives in a pack directory. All of it is derived from the pack beside it and
# holds nothing the pack does not, which is worth saying rather than leaving a file in the
# bundle that no event mentions.
PACK_DERIVED = (
    "this file belongs to the pack file beside it rather than holding objects of its own: "
    "an index, a reverse index, a bitmap or one of the markers git keeps there. What the "
    "pack holds is on the events from the pack, and this file's own name is on this event"
)

NOT_A_PACK = (
    "this file is named as a git pack and does not read as one: {reason}. It is in the "
    "bundle, whole, at the path in this event's provenance"
)

# A pack whose own header counts no objects. Said out loud because the alternative is the
# one failure this suite must not have: every object of a pack is an event of its own, so a
# pack that yields none would otherwise leave a file in the bundle that no event mentions,
# and a case that says nothing about a file reads as a file that held nothing.
EMPTY_PACK = (
    "this pack's own header counts no objects, so there was nothing in it to expand. A "
    "repository writes a pack when it packs its objects, and one counting none is either "
    "a pack that was truncated or one written and never filled"
)

NOT_AN_OBJECT = (
    "this file sits under a repository's objects directory and is not a loose object: {reason}"
)

# A packed object that expanded and then did not read as the type the pack says it is. The
# expansion is the part this suite does, so the bytes are worth carrying even when the
# reading of them failed.
NOT_THE_TYPE = (
    "this object was expanded out of a pack and does not read as the {kind} the pack says "
    "it is: {reason}"
)

# What a repository holds besides its references and its objects. Named rather than read,
# because an agent's own repository carries the same bookkeeping as any other and none of
# it is the evidence this artifact is collected for.
INDEX_STOPPED = (
    "this listing holds more than {limit} paths and the reading stopped there. What is "
    "missing is the rest of this file, not the rest of the evidence: the whole of it is in "
    "the bundle, at the path in this event's provenance"
)

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

# The project segment of the shared store's reference namespace: sixteen hex characters,
# the front of the sha256 of the working directory's absolute path. Matched rather than
# assumed so a reference that merely happens to sit under refs/hermes/ is not relabelled.
_PROJECT_HASH = re.compile(r"[0-9a-f]{16}")

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
        if context.local_path.name == "index":
            yield from self._index(context)
            return
        if context.local_path.name == "pathspec":
            yield from self._pathspec(context)
            return
        if "/refs/" in name:
            yield from self._ref(context)
            return
        yield from self._bookkeeping(context, name)

    # ------------------------------------------------------------- the listing

    def _index(self, context: ParseContext) -> Iterator[Event]:
        """The working copy as git last saw it: one path, with its size, mode and clock.

        The agent that writes one of these beside a checkpoint keeps it out of the system
        temporary directory on purpose, and its own source says why: this file and the path
        list beside it enumerate workspace paths. So it is a listing of somebody's working
        copy at the moment of a checkpoint, untracked files included, and no other artifact
        in this catalogue is that.
        """
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
        if not git_index.looks_like_index(raw):
            yield from self._bookkeeping(context, context.original_path)
            return
        seen = 0
        try:
            for entry in git_index.read(raw):
                seen += 1
                when, precision, timing = normalise_ts(entry.mtime)
                yield self._event(
                    context,
                    f"path:{entry.path}",
                    {
                        "path": entry.path,
                        "mode": f"{entry.mode:06o}",
                        "executable": entry.executable,
                        "size": entry.size,
                        "object_id": entry.object_id,
                    },
                    when=when,
                    precision=precision,
                    # git's own stat cache, which is the filesystem's time for the file
                    # rather than a time the agent wrote down.
                    source="the modification time in git's stat cache",
                    note=timing,
                    text=entry.path,
                )
        except git_index.GitIndexError as error:
            yield self._file_note(
                context,
                f"this index stopped reading after {seen} entry(ies): {error}. What came "
                "out before it is in the case",
            )
            return
        if seen >= git_index.MAX_ENTRIES:
            yield self._file_note(context, INDEX_STOPPED.format(limit=git_index.MAX_ENTRIES))

    def _pathspec(self, context: ParseContext) -> Iterator[Event]:
        """The path list beside the index, one workspace path per line."""
        for line in text_lines(context.local_path):
            text = line.text.strip()
            if not text:
                continue
            yield self._event(
                context,
                line.locator,
                {"path": text},
                note=line.problem,
                text=text,
            )

    def _file_note(self, context: ParseContext, reason: str) -> Event:
        return unparsed(
            context.provenance("file"),
            context.agent,
            {"file": context.local_path.name, "bytes": _size(context)},
            reason,
            user=context.user,
            host=context.host,
        )

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
            yield from self._pack(context)
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

    def _pack(self, context: ParseContext) -> Iterator[Event]:
        """A pack file, expanded object by object, or one of the files derived from it.

        A repository that has been packed holds its objects here and nowhere else, so this
        is the same evidence as a loose object with one step in front of it. Every object
        becomes its own event, located by its byte offset in the pack, and an object that
        did not expand becomes an event too: the difference between a repository that held
        nothing and one whose objects this suite could not read is the whole point.
        """
        name = context.local_path.name
        if not name.endswith(".pack"):
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": name, "bytes": _size(context)},
                PACK_DERIVED,
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
            pack = git_pack.read(raw)
        except git_pack.GitPackError as error:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": name, "bytes": len(raw)},
                NOT_A_PACK.format(reason=error),
                user=context.user,
                host=context.host,
            )
            return
        for found in pack.objects:
            yield self._packed_object(context, found)
        if not pack.objects:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": name, "bytes": len(raw), "objects": pack.count},
                pack.stopped or EMPTY_PACK,
                user=context.user,
                host=context.host,
            )
            return
        if pack.stopped:
            # The walk ended before the pack's own count of objects. Reported as its own
            # record, because the objects that did come out are events of their own and an
            # analyst counting them has no other way to learn that the count is short.
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": name, "objects": pack.count, "read": len(pack.objects)},
                pack.stopped,
                user=context.user,
                host=context.host,
            )

    def _packed_object(self, context: ParseContext, found: git_pack.PackedObject) -> Event:
        """One object out of a pack, read as the object it is or reported as what stopped it."""
        locator = f"offset:{found.offset}"
        where: dict[str, Any] = {"pack_offset": found.offset}
        if found.depth:
            # How many deltas stand between this object and one stored whole. Carried
            # because it is the difference between bytes read out of the file and bytes
            # this suite computed, which an analyst reproducing the object needs.
            where["delta_depth"] = found.depth
        if found.base:
            where["delta_base"] = found.base
        if found.problem:
            return unparsed(
                context.provenance(locator),
                context.agent,
                {"type": found.kind, "bytes": len(found.body), **where},
                found.problem,
                user=context.user,
                host=context.host,
            )
        try:
            object_ = git_objects.interpret(found.kind, found.body)
        except git_objects.GitObjectError as error:
            return unparsed(
                context.provenance(locator),
                context.agent,
                {"object_id": found.object_id, "bytes": len(found.body), **where},
                NOT_THE_TYPE.format(kind=found.kind, reason=error),
                user=context.user,
                host=context.host,
            )
        return self._read_object(
            context, object_, found.object_id, locator=locator, note=FROM_A_PACK, extra=where
        )

    def _read_object(
        self,
        context: ParseContext,
        found: git_objects.GitObject,
        object_id: str | None,
        *,
        locator: str | None = None,
        note: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Event:
        """One object as an event, with the time a commit carries and the content a blob is."""
        record: dict[str, Any] = {"type": found.kind, "size": found.size}
        if object_id:
            record["object_id"] = object_id
        record.update(extra or {})
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
            content, unread = _blob_text(found.body)
            record["content"] = content
            if unread:
                record["problem"] = unread
            text = content

        return self._event(
            context,
            locator or (f"object:{object_id}" if object_id else "file"),
            record,
            when=when,
            precision=precision or "absent",
            source=source,
            note=" ".join(part for part in (timing, note) if part) or None,
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
    of it. Another documents `refs/hermes/<hash>`, where the segment is not a conversation
    but a project: the first sixteen characters of the sha256 of the absolute path of the
    working directory the snapshot was taken in. It is carried under its own name because
    it is not a session id and reading it as one would put a project into the case as a
    conversation. The store's own project index names the directory behind the hash, and
    this suite reads that file as a document of its own.

    Read positionally and only from those shapes: a reference under another layout keeps
    its name and claims nothing.
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
    elif len(parts) == 3 and parts[1] == "hermes" and _PROJECT_HASH.fullmatch(parts[2]):
        out["project_hash"] = parts[2]
    return out


__all__ = ["NO_CONTENT", "STORES", "GitCheckpointsParser"]
