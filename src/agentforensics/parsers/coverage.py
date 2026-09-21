"""What this suite reads, and what it does not read on purpose.

The readers themselves are one module per format family. This is the other half of the
answer: which catalogue entries no reader claims, and why each of those is a decision
somebody made rather than work nobody got round to. Two consumers need it and they need the
same list, which is why it is here rather than in a test: the test that holds it against
the catalogue, and the generator behind docs/SUPPORT.md, which is the page somebody reads
before deciding whether an empty result means anything.

A gap is one of five things, and the difference is the point:

  * a format nobody has a reader for, which for this catalogue is a binary or a directory
    container with no documented layout. Counted, never excused: the entry is still
    collected and still on the timeline as one filesystem event.
  * a credential store, where the collector takes metadata and a hash and no content by
    design, so there is nothing for a reader to read.
  * an entry in a format this suite does read, claimed by no reader, with a reason written
    down below. That is the list that has to stay short and has to stay true.
  * an entry handed to a better reader, where the file is in the bundle whole and the
    tool that should parse it is named rather than reimplemented.
  * unfinished work, which is the one thing this file must never quietly become. An entry
    in a readable format with no reason here fails the test in tests/unit/test_parsers.py,
    so it cannot sit in the catalogue unremarked.

There is one more list at the bottom, and it is a different question. The four above ask
whether an entry is read; UNFINISHED asks whether it is read completely, which is the answer
somebody needs before quoting a case. An entry can be read, appear nowhere in the lists
above, and still have a piece of its format that nobody has mapped, and that is worth a
sentence rather than a reader's silence.
"""

from __future__ import annotations

from dataclasses import dataclass


# A file this suite can read, in the catalogue, that nothing reads. Each one is a decision
# somebody made and wrote down; the test in tests/unit/test_parsers.py fails on any that is
# not here, so the question "why does nothing read this" always has an answer next to it.
#
# Not listed, and not needing to be: every entry whose sensitivity is secret. The collector
# records those by metadata and hash and does not copy the content unless it is told to, so
# there is nothing for a parser to read and a list of them would be a list of the same
# sentence twenty-six times.
@dataclass(frozen=True)
class Excused:
    """Why one readable entry is read by nothing, and what carries its evidence instead.

    Most of these reasons say the evidence is somewhere else in the catalogue. That is a
    claim about another entry, written once, and this project keeps finding out the hard
    way what happens to those: the last line of the last reason here said nothing in this
    suite reads the registry, which stopped being true the week the registry reader was
    written, in a commit that corrected the same sentence in eight other places and did not
    look in a test. So the entries a reason leans on are named rather than described, and
    the test holds them to being in the catalogue and being read.
    """

    reason: str
    # The entries that carry this one's evidence, if that is the reason. Each one has to be
    # in the catalogue and has to be read by something, or the reason has outlived its
    # truth and somebody has to look at this entry again.
    covered_by: tuple[str, ...] = ()


READABLE_AND_UNREAD = {
    "cline.extension_id": Excused(
        "the entry is the extension's storage directory, and what is under it is claimed "
        "by the entries for the task tree and the checkpoints. The id itself is the "
        "evidence and it is in the path, which the artifact event carries",
        ("cline.vscode_task_transcripts", "cline.checkpoints_shadow_git_legacy"),
    ),
    "crosscutting.homebrew_prefixes": Excused(
        "an installation prefix, so the evidence is which directories exist under it "
        "rather than what any one file says"
    ),
    "crosscutting.uv_tool_dir": Excused(
        "declared and deliberately not read by the reader for this format, which says why "
        "in its own module: the manifests here describe the installer's own bookkeeping "
        "rather than an agent's activity"
    ),
    "jetbrains_ai.base_directories": Excused(
        "the entry is the product's directory layout, which is what makes the other "
        "entries for this family resolvable. The files under it are claimed by those",
        ("jetbrains_ai.aia_task_history", "jetbrains_ai.mcp_config", "jetbrains_ai.ide_logs"),
    ),
    "roo_code.extension_id": Excused(
        "the same shape as the other extension id entry above",
        ("roo_code.tasks", "roo_code.checkpoints"),
    ),
    "windsurf.enterprise_policy_templates": Excused(
        "group-policy templates, which are XML and say which settings exist rather than "
        "which were set. What was set is in the registry key of the entry beside this "
        "one, which a Windows collection carries as a document and this suite reads",
        ("windsurf.enterprise_policy",),
    ),
}

# The entries this suite collects and deliberately does not parse, because a better reader
# for that format already exists and is the one an examiner will be asked about in court.
# Each is a decision with a name attached rather than a gap: the file or the key is in the
# bundle whole, and the entry's own notes say which tool reads it.
#
# It is a table rather than a catalogue field because it is a statement about this suite and
# not about the artifact. The test in tests/unit/test_parsers.py holds every id here to being
# in the catalogue and to having no reader, so a reader written later cannot leave a stale
# excuse behind.
HANDED_OVER = {
    "crosscutting.windows_execution_evidence_files": (
        "the platform's own record that a binary ran: Amcache, Prefetch, SRUM and the "
        "scheduled-task XML. Collected whole and handed to the tools written for those "
        "formats, AmcacheParser, PECmd and SrumECmd, which are better than anything this "
        "project would write and are what a report will be challenged on"
    ),
    "crosscutting.windows_execution_evidence_registry": (
        "ShimCache, BAM and UserAssist. Registry keys, so only the PowerShell collector "
        "can reach them and only on the host itself, and the parsers for them are the "
        "established ones. UserAssist in particular records GUI launches and not command "
        "lines, which is how every agent here is started, so an empty result from it says "
        "nothing and the entry says so"
    ),
    "crosscutting.windows_removed_product_registry": (
        "the generic uninstall keys a removed product leaves behind. Declined by name "
        "rather than read, because the per-product protocol handlers that also survive an "
        "uninstall are separate entries and those are read as documents"
    ),
    "crosscutting.macos_launch_services_registrations": (
        "the registration database that still names an application after everything else "
        "has been cleaned. Its own reader is the system's registration tool, which this "
        "suite does not run because it runs nothing on the endpoint, so the file is "
        "collected and read afterwards"
    ),
    "cursor.install_and_machine_identity": (
        "an uninstall key under a product GUID, which is not globbable and is declined by "
        "name. The filesystem half of the same install evidence is read under its own "
        "entries"
    ),
}


# The readers that read a file completely and interpret its records as far as nobody has
# mapped them, which is not the same thing as reading the file. A document split by
# structure one level deep, a database row returned with its columns, a log line returned
# as a line: the content is in the case, and what it means is not decided. Named here
# because the difference is what an analyst needs before quoting a case, and because the
# generated support page has to be able to say it per agent rather than leaving a reader
# to infer completeness from the word "read".
#
# A reader for one product's own format is not in this set even when it leaves single
# fields unmapped: it knows what a record is. Nor is structured_generic, which is the
# shared code behind the four document readers above rather than a reader that ships.
# The test in tests/unit/test_parsers.py holds every name here to being one that does.
GENERIC_READERS = frozenset(
    {
        "json_generic",
        "jsonl_generic",
        "leveldb_store",
        "lmdb_generic",
        "plist_generic",
        "prose_document",
        "sqlite_generic",
        "text_log",
        "toml_generic",
        "yaml_generic",
    }
)


# The formats this suite has a reader for. A catalogue entry in one of these and claimed by
# nobody is the case worth catching: the others need format work and the filesystem event
# is the honest answer for them until somebody does it.
READABLE_FORMATS = frozenset(
    {"json", "jsonl", "leveldb", "lmdb", "markdown", "plist", "sqlite", "text", "toml", "yaml"}
)


# The readings somebody started and did not finish, each saying what is missing. Everything
# above is a decision and this is a list of work, which is why it is separate: a reader of
# the support page asking "is this agent covered" and a reader asking "what is left to do"
# want different answers out of the same fact, and an entry here can be in both places.
#
# What belongs here is narrow on purpose. Not an entry a generic reader reads, because that
# is true of nearly three hundred of them and the page counts those as a class. Not an entry
# nobody has a format for, because that is the group above. This is for a file whose format
# somebody has already described, in the entry or in a reader, where the described part is
# not the part being read.
#
# The test in tests/unit/test_parsers.py holds every id here to being in the catalogue, so a
# renamed or deleted entry takes its promise with it rather than leaving the page making a
# commitment about a file that is gone.
# Empty, and the table stays rather than going with its last entry. It is the only place a
# sentence of this kind may live, so an empty one is the statement that nobody currently
# owes this catalogue a reading, and the next person who defers one has somewhere to say so
# instead of leaving it in a note nobody generates a page from. Both entries it held were
# closed by writing the readers rather than by deleting the promise.
UNFINISHED: dict[str, str] = {}


__all__ = ["READABLE_AND_UNREAD", "READABLE_FORMATS", "UNFINISHED", "Excused"]
