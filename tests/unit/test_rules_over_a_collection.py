"""The packs, run over a whole synthetic collection rather than over their own samples.

Every rule carries its own tests and they are checked elsewhere. This file asks the other
question, and it is the one that was not being asked: given a collection of the shape a
real endpoint produces, does the rule fire?

The two are not the same, and the gap between them cost six rules. A sample is written by
whoever wrote the rule, in the shape they had in mind. A collection arrives in whatever
shape the file was in on disk, read by whatever parser claimed it, and for a settings file
that shape is a document nobody has mapped: the structure in `raw`, rendered by the text
views as `key = value` lines with no JSON quoting anywhere. Four rules were written against
events no collection produced, and two more against a serialisation the text views do not
use. All six passed their own samples and none of them could fire on a real case.

Three more arrived the same way and from one cause: the shell history was collected and
nothing read it, so every rule about a start line, an exported variable or a credential on
a command line had nothing to match in a collection while passing its own samples. The
parser for those four files closed it, and the three rules are held here.

Two more came from the copies an agent keeps of the files it changes. The credential in a
pre-edit copy of a settings file is written the way a settings file writes one, behind a
quote, and the rule expected a colon to follow the header name directly; the password in a
pasted configuration blob is named DATABASE_PASSWORD, and an underscore is a word character,
so the rule's leading word boundary put none between the prefix and the name. Both rules
passed their own samples throughout, because a sample is written by whoever wrote the rule.

So this is a floor under the packs: the fixture holds the evidence each of these rules is
about, and the rule has to find it. It is not a test of how many findings the fixture
produces, because that number changes whenever the fixture grows.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agentforensics.model import Case
from agentforensics.rules import load, scan

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import build_home  # noqa: E402

# One rule id per piece of evidence the synthetic profile carries on purpose, with the file
# that has to trigger it. A rule that stops firing here has gone blind to the shape a
# collection actually produces, which is the failure its own samples cannot catch.
EXPECTED = {
    "AFX-ANTIFORENSICS-001": "~/.claude/settings.json lowers cleanupPeriodDays below the default",
    "AFX-ANTIFORENSICS-002": "~/.zsh_history holds the export that stops the prompt history "
    "being written, and the captured shell environment holds it as a variable that was in "
    "force",
    "AFX-COLLECTIONINTEGRITY-001": "~/.zshrc exports the variable that moves the agent's "
    "whole configuration tree away from the path this very fixture writes it to",
    "AFX-COLLECTIONINTEGRITY-004": "the working copy is open in two editors at once, each "
    "with a per-workspace store under the same opaque directory name, and the file beside "
    "each store is what turns that name back into the folder both of them share",
    "AFX-ANTIFORENSICS-005": "~/.config/git/ignore carries the line the agent appended "
    "when it saved its first standing permission, which outlives every directory it owns",
    "AFX-DANGEROUSCOMMANDS-002": "a transcript holds a command that pipes a download into a shell",
    "AFX-EXFILINDICATORS-004": "~/.zsh_history holds a command that uploaded a named file",
    "AFX-PERMISSIONBYPASS-001": "~/.zsh_history holds the start line that skips the prompts",
    "AFX-PERMISSIONBYPASS-002": "a transcript holds a mid-session switch to an approval mode "
    "that stops asking",
    "AFX-PERMISSIONBYPASS-003": "~/.claude/settings.json allows Bash(*)",
    "AFX-PERMISSIONBYPASS-004": "an instruction file grants itself the right to run commands",
    "AFX-PERMISSIONBYPASS-005": "~/.cline/schedules/nightly-review.json runs in the mode that "
    "approves every tool",
    "AFX-PERMISSIONBYPASS-006": "~/.claude/settings.json starts sessions in acceptEdits",
    "AFX-PERMISSIONBYPASS-007": "~/.codex/config.toml disables the sandbox entirely",
    "AFX-PERMISSIONBYPASS-008": "~/.codex/config.toml also lets the sandbox reach the network",
    "AFX-PROMPTINJECTION-002": "a rules file carries invisible characters",
    "AFX-PROMPTINJECTION-003": "a project instruction file arrived with the work",
    "AFX-PROMPTINJECTION-004": "a memory holds a standing permission the user is never asked "
    "for again",
    "AFX-ANTIFORENSICS-003": "~/.zsh_history holds the agent's own purge subcommand, which "
    "names itself where the deletion beside it does not",
    "AFX-ANTIFORENSICS-004": "~/.zsh_history holds the same tidy-up done by hand, reaching the "
    "transcript store and the history file itself",
    "AFX-DANGEROUSCOMMANDS-001": "a transcript holds a recursive delete against an unset "
    "variable, which is the accident rather than a contrived rm of the root",
    "AFX-DANGEROUSCOMMANDS-003": "~/.zsh_history holds a force push and a hard reset, so the "
    "reflog on this machine is the only copy of what the remote held",
    "AFX-EXFILINDICATORS-001": "a transcript holds a tool call that posts to a public paste "
    "service",
    "AFX-EXFILINDICATORS-002": "the same call packs and encodes the two credential directories "
    "before sending them, which is the shape this rule is written for",
    "AFX-EXFILINDICATORS-003": "a transcript holds a tool call that adds a remote and pushes the "
    "whole repository to it",
    "AFX-SENSITIVEPATHS-001": "a transcript holds the agent reading a private key by name",
    "AFX-SENSITIVEPATHS-002": "and the cloud provider credential file beside it",
    "AFX-SENSITIVEPATHS-003": "and asking the platform keychain for a stored password",
    "AFX-COLLECTIONINTEGRITY-002": "~/.cursor/projects/ holds a zero byte file whose name is "
    "the date the product's own cleanup ran, which is what tells an absence apart from a "
    "deletion",
    "AFX-DATAVOLUME-001": "one transcript reads twenty-two files inside one minute, which no "
    "person does and no single tool call shows",
    "AFX-DATAVOLUME-002": "a tool result in the same transcript carries more text than anybody "
    "reads, which is what bulk leaving a device looks like from inside a conversation",
    "AFX-PROMPTINJECTION-001": "a tool result carries instruction-shaped text that arrived "
    "inside content the agent fetched, addressed to the model and telling it not to tell "
    "the user",
    "AFX-SECRETS-002": "a tool result carries a private key header, assembled by the "
    "generator rather than written into it, because this repository's own pre-commit hook "
    "refuses a file that holds one",
    "AFX-SECRETS-003": "the same transcript carries a model provider token in the contents of "
    "a file the agent read",
    "AFX-SECRETS-004": "and a source forge token beside it",
    "AFX-SECRETS-001": "a transcript holds a cloud provider access key",
    "AFX-SECRETS-005": "~/.claude/paste-cache holds the configuration somebody pasted "
    "instead of committing, with a password named the way a configuration file names one",
    "AFX-SECRETS-006": "~/.zsh_history holds a command that carried an API key as a flag",
    "AFX-SECRETS-008": "<project>/.worktreeinclude names the gitignored files the agent "
    "copies into every worktree it creates, and two of them are credentials",
    "AFX-SECRETS-007": "a wrapper function in the captured shell environment adds an "
    "authorization header the transcript never shows, and the pre-edit copy of a settings "
    "file holds the same header as JSON",
    "AFX-SUPPLYCHAIN-001": "~/src/app/.mcp.json starts a server through uvx",
    "AFX-SUPPLYCHAIN-002": "~/.claude/settings.json configures a PreToolUse hook",
    "AFX-SUPPLYCHAIN-003": "a hook script on the endpoint fetches code and runs it",
    "AFX-SUPPLYCHAIN-004": "~/.claude/settings.json names a command that produces the credential",
    "AFX-THIRDPARTYENDPOINTS-001": "~/.claude/settings.json points the model endpoint at a gateway",
    "AFX-THIRDPARTYENDPOINTS-002": "~/src/app/.mcp.json also configures a server that runs "
    "somewhere else",
}


# The other side of the table above, and it exists because the table above cannot say
# anything about what is missing from it. Twenty-nine rules fire over the profile and the
# rest do not, and until this was written nobody had to say which or why. A rule that
# quietly left EXPECTED would leave no trace, and a rule added to a pack with no evidence
# behind it would look exactly like a rule that is simply about something rare.
#
# Every entry here is a gap to close rather than a decision: the profile is the only place
# the whole chain runs at once, so a rule that never meets it is a rule tested against
# events somebody wrote by hand. AFX-COLLECTIONINTEGRITY-004 was in that state days ago,
# and when the evidence was finally put in front of it, two things between the catalogue
# and the parser turned out to be wrong.
SILENT = {
    "AFX-COLLECTIONINTEGRITY-003": "the profile carries no registry document, so the URL "
    "handler a product registers under the user's class keys is in no case this builds",
    "AFX-PERMISSIONBYPASS-009": "a policy under the user's own hive is a registry document, "
    "and the profile carries none. The Windows profile is where one would go",
}


@pytest.fixture(scope="module")
def case_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A case built from the synthetic profile, kept so a test can look at the events."""
    from agentforensics.catalog import load_catalogue
    from agentforensics.ingest import ingest

    home = tmp_path_factory.mktemp("profile")
    build_home(home, with_edge_cases=False)
    case_path = tmp_path_factory.mktemp("case") / "case.db"
    with Case.open(case_path) as case:
        ingest(case, home, load_catalogue(REPO_ROOT / "catalog"))
    return case_path


@pytest.fixture(scope="module")
def findings(case_file: Path) -> set[str]:
    """Every rule id that fired over a case built from the synthetic profile."""
    with Case.open(case_file) as case:
        report = scan(case, load(REPO_ROOT / "rules"), store=False)
    return {finding.rule.id for finding in report.findings}


@pytest.mark.slow
@pytest.mark.parametrize(("rule_id", "evidence"), sorted(EXPECTED.items()))
def test_the_rule_finds_the_evidence_the_profile_carries(
    findings: set[str], rule_id: str, evidence: str
) -> None:
    assert rule_id in findings, (
        f"{rule_id} did not fire, and the collection holds what it is about: {evidence}. "
        "A rule that passes its own samples and finds nothing in a collection is written "
        "against a shape no endpoint produces"
    )


@pytest.mark.slow
def test_a_settings_file_reaches_the_packs_as_a_configuration(findings: set[str]) -> None:
    """The four rules that could not fire at all before a settings file was read.

    All four answer questions about a configuration, and every one of those answers lives
    in a JSON document the suite collected and nothing read. Grouped into one assertion
    because they failed together and would fail together again: a change that stopped
    filing these documents as configuration would take all four out at once.
    """
    assert {
        "AFX-ANTIFORENSICS-001",
        "AFX-PERMISSIONBYPASS-003",
        "AFX-SUPPLYCHAIN-001",
        "AFX-SUPPLYCHAIN-002",
        "AFX-THIRDPARTYENDPOINTS-001",
    } <= findings


@pytest.mark.slow
def test_a_credential_is_recovered_from_a_pack_and_reaches_the_packs(case_file: Path) -> None:
    """The longest path in this suite, asserted end to end.

    The profile's shadow repository holds the version of a configuration file from before
    the agent took a credential out of it. After that edit the token is in no file on the
    endpoint and in no transcript. It is a difference against another object inside a pack
    file in the agent's own repository, and a case either recovers it from there or does
    not have it at all.

    So this asks for the finding and then asks what it rests on: a file snapshot located by
    a byte offset in a pack, whose content this suite computed by applying a delta. Every
    piece of that is tested on its own. What this holds together is the whole of it, which
    is the sentence a report would make: the agent removed a credential, and here is the
    file as it stood before.
    """
    import json

    with Case.open(case_file) as case:
        report = scan(case, load(REPO_ROOT / "rules"), store=False)
        out_of_a_pack = []
        for finding in report.findings:
            if not finding.rule.id.startswith("AFX-SECRETS-"):
                continue
            for event_id in finding.event_ids:
                rows = case.query(
                    "SELECT locator, raw FROM events WHERE event_id = ? AND kind = 'file.snapshot'",
                    (event_id,),
                )
                for row in rows:
                    raw = json.loads(row["raw"])
                    if raw.get("pack_offset") is not None:
                        out_of_a_pack.append((finding.rule.id, row["locator"], raw))

    assert out_of_a_pack, (
        "no secrets rule rests on an object out of a pack, so the one copy of that "
        "credential on the endpoint is in the case as a file nobody read"
    )
    _, locator, raw = out_of_a_pack[0]
    assert locator.startswith("offset:")
    assert raw["type"] == "blob"
    # Computed rather than read: the pre-edit version is stored as a difference against the
    # version that replaced it, so a reader that stopped at loose objects had nothing here.
    assert raw["delta_depth"] >= 1
    assert "sk_live_examplekey0123456789" in raw["content"]


@pytest.mark.slow
def test_every_rule_is_either_exercised_here_or_declared_unexercised() -> None:
    """Neither table says anything on its own; together they have to cover every rule.

    Without this, a rule can be added to a pack, pass its own samples, and never meet a
    collection, and nothing in the suite says so. That is the state AFX-COLLECTIONINTEGRITY-004
    was in, and putting the evidence in front of it found two defects between the catalogue
    and the parser that its own samples could not have caught.

    So a new rule has to be put in one table or the other, and the entry in the second one
    is a sentence saying what the profile would need to carry. That sentence is the work
    item.
    """
    shipped = {rule.id for rule in load(REPO_ROOT / "rules")}
    covered = set(EXPECTED) | set(SILENT)
    assert shipped - covered == set(), (
        "these rules are neither exercised over the synthetic profile nor declared as not "
        f"exercised, so nothing says whether they can fire at all: {sorted(shipped - covered)}"
    )
    assert covered - shipped == set(), (
        f"these table entries name rules that no longer exist: {sorted(covered - shipped)}"
    )
    assert set(EXPECTED) & set(SILENT) == set(), "a rule cannot be in both tables"


@pytest.mark.slow
def test_a_rule_declared_unexercised_really_does_not_fire(findings: set[str]) -> None:
    """The table has to stay honest in the other direction too.

    A rule listed as unexercised that has started firing is good news and a stale reason:
    the profile grew the evidence, somebody should say so in EXPECTED, and the sentence
    explaining what the profile lacks is now wrong.
    """
    started = sorted(rule_id for rule_id in SILENT if rule_id in findings)
    assert not started, (
        "these rules are declared as not exercised by the synthetic profile and they fired "
        f"over it, so the profile now holds what they are about: {started}. Move them to "
        "EXPECTED with the evidence named"
    )
