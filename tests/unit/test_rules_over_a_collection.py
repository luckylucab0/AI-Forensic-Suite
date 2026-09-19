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


@pytest.fixture(scope="module")
def findings(tmp_path_factory: pytest.TempPathFactory) -> set[str]:
    """Every rule id that fired over a case built from the synthetic profile."""
    from agentforensics.catalog import load_catalogue
    from agentforensics.ingest import ingest

    home = tmp_path_factory.mktemp("profile")
    build_home(home, with_edge_cases=False)
    case_path = tmp_path_factory.mktemp("case") / "case.db"
    catalogue = load_catalogue(REPO_ROOT / "catalog")
    with Case.open(case_path) as case:
        ingest(case, home, catalogue)
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
