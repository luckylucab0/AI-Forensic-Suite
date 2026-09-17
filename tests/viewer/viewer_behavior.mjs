/**
 * Behavioral tests for the viewer's pure logic, run without a browser.
 *
 * The viewer is deliberately one self-contained HTML file (ADR 0001), so its functions
 * cannot be imported. Instead this harness extracts the script block, cuts it at the boot
 * marker so nothing touches the DOM, and evaluates the rest in a vm context. What is left
 * is the parsing, normalization and summarization logic, which is exactly the part where a
 * regression loses evidence.
 *
 * Most of what is asserted here is ADR 0009: no record is ever dropped, truncated or
 * hidden. Those are easy properties to break by accident and impossible to notice by
 * looking at a rendered transcript, because the symptom is an absence.
 *
 * Run through pytest (tests/unit/test_viewer_behavior.py), or directly:
 *     node tests/viewer/viewer_behavior.mjs
 */

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const VIEWER = path.join('viewer', 'index.html');
const BOOT_MARKER = '// ---------- boot ----------';

const html = fs.readFileSync(VIEWER, 'utf8');
const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
if (blocks.length === 0) throw new Error('no script block in ' + VIEWER);

let code = blocks[blocks.length - 1];
const bootAt = code.indexOf(BOOT_MARKER);
if (bootAt < 0) throw new Error('boot marker not found; update BOOT_MARKER in this harness');
code = code.slice(0, bootAt);

// The only globals the pre-boot code touches. `document` is referenced inside function
// bodies we do not call, so it stays absent on purpose: if a change starts touching the
// DOM during parsing, this harness fails loudly rather than quietly passing.
const ctx = {
  window: {},
  console,
  URL,
  TextEncoder,
  JSON,
  Math,
  Object,
  Array,
  String,
  Number,
  Boolean,
  Set,
  Map,
  Promise,
  RegExp,
  Error,
  Date,
};
vm.createContext(ctx);

// Appended to the same script so the lexical bindings above are in scope. `setSource` can
// assign to the `dataSource` binding because it closes over it.
vm.runInContext(
  code +
    `
;globalThis.__api = {
  normalizeCodex, normalizeCopilot, normalizeEvents, summarize, buildTimeline,
  relPath, toolSummary, scanSecrets, fetchEvents, state, decodeProjectName,
  clientInfo, blocksToText, buildToolResultMap,
  normalizeUnified, groupUnified, unifiedEvent, unifiedDerived, assistantNameFor,
};
globalThis.__setSource = (s) => { dataSource = s; };
`,
  ctx,
);

const api = ctx.__api;
const setSource = ctx.__setSource;

let failures = 0;
let checks = 0;

function ok(cond, what) {
  checks += 1;
  if (!cond) {
    failures += 1;
    console.error('FAIL: ' + what);
  }
}

function eq(actual, expected, what) {
  checks += 1;
  if (actual !== expected) {
    failures += 1;
    console.error('FAIL: ' + what + '\n  expected: ' + expected + '\n  actual:   ' + actual);
  }
}

// ---------------------------------------------------------------- ADR 0009, fetchEvents

{
  const long = 'x'.repeat(5000);
  const lines = [
    JSON.stringify({ type: 'user', message: { content: 'hello' } }),
    '{ this is not json ' + long,
    '42',
    '',
    JSON.stringify({ type: 'assistant', message: { id: 'a1', content: [] } }),
  ].join('\n');
  setSource({ kind: 'test', async listDir() { return []; }, async readText() { return lines; } });
  const events = await api.fetchEvents('test://one');

  eq(events.length, 4, 'blank lines are skipped, every other line produces a record');
  eq(events[1].type, 'parse-error', 'a malformed line becomes a parse-error record');
  eq(events[1].__line, 2, 'a parse-error carries its 1-based line number');
  ok(
    events[1].raw.length > 4000,
    'a malformed line is kept in full, never truncated (the old code cut it at 2000 chars)',
  );
  eq(events[2].type, 'unstructured-record', 'a bare JSON scalar gets its own record kind');
  eq(events[2].__line, 3, 'an unstructured record carries its line number');
  eq(events[0].__line, 1, 'a parsed record is annotated with its line number');
  eq(events[3].__line, 5, 'line numbers count blank lines, so they match the file');
}

// ------------------------------------------------------------------ ADR 0009, summarize

{
  const events = [
    { type: 'user', message: { content: 'what is this' }, timestamp: '2026-01-01T00:00:00Z' },
    { type: 'parse-error', raw: 'broken', __line: 2 },
    { type: 'unstructured-record', raw: '7', __line: 3 },
    { type: 'assistant', message: { id: 'a', role: 'assistant', content: [{ type: 'text', text: 'hi' }] } },
  ];
  const s = api.summarize(events);
  eq(s.unparsed, 2, 'summarize counts unparsed and unstructured records');
  eq(s.userMsgs, 1, 'an unparsed record is not miscounted as a user message');
  eq(s.title, 'what is this', 'the title still falls back to the first human prompt');
}

// ---------------------------------------------------------------- ADR 0009, Codex parser

{
  const raw = [
    { timestamp: '2026-01-01T00:00:00Z', type: 'session_meta', payload: { cwd: '/w', cli_version: '1.2.3' } },
    { timestamp: '2026-01-01T00:00:01Z', type: 'compacted', payload: { message: 'summarised' } },
    { timestamp: '2026-01-01T00:00:02Z', type: 'event_msg', payload: { type: 'agent_message' } },
    { timestamp: '2026-01-01T00:00:03Z', type: 'event_msg', payload: { type: 'agent_message' } },
    { timestamp: '2026-01-01T00:00:04Z', type: 'event_msg', payload: { type: 'token_count' } },
    { timestamp: '2026-01-01T00:00:05Z', type: 'brand_new_record_type', payload: { a: 1 } },
    { timestamp: '2026-01-01T00:00:06Z', type: 'response_item', payload: { type: 'message', role: 'user', content: 'hi' } },
    { timestamp: '2026-01-01T00:00:07Z', type: 'response_item', payload: { type: 'brand_new_item_kind', x: 2 } },
  ];
  const out = api.normalizeCodex(raw);
  const systems = out.filter((e) => e.type === 'system').map((e) => e.content);
  const unknown = out.filter((e) => e.type === 'unknown-record');

  ok(
    systems.some((c) => c.startsWith('context compacted')),
    'a compacted record is surfaced, because it explains a gap in a transcript',
  );
  ok(
    systems.some((c) => c.includes('event_msg record') && c.includes('agent_message x2')),
    'event_msg records are tallied and reported rather than silently skipped',
  );
  ok(
    unknown.some((e) => e.recordType === 'brand_new_record_type'),
    'an unknown top-level record type is preserved as unknown-record',
  );
  ok(
    unknown.some((e) => e.recordType === 'response_item/brand_new_item_kind'),
    'an unknown response_item kind is preserved as unknown-record',
  );
  eq(out[0].type, 'meta', 'the synthetic meta event is still prepended');
  eq(out[0].version, '1.2.3', 'session metadata is still picked up from session_meta');
}

// -------------------------------------------------------------- ADR 0009, Copilot parser

{
  const raw = [
    { type: 'session.start', timestamp: '2026-01-01T00:00:00Z', data: { copilotVersion: '9.9.9' } },
    { type: 'user.message', timestamp: '2026-01-01T00:00:01Z', data: { content: 'go' } },
    { type: 'some.future.event', timestamp: '2026-01-01T00:00:02Z', data: { detail: 'kept' } },
  ];
  const out = api.normalizeCopilot(raw);
  const unknown = out.filter((e) => e.type === 'unknown-record');
  eq(unknown.length, 1, 'an unknown Copilot event type is preserved, not swallowed by default');
  eq(unknown[0].recordType, 'some.future.event', 'the unknown event keeps its type');
  ok(unknown[0].raw && unknown[0].raw.data.detail === 'kept', 'the original record is kept');
}

// ------------------------------------------------------- ADR 0009, id-less assistant turn

{
  const events = [
    { type: 'assistant', message: { id: 'a1', content: [{ type: 'text', text: 'one' }] } },
    { type: 'assistant', message: { id: 'a1', content: [{ type: 'text', text: 'still one' }] } },
    { type: 'assistant', message: { content: [{ type: 'text', text: 'no id at all' }] } },
    { type: 'user', message: { content: 'next' } },
  ];
  const items = api.buildTimeline(events);
  const turns = items.filter((i) => i.kind === 'assistant');
  eq(turns.length, 2, 'two assistant turns: one grouped by id, one for the id-less record');
  eq(turns[0].events.length, 2, 'records sharing a message.id are grouped into one turn');
  eq(turns[1].events.length, 1, 'an id-less assistant record gets a turn of its own');
  ok(
    !items.some((i) => i.kind === 'event' && i.event.type === 'assistant'),
    'no assistant record falls through to renderEvent, where it used to vanish',
  );
}

// ----------------------------------------------- cross-session tool summaries use the
// ----------------------------------------------- owning session's cwd, not the open one

{
  eq(api.relPath('/home/alice/proj/a.py', '/home/alice/proj'), 'a.py', 'relPath strips the given cwd');
  eq(
    api.relPath('/home/bob/other/a.py', '/home/alice/proj'),
    '/home/bob/other/a.py',
    'a path outside the given cwd is left absolute rather than mangled',
  );
  eq(api.relPath('/x/y.py', undefined), '/x/y.py', 'no cwd means no shortening');
  eq(
    api.toolSummary('Read', { file_path: '/home/alice/proj/a.py' }, '/home/alice/proj'),
    'a.py',
    'toolSummary relativizes against the cwd it is given',
  );
  // The regression: state.current belongs to whichever session the analyst has open, so
  // reading it here produced a path that never existed on the endpoint.
  api.state.current = { summary: { cwd: '/completely/different' } };
  eq(
    api.toolSummary('Read', { file_path: '/home/alice/proj/a.py' }, '/home/alice/proj'),
    'a.py',
    'toolSummary ignores the currently open session',
  );
  api.state.current = null;
}

// ------------------------------------------------------------------------ secret scanner

{
  const hits = api.scanSecrets('export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');
  ok(hits.some((h) => h.rule === 'AWS access key'), 'the AWS access key rule still fires');
  eq(api.scanSecrets('').length, 0, 'empty input produces no findings');
  eq(api.scanSecrets('nothing interesting here').length, 0, 'plain text produces no findings');
}

// ------------------------------------------------------- documented parsing limitations

{
  // Not a bug to fix here, a property to pin: the project directory encoding is not
  // reversible, so the decoded name is a label and the in-record cwd is authoritative.
  // See ADR 0003 and the comment on decodeProjectName.
  eq(
    api.decodeProjectName('-home-alice-src-my-project'),
    '/home/alice/src/my/project',
    'decodeProjectName is lossy on hyphens, which is why cwd from the records wins',
  );
  eq(api.clientInfo('cli').label, 'Claude Code · CLI', 'the entrypoint map still resolves');
  eq(api.clientInfo('something-new').label, 'something-new', 'an unknown entrypoint shows verbatim');
}

// ------------------------------------------------- the unified agent log, ADR 0018
//
// The format is the one thing several producers share, so a viewer that read it loosely
// would make two collections of the same host look different. What is pinned here is the
// mapping onto the viewer's own event shape, and above all that nothing in a unified log
// can fail to appear on screen.
{
  const provenance = (locator) => ({
    bundle_uuid: 'b1',
    original_path: '/home/alice/.claude/projects/-src-app/s1.jsonl',
    sha256: 'aa',
    artifact_id: 'claude_code.transcripts',
    locator,
  });
  const record = (kind, extra = {}) => ({
    v: 1,
    agent: 'claude_code',
    kind,
    ts_utc: '2026-09-06T09:00:00.000Z',
    ts_precision: 'exact',
    actor: 'assistant',
    user: 'alice',
    session_id: 's1',
    project_path: '/src/app',
    payload: {},
    provenance: provenance('line:1'),
    raw: {},
    ...extra,
  });

  const conversation = api.normalizeUnified([
    record('session.start', { actor: 'system', client: 'cli' }),
    record('user.prompt', { actor: 'user', payload: { text: 'check the lockfile' } }),
    record('assistant.thinking', { payload: { text: 'read it first', models: [{ model: 'm1' }] } }),
    record('assistant.text', { payload: { text: 'here it is', message_id: 'msg_1' } }),
    record('tool.call', {
      payload: { tool: 'Bash', tool_use_id: 't1', input: { command: 'npm ci' } },
      provenance: provenance('line:5#tool0'),
    }),
    record('command.exec', {
      payload: { commands: [{ command: 'npm ci' }] },
      provenance: provenance('line:5#effect0'),
    }),
    record('tool.result', { actor: 'tool', payload: { tool_use_id: 't1', output: 'ok' } }),
    record('safety.refusal', { payload: { refusal: 'example_policy', text: 'I cannot.' } }),
    record('permission.change', {
      payload: { permissions: [{ mode: 'acceptEdits', previous: 'default', scope: 'session' }] },
    }),
    record('unparsed.record', { parse_problem: 'not valid JSON', raw: '{"broken' }),
    record('some.future.kind'),
  ]);

  const kinds = conversation.map((e) => e.type);
  eq(kinds[0], 'meta', 'a unified session begins with the synthetic meta row');
  ok(kinds.includes('user'), 'a unified prompt becomes a user turn');
  ok(kinds.includes('assistant'), 'a unified assistant turn becomes an assistant turn');

  const summary = api.summarize(conversation);
  eq(summary.cwd, '/src/app', 'the working directory reaches the session header');
  eq(summary.userMsgs, 1, 'the prompt is counted once');
  eq(summary.toolCalls, 1, 'the tool call is counted once');

  // The analyzer emits a tool call and a second event for what the call touched, both from
  // one line. Showing both would report every command twice.
  const commandRows = conversation.filter(
    (e) => e.type === 'system' && String(e.content || '').startsWith('command:'),
  );
  eq(commandRows.length, 0, 'an effect event from the same record as its call is not shown twice');

  // The same effect without a matching call is a producer that emitted only the effect, and
  // then it is the only evidence there is of that command.
  const effectOnly = api.normalizeUnified([
    record('command.exec', {
      payload: { commands: [{ command: 'rm -rf /tmp/x' }] },
      provenance: provenance('line:9#effect0'),
    }),
  ]);
  ok(
    effectOnly.some((e) => String(e.content || '').includes('rm -rf /tmp/x')),
    'an effect with no matching call is shown, because nothing else carries that command',
  );

  const tools = api.buildToolResultMap(conversation);
  ok(tools.t1 && tools.t1.block.content === 'ok', 'a tool result is joined to its call by id');

  const refusal = conversation.find((e) => String(e.content || '').includes('refused'));
  ok(refusal, 'a refusal is a row of its own, not a field nobody reads');
  ok(String(refusal.content).includes('example_policy'), 'the refusal carries its category');

  const permission = conversation.find((e) =>
    String(e.content || '').includes('permission mode changed'),
  );
  ok(permission, 'a permission change is visible, because the bypass question turns on it');
  ok(String(permission.content).includes('acceptEdits'), 'and it names the new mode');

  // ADR 0009 carried into this format. Both of these are absences by default, so they are
  // the two that have to be asserted.
  const unreadable = conversation.filter((e) => e.type === 'unknown-record');
  eq(unreadable.length, 2, 'an unreadable record and an unknown kind are both kept');
  ok(
    unreadable.some((e) => e.raw === '{"broken'),
    'an unreadable record keeps the original text the producer could not read',
  );
  ok(
    unreadable.some((e) => String(e.recordType).includes('some.future.kind')),
    'a kind from a newer producer is named rather than swallowed',
  );

  eq(
    conversation.length,
    11,
    'every record but the suppressed duplicate produced a row, and the meta row was added',
  );

  // The model is announced once and applies to what follows.
  const withModel = conversation.find((e) => e.type === 'assistant' && e.message.model);
  eq(withModel.message.model, 'm1', 'the model is carried forward from the record that named it');

  // A unified log can hold several agents at once, which is what a fleet hunt returns.
  const mixed = [
    record('user.prompt', { agent: 'claude_code', payload: { text: 'a' } }),
    record('user.prompt', { agent: 'codex', session_id: 's2', payload: { text: 'b' } }),
    record('artifact.fs', {
      agent: 'cline',
      session_id: null,
      kind: 'artifact.fs',
      payload: { files: [{ path: '/home/alice/.cline/tasks/x.json' }] },
    }),
  ];
  const groups = api.groupUnified(mixed);
  eq(Object.keys(groups).length, 3, 'agents and sessions are grouped apart');
  ok(
    Object.values(groups).some((g) => g.name.includes('files on disk')),
    'a file nobody parsed gets a group of its own rather than disappearing',
  );

  eq(
    api.assistantNameFor('unified', 'codex'),
    'Codex',
    'the header names the agent the records came from, not the source format',
  );
  eq(
    api.assistantNameFor('unified', 'some_new_agent'),
    'some_new_agent',
    'an agent nobody has a label for keeps its own name',
  );
}

// --------------------------------- a real log, end to end, when one has been produced
//
// The checks above use records written by hand, which proves the mapping and not the
// interface. AFX_UNIFIED_LOG points at a log this repository's own normalizer produced
// from the synthetic profile, so this asserts that the two ends of the format actually
// meet. Skipped when the variable is unset, so running this harness by hand still works.
if (process.env.AFX_UNIFIED_LOG) {
  const text = fs.readFileSync(process.env.AFX_UNIFIED_LOG, 'utf8');
  const records = text
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
  ok(records.length > 0, 'the generated log has records in it');

  const groups = api.groupUnified(records);
  ok(Object.keys(groups).length > 0, 'a real log groups into at least one project');

  let rows = 0;
  let placed = 0;
  for (const key of Object.keys(groups)) {
    for (const sid of Object.keys(groups[key].sessions)) {
      const session = groups[key].sessions[sid];
      placed += session.length;
      // One meta row is added per session and is not a record, so it is not counted.
      rows += api.normalizeUnified(session).length - 1;
    }
  }
  eq(placed, records.length, 'every record of a real log is placed in some session');
  // Fewer rows than records is only allowed for the duplicate-view case, where an effect
  // event and the tool call it came from share a line. Anything larger would mean records
  // vanishing between the log and the screen.
  const suppressed = records.filter(
    (r) =>
      ['command.exec', 'file.read', 'file.write', 'file.snapshot', 'network.request'].includes(
        r.kind,
      ) && String((r.provenance || {}).locator || '').includes('#'),
  ).length;
  eq(
    rows,
    records.length - suppressed,
    'every record of a real log produces a row, except an effect shown by its own tool call',
  );

  const agents = new Set(records.map((r) => r.agent));
  ok(agents.size >= 3, 'the generated log carries several agents, as a collection would');
  ok(
    records.some((r) => r.kind === 'unparsed.record'),
    'and it carries a record nothing could read, which the viewer has to show',
  );
}

console.error(
  (failures === 0 ? 'viewer behavior: ' : 'viewer behavior FAILED: ') +
    (checks - failures) +
    '/' +
    checks +
    ' checks passed',
);
process.exit(failures === 0 ? 0 : 1);
