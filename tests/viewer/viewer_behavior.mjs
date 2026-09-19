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
  // The case API source reads these two. Left as the harmless defaults and overwritten per
  // test, because the tests that matter here are the ones about what happens when a server
  // answers badly: a short page, a seam between pages, an offset that does not advance.
  location: { protocol: 'file:' },
  fetch: undefined,
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
  apiSource, probeCaseApi, findCaseSession, artifactState, CASE_API_VERSION, tailPath,
  filterToolRows, filterFindingRows, filterTimelineItems, turnKinds, scopePath, buildTimeline,
  windowBound, timeWindow, inWindow, itemTime, sessionMarks, findingSessions,
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

// ------------------------------------------------------------------------ filters

{
  const rows = [
    { name: 'Bash', summary: 'npm ci', project: 'p1', path: 's1', isErr: false },
    { name: 'Bash', summary: 'rm -rf build', project: 'p1', path: 's2', isErr: true },
    { name: 'Read', summary: '/home/alice/.ssh/id_rsa', project: 'p2', path: 's1', isErr: false },
  ];
  eq(api.filterToolRows(rows, {}).length, 3, 'no filter keeps every tool call');
  eq(api.filterToolRows(rows, { path: 's1' }).length, 2, 'a scope keeps only its own session');
  eq(api.filterToolRows(rows, { name: 'Bash' }).length, 2, 'a name filter keeps that tool');
  eq(api.filterToolRows(rows, { name: 'all' }).length, 3, "the name 'all' is not a tool name");
  eq(api.filterToolRows(rows, { errOnly: true }).length, 1, 'failed only keeps the failures');
  eq(
    api.filterToolRows(rows, { query: '.SSH' }).length,
    1,
    'the text filter is case-insensitive and searches the summary',
  );
  eq(
    api.filterToolRows(rows, { path: 's1', name: 'Bash', query: 'npm' }).length,
    1,
    'the filters combine rather than replacing each other',
  );
  eq(
    api.filterToolRows(rows, { path: 's2', errOnly: true, name: 'Read' }).length,
    0,
    'and an impossible combination returns nothing rather than falling back to everything',
  );
}

{
  const found = [
    { rule: 'AWS access key', sev: 'high', path: 's1' },
    { rule: 'JWT', sev: 'med', path: 's1' },
    { rule: 'JWT', sev: 'med', path: 's2' },
  ];
  eq(api.filterFindingRows(found, {}).length, 3, 'no filter keeps every finding');
  eq(api.filterFindingRows(found, { path: 's1' }).length, 2, 'a scope keeps its own session');
  eq(api.filterFindingRows(found, { sev: 'high' }).length, 1, 'a severity filter works');
  eq(api.filterFindingRows(found, { rule: 'JWT' }).length, 2, 'a rule filter works');
  eq(
    api.filterFindingRows(found, { sev: 'all', rule: 'all' }).length,
    3,
    "'all' means all for both",
  );
}

{
  // What one transcript row counts as. The assistant turn is the interesting case: it is
  // one row holding several kinds, and the filter keeps whole turns.
  const events = [
    { type: 'user', message: { content: 'do the thing' } },
    {
      type: 'assistant',
      message: {
        id: 'a1',
        content: [
          { type: 'thinking', thinking: 'plan' },
          { type: 'text', text: 'doing it' },
          { type: 'tool_use', id: 't1', name: 'Bash', input: { command: 'ls' } },
        ],
      },
    },
    { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 't1', content: 'ok' }] } },
    { type: 'parse-error', raw: 'broken', __line: 9 },
  ];
  const items = api.buildTimeline(events);
  eq(items.length, 4, 'the timeline groups the assistant records into one turn');
  const kinds = items.map((item) => api.turnKinds(item));
  ok(kinds[0].includes('prompts'), 'a typed message is a prompt');
  ok(
    kinds[1].includes('tools') && kinds[1].includes('thinking') && kinds[1].includes('answers'),
    'one assistant turn can be all three at once, so a filter on any of them keeps it',
  );
  ok(
    kinds[2].includes('tools') && !kinds[2].includes('prompts'),
    'a user record carrying only tool results is not counted as something a person typed',
  );
  ok(kinds[3].includes('problems'), 'a line that did not parse is a problem row');

  for (const [mode, expected] of [
    ['all', 4],
    ['prompts', 1],
    ['tools', 2],
    ['thinking', 1],
    ['answers', 1],
    ['problems', 1],
  ]) {
    eq(api.filterTimelineItems(items, mode).items.length, expected, `the ${mode} filter keeps ${expected}`);
  }
  // The property the honesty rule rests on: what is filtered out is counted, so the
  // interface can say how much is off screen instead of leaving it looking absent.
  const only = api.filterTimelineItems(items, 'prompts');
  eq(only.hidden, 3, 'a filter reports how many rows it took out of view');
  eq(api.filterTimelineItems(items, 'all').hidden, 0, 'and no filter hides nothing');
  eq(
    api.filterTimelineItems(items, 'prompts').items.length + only.hidden,
    items.length,
    'every row is either shown or counted as hidden, never neither',
  );
}

{
  api.state.scope = 'all';
  api.state.current = { path: 's1' };
  eq(api.scopePath(), null, 'the default scope is every session');
  api.state.scope = 'session';
  eq(api.scopePath(), 's1', 'scoping to a session uses the open one');
  api.state.current = null;
  eq(
    api.scopePath(),
    null,
    'and with no session open it falls back to all, which the chip row says out loud',
  );
  api.state.scope = 'all';
}

// ------------------------------------------------------- the case API source (afx serve)

// A stand-in for the server. `pages` is what each call answers with, in order, so a test
// states the sequence it is about rather than a whole server.
function fakeFetch(pages) {
  const calls = [];
  ctx.fetch = async (url) => {
    calls.push(url);
    const page = pages[Math.min(calls.length - 1, pages.length - 1)];
    return {
      ok: page.ok !== false,
      status: page.status || 200,
      headers: { get: (name) => (name === 'X-Afx-Next-Offset' ? (page.next ?? null) : null) },
      async text() {
        return page.body;
      },
      async json() {
        return page.json;
      },
    };
  };
  return calls;
}

{
  const calls = fakeFetch([
    { body: JSON.stringify({ v: 1, agent: 'claude_code', kind: 'user.prompt' }) + '\n', next: '1' },
    { body: JSON.stringify({ v: 1, agent: 'claude_code', kind: 'assistant.text' }) + '\n' },
  ]);
  setSource(api.apiSource);
  const events = await api.fetchEvents('api/sessions/' + 'a'.repeat(32) + '/events');
  eq(events.length, 2, 'the case source follows the pages the server offers');
  eq(calls.length, 2, 'and stops when the server stops offering a next offset');
  ok(calls[0].includes('offset=0') && calls[1].includes('offset=1'), 'each page asks for its own offset');
  eq(events[1].__line, 2, 'line numbers run across the whole session, not per page');
}

{
  // A page that does not end in a newline. Without the seam fix the two records either side
  // of it would be concatenated into one unparseable line, which would show up as a record
  // the analyst has to explain and a record that vanished.
  fakeFetch([
    { body: JSON.stringify({ v: 1, agent: 'codex', kind: 'user.prompt' }), next: '1' },
    { body: JSON.stringify({ v: 1, agent: 'codex', kind: 'assistant.text' }) + '\n' },
  ]);
  const events = await api.fetchEvents('api/sessions/' + 'b'.repeat(32) + '/events');
  eq(events.length, 2, 'a page with no trailing newline does not swallow the next record');
  ok(
    !events.some((e) => e.type === 'parse-error'),
    'and the seam does not produce an unparseable line',
  );
}

{
  // A server answering with an offset that does not advance. Looping would re-show the
  // first page forever; keeping what arrived is the lesser failure and is visible.
  const calls = fakeFetch([
    { body: JSON.stringify({ v: 1, agent: 'copilot', kind: 'user.prompt' }) + '\n', next: '0' },
  ]);
  const events = await api.fetchEvents('api/sessions/' + 'c'.repeat(32) + '/events');
  eq(calls.length, 1, 'an offset that does not advance stops the paging instead of looping');
  eq(events.length, 1, 'and what did arrive is kept');
}

{
  let threw = false;
  try {
    await api.apiSource.listDir('api/');
  } catch (e) {
    threw = true;
  }
  ok(threw, 'the case source refuses to list a directory rather than returning an empty one');
}

{
  ctx.location = { protocol: 'file:' };
  fakeFetch([{ json: { afx_api: 1 } }]);
  eq(await api.probeCaseApi(), null, 'a file:// page never probes for a case API');

  ctx.location = { protocol: 'http:' };
  fakeFetch([{ ok: false, status: 404, json: {} }]);
  eq(await api.probeCaseApi(), null, 'a 404 is not a case');

  fakeFetch([{ json: { hello: 'world' } }]);
  eq(await api.probeCaseApi(), null, 'a 200 with the wrong JSON is not a case either');

  fakeFetch([{ json: { afx_api: 1, counts: {} } }]);
  const found = await api.probeCaseApi();
  ok(found && found.afx_api === api.CASE_API_VERSION, 'the marker field is what identifies a case');

  fakeFetch([{ json: { afx_api: 99 } }]);
  const other = await api.probeCaseApi();
  ok(
    other && other.afx_api === 99,
    'a version this viewer does not read is still returned, so the mismatch can be said out loud',
  );
}

{
  // Tracing one event back to the session it belongs in. The six values are the ones the
  // server derived the session from, so all six have to agree, and a null has to match a
  // null: a session with no working directory is a real session.
  const group = {
    key: 'k', path: 'api/sessions/k/events', agent: 'claude_code', host: null, user: 'alice',
    project_path: null, session_id: 's1', files: false,
  };
  api.state.projects = [{ id: 'p', name: 'p', sessions: [{ path: group.path, caseSession: group }] }];
  ok(
    api.findCaseSession({ agent: 'claude_code', host: null, user: 'alice', project_path: null, session_id: 's1', kind: 'user.prompt' }),
    'an event is traced back to its own session, with nulls matching nulls',
  );
  eq(
    api.findCaseSession({ agent: 'claude_code', host: null, user: 'alice', project_path: null, session_id: 's2', kind: 'user.prompt' }),
    null,
    'an event from another session is not silently shown in this one',
  );
  eq(
    api.findCaseSession({ agent: 'claude_code', host: null, user: 'alice', project_path: null, session_id: 's1', kind: 'artifact.fs' }),
    null,
    'a filesystem event does not land in a conversation, because the server groups it apart',
  );
  api.state.projects = [];
}

{
  // The two gaps a reader must be able to tell apart: a file nobody collected, and a file
  // that was collected and never read.
  eq(api.artifactState({ collected: false, parse_status: null }), 'not collected', 'an uncollected file says so');
  eq(api.artifactState({ collected: true, parse_status: null }), 'no parser', 'a collected file with no parser says so');
  eq(api.artifactState({ collected: true, parse_status: 'parsed' }), 'parsed', 'a parsed file says so');
  eq(api.artifactState({ collected: true, parse_status: 'failed' }), 'failed', 'a failed parse is not called parsed');
}

{
  // ---- the time window ----
  //
  // A window is a filter, so it is under the same rule as every other one: it may take
  // rows off the screen and it may never leave them looking absent. Two of its decisions
  // are load-bearing and are pinned here.
  eq(api.windowBound('2026-09-06', false).value, '2026-09-06T00:00:00.000000Z', 'a bare date opens at midnight');
  eq(
    api.windowBound('2026-09-06', true).value,
    '2026-09-06T23:59:59.999999Z',
    'and closes at the end of that day, not at its start',
  );
  eq(
    api.windowBound('2026-09-06T09:00', false).value,
    '2026-09-06T09:00:00.000000Z',
    'a bound without seconds is padded to the shape the case stores',
  );
  eq(
    api.windowBound('2026-09-06T09:00', true).value,
    '2026-09-06T09:00:59.999999Z',
    'and an upper bound without seconds means the end of that minute',
  );
  eq(api.windowBound('', false).value, null, 'an empty bound is no bound');
  ok(api.windowBound('yesterday', false).problem, 'an unreadable bound is a problem, not an empty filter');

  api.state.since = 'nonsense';
  api.state.until = '';
  ok(api.timeWindow().problems.length === 1, 'the problem travels to the caller');
  ok(api.timeWindow().set === false, 'and an unreadable bound is never applied as a window');
  api.state.since = '2026-09-07';
  api.state.until = '2026-09-06';
  ok(api.timeWindow().problems.length === 1, 'a window that ends before it starts says so');

  api.state.since = '2026-09-06';
  api.state.until = '2026-09-06';
  const win = api.timeWindow();
  ok(api.inWindow('2026-09-06T12:00:00.000000Z', win), 'an event inside the day is inside');
  ok(!api.inWindow('2026-09-05T23:59:59.000000Z', win), 'the moment before it is not');
  ok(!api.inWindow('2026-09-07T00:00:00.000000Z', win), 'and neither is the moment after');
  // The rule the case database applies server-side, kept here so the screen and an
  // exported timeline agree: an undated event's position is unknown, not outside.
  ok(api.inWindow(null, win), 'an event with no timestamp is inside every window');

  const items = [
    { kind: 'event', event: { type: 'user', timestamp: '2026-09-06T09:00:00.000000Z', message: { content: 'a' } } },
    { kind: 'event', event: { type: 'user', timestamp: '2026-09-08T09:00:00.000000Z', message: { content: 'b' } } },
    { kind: 'event', event: { type: 'user', message: { content: 'c' } } },
  ];
  const shown = api.filterTimelineItems(items, 'all', win);
  eq(shown.items.length, 2, 'a window keeps what is inside it and what has no time');
  eq(shown.hidden, 1, 'and counts what it took out of view');
  eq(shown.undated, 1, 'counting the undated rows separately, which is what explains the rest');
  eq(
    api.filterTimelineItems(items, 'all', { set: false }).items.length,
    3,
    'and no window hides nothing',
  );
  api.state.since = '';
  api.state.until = '';
}

{
  // ---- the session list's two marks ----
  //
  // Both are about the case's own reliability rather than its content: where a rule found
  // something, and where a parser could not read a line. The second is invisible in a total
  // on a large case, which is exactly why it gets a chip.
  api.state.caseFindings = { findings: [{ session_id: 's1' }, { session_id: null }] };
  eq(api.findingSessions().size, 1, 'a finding with no session belongs to no session');
  const flagged = { caseSession: { session_id: 's1', unreadable: 0 } };
  const unreadable = { caseSession: { session_id: 's2', unreadable: 3 } };
  // Read fine, in a format nobody has mapped: the other mark, and the opposite answer.
  const unmapped = { caseSession: { session_id: 's4', uninterpreted: 40 } };
  const quiet = { caseSession: { session_id: 's3', unreadable: 0 } };
  eq(api.sessionMarks(flagged).join(), 'findings', 'a session a rule fired in is marked');
  eq(api.sessionMarks(unreadable).join(), 'unreadable', 'a session with a record nobody read is marked');
  eq(api.sessionMarks(unmapped).join(), 'unmapped', 'a session whose records nobody has mapped is marked apart');
  eq(api.sessionMarks(quiet).join(), '', 'and a session with neither is not');
  eq(api.sessionMarks({}).join(), '', 'a session from a folder source carries no marks at all');
  api.state.caseFindings = null;
}

console.error(
  (failures === 0 ? 'viewer behavior: ' : 'viewer behavior FAILED: ') +
    (checks - failures) +
    '/' +
    checks +
    ' checks passed',
);
process.exit(failures === 0 ? 0 : 1);
