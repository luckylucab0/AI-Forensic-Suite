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

console.error(
  (failures === 0 ? 'viewer behavior: ' : 'viewer behavior FAILED: ') +
    (checks - failures) +
    '/' +
    checks +
    ' checks passed',
);
process.exit(failures === 0 ? 0 : 1);
