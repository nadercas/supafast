#!/usr/bin/env node
// Extract host-script generators from components/cloudInitGenerator.js and write
// their output into management/hostbin/. The management container's bootstrap
// endpoint serves these frozen copies (base64-embedded) so both fresh cloud-init
// boots and old-server SSH bootstrap use the same content.
//
// Run from repo root after editing any get*Sh() in cloudInitGenerator.js:
//   node management/scripts/extract-runner.js

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..', '..');
const src = fs.readFileSync(path.join(root, 'components/cloudInitGenerator.js'), 'utf8');

const targets = [
  { fn: 'getSupafastMigrateSh',   out: 'management/hostbin/supafast-migrate.sh' },
  { fn: 'getSupabasePinDigestsSh', out: 'management/hostbin/supabase-pin-digests.sh' },
];

for (const { fn, out } of targets) {
  // Find the function start, then walk to the end of its span by cutting at
  // the next top-level `function ` / `export function ` declaration, and
  // keeping everything up to the last `\n}\n` in that span (the real close
  // brace — earlier `\n}\n` occurrences can appear inside the embedded bash
  // template literal and would mislead a lazy regex).
  const startRe = new RegExp(`(?:export\\s+)?function ${fn}\\(\\)`);
  const startMatch = src.match(startRe);
  if (!startMatch) { console.error('could not locate', fn); process.exit(1); }
  const startIdx = startMatch.index;
  const after = src.slice(startIdx + startMatch[0].length);
  const nextFn = after.search(/\n(?:export\s+)?function [A-Za-z_]/);
  const span = nextFn === -1 ? after : after.slice(0, nextFn);
  const lastClose = span.lastIndexOf('\n}\n');
  if (lastClose === -1) { console.error('no close brace for', fn); process.exit(1); }
  const body = startMatch[0] + span.slice(0, lastClose + 3);
  const stripped = body.replace(/^export\s+/, '');
  const ctx = { module: { exports: {} } };
  vm.runInNewContext(stripped + `\nmodule.exports = ${fn};`, ctx);
  const dest = path.join(root, out);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, ctx.module.exports(), { mode: 0o755 });
  console.log('wrote', out);
}
