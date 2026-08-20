/**
 * Sanity checks for the playbook action catalogue.
 *
 * The catalogue is what the editor validates steps against, so a wrong entry
 * here means a malformed step saves cleanly and fails later on the endpoint,
 * where the reason is much harder to see.
 *
 * Run:
 *   cd frontend
 *   node --experimental-strip-types --test src/lib/playbookActions.test.ts
 *
 * Uses `node:test` rather than a framework so it needs no new dependency.
 * The file is excluded from tsconfig.app.json — it is not application code,
 * and the browser build has no types for Node built-ins. If the frontend
 * grows a real test story later, vitest is the natural home for this.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

// Explicit .ts extension: Node's ESM resolver does not guess it the way Vite
// and TypeScript's bundler resolution do. Harmless for the app build, which
// excludes this file entirely.
import { ACTIONS, getAction, validateStep, searchActions } from './playbookActions.ts';

test('every action has a unique value', () => {
  const values = ACTIONS.map(a => a.value);
  assert.equal(new Set(values).size, values.length);
});

test('every action carries a description', () => {
  for (const a of ACTIONS) {
    assert.ok(a.description.trim().length > 10, `${a.value} needs a real description`);
  }
});

test('irreversible actions are flagged', () => {
  // These take an endpoint away from the operator or destroy data; the editor
  // warns on them before saving.
  for (const value of ['isolate_host', 'delete_file', 'delete_registry_key', 'run_cmd']) {
    assert.equal(getAction(value)?.destructive, true, `${value} must be marked destructive`);
  }
  assert.notEqual(getAction('quarantine_file')?.destructive, true, 'quarantine is reversible');
});

test('parameterless actions declare no param', () => {
  for (const value of ['flush_dns', 'lock_machine', 'clear_temp', 'protect_shadows', 'isolate_host']) {
    assert.equal(getAction(value)?.param, undefined, `${value} should take no parameter`);
    assert.equal(validateStep(value, ''), null, `${value} must validate with an empty target`);
  }
});

test('block_ip rejects anything that is not an IPv4 address', () => {
  assert.equal(validateStep('block_ip', '203.0.113.10'), null);
  assert.ok(validateStep('block_ip', '203.0.113.999'));
  assert.ok(validateStep('block_ip', 'not-an-ip'));
  assert.ok(validateStep('block_ip', ''));
});

test('templates are accepted, since they resolve at run time', () => {
  assert.equal(validateStep('block_ip', '{{event.ip}}'), null);
  assert.equal(validateStep('quarantine_file', '{{event.path}}'), null);
});

test('file actions require an absolute path', () => {
  assert.equal(validateStep('delete_file', '/tmp/x.sh'), null);
  assert.equal(validateStep('delete_file', 'C:\\Users\\x\\e.exe'), null);
  assert.ok(validateStep('delete_file', 'relative/path.sh'));
});

test('kill_process refuses PID 1', () => {
  // Killing init takes the host down — a typo that costs a machine.
  assert.ok(validateStep('kill_process', '1'));
  assert.equal(validateStep('kill_process', '4812'), null);
  assert.equal(validateStep('kill_process', 'powershell.exe'), null);
});

test('unknown actions are reported rather than silently accepted', () => {
  assert.ok(validateStep('rm_minus_rf', 'anything'));
});

test('search matches label, value and description', () => {
  assert.ok(searchActions('block').some(a => a.value === 'block_ip'));
  assert.ok(searchActions('firewall').some(a => a.value === 'block_ip'));
  assert.ok(searchActions('ransomware').some(a => a.value === 'protect_shadows'));
  assert.equal(searchActions('').length, ACTIONS.length);
});
