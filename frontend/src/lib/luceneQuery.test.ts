/**
 * The builder has to produce a query that means what was clicked.
 *
 * CodeQL called the old version incomplete sanitisation, and the label is
 * misleading here: the query box next to the builder is editable by design, so
 * an operator can type raw Lucene whenever they like and there is no boundary
 * being crossed. What was actually broken is fidelity — two shapes of value
 * produced a query that searched for something else, or for nothing.
 *
 * Both are in here as their own cases, because they are the ones that were
 * wrong rather than the ones that are easy to write.
 *
 * Run:
 *   cd frontend
 *   npm test
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { quoteValue, toQuery } from './luceneQuery.ts';

describe('quoteValue', () => {
  test('a plain token is left alone', () => {
    // Quoting everything would work, and would make `foo*` stop being a
    // wildcard for somebody who typed one into the value box.
    assert.equal(quoteValue('CRITICAL'), 'CRITICAL');
    assert.equal(quoteValue('agent-01'), 'agent-01');
    assert.equal(quoteValue('user@example.com'), 'user@example.com');
    assert.equal(quoteValue('4.18.25080.5'), '4.18.25080.5');
  });

  test('a trailing backslash does not escape the closing quote', () => {
    // The bug. `a\` became `"a\"` — the quote escaped, the phrase running on
    // into whatever came after it in the query.
    assert.equal(quoteValue('a\\'), '"a\\\\"');
  });

  test('a Windows path survives intact', () => {
    // The everyday version of the same thing: every path in this product's
    // telemetry has backslashes in it.
    assert.equal(quoteValue('C:\\Users\\jdoe'), '"C:\\\\Users\\\\jdoe"');
  });

  test('backslashes are escaped before quotes, not after', () => {
    // Escaping the quote first turns `"` into `\"`, and the backslash pass
    // then escapes the backslash that pass just added — producing `\\"`,
    // which is an escaped backslash followed by a live quote.
    assert.equal(quoteValue('say "hi"'), '"say \\"hi\\""');
    assert.equal(quoteValue('a\\"b'), '"a\\\\\\"b"');
  });

  test('a value with no whitespace is still quoted when it needs it', () => {
    // The old rule only quoted on whitespace or a quote, so this went in raw
    // and changed the structure of the query rather than the term.
    assert.equal(quoteValue('a)OR(b'), '"a)OR(b"');
    assert.equal(quoteValue('x:y'), '"x:y"');
    assert.equal(quoteValue('a&&b'), '"a&&b"');
  });

  test('whitespace still forces quoting', () => {
    assert.equal(quoteValue('two words'), '"two words"');
  });
});

describe('toQuery', () => {
  test('an empty filter set is an empty query', () => {
    assert.equal(toQuery([]), '');
  });

  test('filters with no field or no value are dropped', () => {
    assert.equal(toQuery([
      { field: '', op: ':', value: 'x' },
      { field: 'severity', op: ':', value: '' },
    ]), '');
  });

  test('negation is spelled NOT field:value', () => {
    assert.equal(
      toQuery([{ field: 'severity', op: '!=', value: 'INFO' }]),
      'NOT severity:INFO');
  });

  test('several filters join with AND', () => {
    assert.equal(
      toQuery([
        { field: 'severity', op: ':', value: 'CRITICAL' },
        { field: 'agent', op: '!=', value: 'WIN-01' },
      ]),
      'severity:CRITICAL AND NOT agent:WIN-01');
  });

  test('a path value produces a query that still parses', () => {
    const query = toQuery([
      { field: 'message', op: ':', value: 'C:\\Windows\\Temp\\svc.exe' },
    ]);
    assert.equal(query, 'message:"C:\\\\Windows\\\\Temp\\\\svc.exe"');
    // The quotes that remain are the pair that delimits the phrase: every
    // other one would have to be escaped, and there are none here.
    const unescaped = query.replace(/\\\\/g, '').replace(/\\"/g, '');
    assert.equal((unescaped.match(/"/g) || []).length, 2);
  });
});
