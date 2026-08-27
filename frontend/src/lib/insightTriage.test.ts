/**
 * Telling apart "the model answered" from "the model did not".
 *
 * The operator's complaint was that the AI feed had filled with rows saying
 * nothing - contradictory verdicts, unparseable replies, events that never
 * reached the model because they would not decrypt. Hiding them is only safe
 * if the predicate is exact: too loose and it hides real detections, which is
 * a worse failure than the noise it was meant to fix.
 *
 * Run:
 *   cd frontend
 *   npm test
 *
 * Uses `node:test` rather than a framework so it needs no new dependency,
 * matching playbookActions.test.ts.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { isUnanswered, countUnanswered } from './insightTriage.ts';

describe('isUnanswered', () => {
  test('a real verdict is an answer', () => {
    assert.equal(isUnanswered({ verdict: 'CRITICAL', critical_summary: 'reverse shell' }), false);
    assert.equal(isUnanswered({ verdict: 'IGNORE', critical_summary: 'cron job' }), false);
  });

  test('catches the verdict the coherence check falls back to', () => {
    // ai/schemas.py rejects "SUSPICIOUS at severity INFO" and the worker
    // records INSUFFICIENT_DATA rather than picking a half to believe.
    assert.equal(isUnanswered({ verdict: 'INSUFFICIENT_DATA' }), true);
  });

  test('catches rows the model never answered', () => {
    assert.equal(isUnanswered({ critical_summary: '[PARSE FAILED] no verdict returned' }), true);
    assert.equal(isUnanswered({
      critical_summary: '[NOT ANALYSED] The event could not be decrypted, so it was never sent to the model.',
    }), true);
  });

  test('does not swallow a verdict that merely mentions failure', () => {
    // This is the expensive mistake: a finding about failed logins is an
    // answer, and hiding it would hide a real detection to reduce noise.
    assert.equal(isUnanswered({
      verdict: 'SUSPICIOUS',
      critical_summary: 'Repeated failed SSH logins, then one success.',
    }), false);
    assert.equal(isUnanswered({
      verdict: 'MONITOR',
      critical_summary: 'A parse failed in the application log.',
    }), false);
  });

  test('survives the shapes the API actually returns', () => {
    assert.equal(isUnanswered(null), false);
    assert.equal(isUnanswered(undefined), false);
    assert.equal(isUnanswered({}), false);
    // Rows written before the verdict column existed carry NULL, and a NULL
    // verdict is not the same claim as INSUFFICIENT_DATA.
    assert.equal(isUnanswered({ verdict: null, critical_summary: 'old row' }), false);
  });
});

describe('countUnanswered', () => {
  test('counts what the feed hides, so it stays visible as a number', () => {
    const rows = [
      { verdict: 'CRITICAL', critical_summary: 'real finding' },
      { verdict: 'INSUFFICIENT_DATA' },
      { critical_summary: '[NOT ANALYSED] could not be decrypted' },
      { verdict: 'IGNORE', critical_summary: 'noise' },
    ];
    assert.equal(countUnanswered(rows), 2);
    assert.equal(rows.filter(r => !isUnanswered(r)).length, 2);
  });

  test('is zero for an empty set', () => {
    assert.equal(countUnanswered([]), 0);
  });
});
