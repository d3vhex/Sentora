/** Telling apart "the model said something" from "the model said nothing".
 *
 *  Three ways a triage row can carry no answer, none of them a finding about
 *  the host it names:
 *
 *    - the model contradicted itself, e.g. verdict SUSPICIOUS at severity
 *      INFO. `coherence_problem` in `ai/schemas.py` catches these; we do not
 *      get to pick which half was meant, so neither half is usable.
 *    - the model returned nothing that parsed into a verdict.
 *    - the event could not be decrypted, so the model was never asked. The
 *      row exists to say the event was seen and skipped, not judged.
 *
 *  These are worth *recording* - a model that cannot answer is a fact about
 *  the model, and dropping them would quietly overstate how much of the fleet
 *  was actually triaged. They are not worth *showing by default*: a feed of
 *  them buries the rows that do carry an answer, which is the failure the
 *  operator reported. So: hidden, counted, and one click away.
 */

/** Prefixes written by `_parse_failure_entry` and the decrypt path in
 *  `ai_worker.py`. Kept as literals rather than a loose /failed/i so that a
 *  model verdict that happens to contain the word is not swallowed. */
const NO_ANSWER_MARKERS = ['[PARSE FAILED]', '[NOT ANALYSED]'] as const;

export interface TriageRow {
  verdict?: string | null;
  critical_summary?: string | null;
}

/** True when this row records the absence of an answer rather than an answer. */
export function isUnanswered(row: TriageRow | null | undefined): boolean {
  if (!row) return false;
  if (row.verdict === 'INSUFFICIENT_DATA') return true;
  const summary = row.critical_summary || '';
  return NO_ANSWER_MARKERS.some(marker => summary.includes(marker));
}

/** How many rows in a set carry no answer. Shown next to the feed so the
 *  hidden ones stay visible as a number even when hidden as rows. */
export function countUnanswered(rows: readonly TriageRow[]): number {
  return rows.reduce((n, row) => n + (isUnanswered(row) ? 1 : 0), 0);
}
