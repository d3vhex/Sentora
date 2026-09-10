/** Making a Windows event message readable in one line.
 *
 *  Windows writes event bodies as a headline followed by tab-indented
 *  `Key=Value` lines, and the SIEM stores that verbatim - correctly, because
 *  it is the record. Rendered into a table cell the whitespace collapses and
 *  an analyst gets this:
 *
 *    [PowerShell] EID=403, Cat=4 | Stopped | Available | NewEngineState=
 *    Stopped PreviousEngineState=Available SequenceNumber=49 HostName=
 *    ConsoleHost HostVersion=5.1.26100.9168 HostId=b5b39b50-... HostApplication=
 *    powershell -NoProfile -Command ... EngineVersion=... RunspaceId=...
 *    PipelineId= CommandName= CommandType= ScriptName= CommandPath= CommandLine=
 *
 *  Everything is there and nothing is legible, and the one field an analyst
 *  actually wants - what was executed - is buried between two GUIDs and six
 *  empty keys.
 *
 *  So: keep the headline, drop the empty fields, and surface the fields that
 *  answer "what happened" first. Nothing is invented and nothing is
 *  discarded - `parseEventMessage` returns every field it found, so a detail
 *  view can show the lot.
 */

export interface EventField {
  key: string;
  value: string;
}

export interface ParsedEvent {
  /** The text before the first `Key=Value`, tidied. */
  headline: string;
  /** Every non-empty field, in the order Windows wrote them. */
  fields: EventField[];
  /** True when this looked like a Windows event body at all. */
  structured: boolean;
}

/** Fields that answer "what happened", best first.
 *
 *  Order is deliberate: a command line beats the host that ran it, and an
 *  account name beats a session id. Everything not listed still appears in
 *  the detail view - this only decides what earns the one line in a table. */
const INTERESTING = [
  'CommandLine',
  'HostApplication',
  'ScriptName',
  'NewProcessName',
  'Image',
  'ProcessName',
  'TargetUserName',
  'SubjectUserName',
  'AccountName',
  'ServiceName',
  'ObjectName',
  'IpAddress',
  'WorkstationName',
  'NewEngineState',
];

const FIELD_LINE = /^[\s ]*([A-Za-z][A-Za-z0-9_.]{1,60})=(.*)$/;

/** Split a Windows event body into its headline and fields. */
export function parseEventMessage(raw: string): ParsedEvent {
  const text = typeof raw === 'string' ? raw : '';
  if (!text) return { headline: '', fields: [], structured: false };

  const lines = text.split(/\r\n|\r|\n/);
  const headlineParts: string[] = [];
  const fields: EventField[] = [];
  let seenField = false;

  for (const line of lines) {
    // Split on tabs before matching. `FIELD_LINE` is anchored at the start of
    // a line, and the agent builds its message as `summary | inserts` on one
    // line - so the first field arrives *after* the headline on the same line,
    // separated by the tab Windows puts in front of it:
    //
    //   [PowerShell] EID=403, Cat=4 | Stopped | Available | \tNewEngineState=Stopped
    //
    // Matching per line dropped that field on every event of this shape, and
    // it is the field that says what actually happened. The rest of the
    // inserts are one per line and are unaffected.
    for (const segment of line.split('\t')) {
      const match = segment.match(FIELD_LINE);
      if (match) {
        seenField = true;
        const key = match[1];
        const value = match[2].trim();
        // Windows emits a run of empty keys on most events - PipelineId,
        // CommandName, CommandType, CommandPath. They are noise in every one.
        if (value) fields.push({ key, value });
        continue;
      }
      if (!seenField) headlineParts.push(segment);
    }
  }

  // The first line often ends with the same values repeated as ` | a | b | `
  // before the fields begin. Trim the trailing separators, keep the text.
  //
  // Trimmed with a loop rather than a regex, and deliberately.
  //
  // This was `(\s*\|\s*)+$`: a quantifier inside a quantifier with the
  // whitespace ambiguous between adjacent repetitions, which backtracks
  // exponentially on a line ending in a long run of spaces. `[\s|]+$` fixes
  // that and is still super-linear, because an anchored trailing match makes
  // the engine retry from every position when it fails. JavaScript has no
  // possessive quantifiers to say "do not backtrack", so the honest answer is
  // not to ask a regex for something a scan does in one pass - over text an
  // attacker writes into a log, running in the operator's browser.
  const collapsed = headlineParts.join(' ').replace(/\s+/g, ' ');
  let end = collapsed.length;
  while (end > 0 && (collapsed[end - 1] === '|' || collapsed[end - 1] === ' ')) {
    end -= 1;
  }
  const headline = collapsed.slice(0, end).trim();

  return { headline, fields, structured: seenField };
}

function truncate(value: string, limit: number): string {
  const flat = value.replace(/\s+/g, ' ').trim();
  return flat.length > limit ? `${flat.slice(0, limit - 1)}…` : flat;
}

/** One readable line for a table cell.
 *
 *  Falls back to the original text - whitespace collapsed - whenever this is
 *  not a Windows event body, so a syslog line is passed through unchanged
 *  rather than mangled by a parser written for something else.
 */
export function summariseEventMessage(raw: string, limit = 240): string {
  const text = typeof raw === 'string' ? raw : '';
  if (!text.trim()) return '';

  let parsed: ParsedEvent;
  try {
    parsed = parseEventMessage(text);
  } catch {
    return truncate(text, limit);
  }

  if (!parsed.structured) return truncate(text, limit);

  const chosen: string[] = [];
  for (const key of INTERESTING) {
    const field = parsed.fields.find((f) => f.key === key);
    if (field) {
      chosen.push(`${field.key}: ${truncate(field.value, 140)}`);
      if (chosen.length === 2) break;
    }
  }

  // Nothing from the interesting list: show the first real fields rather than
  // a bare headline, because "EID=4672" alone tells an analyst nothing.
  if (!chosen.length) {
    for (const field of parsed.fields.slice(0, 2)) {
      chosen.push(`${field.key}: ${truncate(field.value, 100)}`);
    }
  }

  const parts = [parsed.headline, ...chosen].filter(Boolean);
  return truncate(parts.join(' — '), limit);
}
