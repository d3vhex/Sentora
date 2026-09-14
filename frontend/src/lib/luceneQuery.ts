/**
 * Turning a clicked filter into the query the server actually runs.
 *
 * The query box on the Search page is editable on purpose — somebody who knows
 * Lucene should never be fighting the builder — so this is not a sanitiser and
 * there is no privilege to escalate: the operator can type whatever they like
 * into the box beside it, and the server runs it either way.
 *
 * What it has to be is *faithful*. Clicking `message = C:\Users\x` has to
 * produce a query that searches for `C:\Users\x`, and the previous version did
 * not:
 *
 *     value.replace(/"/g, '\\"')      // escapes the quote, not the backslash
 *
 * so `a\` became `"a\"` — the closing quote escaped, the string running on into
 * whatever followed. And the unquoted branch was worse, because it only quoted
 * when the value contained whitespace or a quote: `a)OR(b` has neither, went in
 * raw, and changed the shape of the query.
 *
 * The rule here is the other way round. A value that is anything other than a
 * plain token gets quoted, and inside the quotes the two characters that mean
 * something to Lucene — the backslash and the quote — are escaped, backslash
 * first. Escaping the quote first would then escape the backslash it just
 * added, which is the classic way to get this exactly wrong.
 */

export type Filter = { field: string; op: ':' | '!='; value: string };

/** Characters a value may contain and still go in bare.
 *
 *  Deliberately a small allow-list rather than a list of things to escape: the
 *  Lucene metacharacter set is `+ - && || ! ( ) { } [ ] ^ " ~ * ? : \ /` plus
 *  whitespace, and enumerating it is how one gets missed. Anything outside
 *  word characters, dot, at-sign and hyphen is quoted.
 */
const PLAIN_TOKEN = /^[\w.@-]+$/;

export function quoteValue(value: string): string {
  if (PLAIN_TOKEN.test(value)) return value;
  // Backslash first. The other order escapes the backslashes this line adds.
  const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `"${escaped}"`;
}

export function toQuery(filters: Filter[]): string {
  return filters
    .filter((f) => f.field && f.value)
    .map((f) => {
      const value = quoteValue(f.value);
      return f.op === ':' ? `${f.field}:${value}` : `NOT ${f.field}:${value}`;
    })
    .join(' AND ');
}
