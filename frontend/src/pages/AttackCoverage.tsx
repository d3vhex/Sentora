import React, { useCallback, useEffect, useState } from 'react';
import { Grid3x3, ShieldAlert, ShieldCheck, EyeOff, AlertTriangle, GitBranch } from 'lucide-react';
// One StatCard, not three. It was written independently on this page, on
// Dashboard and on ThreatIntel, and the three had drifted to different
// paddings, weights and label sizes - which is most of why the console read
// as three products rather than one.
import { StatCard } from '../components/ui';
import { agentService } from '../services/api';

/**
 * MITRE ATT&CK coverage.
 *
 * The point of this page is a distinction a single "coverage %" destroys.
 * Three states, not two:
 *
 *   covered + seen    a rule exists and it has fired here
 *   covered + quiet   a rule exists and nothing matched it. Normal, and good.
 *   neither           nothing installed would catch it. The console's silence
 *                     about this technique means nothing at all.
 *
 * The third is the only one that should worry anybody, and it is the one a
 * percentage hides - a heatmap showing "62% covered" reads as reassurance
 * while saying nothing about which 38%.
 *
 * Techniques come from the installed Sigma rules' own `tags` and from the
 * correlation rules, so this is derived from what is actually loaded rather
 * than from a hand-kept table that can claim coverage the platform does not
 * have. Correlation is counted here because it is real coverage an operator
 * has: leaving it out would draw T1110.003 as a blind spot on an estate that
 * detects it, and telling "quiet" from "blind" is the whole point of the
 * page.
 */

type Coverage = {
  covered: string[];
  observed: { technique: string; events: number }[];
  covered_count: number;
  observed_count: number;
  quiet: string[];
  uncovered_but_seen: string[];
  /** Seen, with rules for *other* sub-techniques of the same parent and not
   *  this one. Its own state because it is the one most easily mistaken for
   *  coverage: the parent cell is green while this particular action would go
   *  unnoticed. Detecting T1003.001 (LSASS memory) says nothing about
   *  T1003.003 (the AD database) - different action, different telemetry. */
  covered_only_by_a_sibling: string[];
  /** Seen at sub-technique granularity, with a rule claiming the whole
   *  parent. Genuinely covered. */
  covered_by_the_parent: string[];
  /** Parent technique -> the sub-techniques covered under it, so a rolled-up
   *  cell can say "2 sub-techniques" rather than implying the whole of it. */
  subtechniques: Record<string, string[]>;
};

/** The tactics, in the order ATT&CK orders them: earliest to latest in a
 *  kill chain. A grid sorted alphabetically tells you nothing about where in
 *  an intrusion you are blind. */
const TACTIC_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
];

/** Technique -> tactic, for the techniques this platform has rules or events
 *  for. Deliberately small: it is a display grouping, not a detection input,
 *  and an unknown technique falls into "other" rather than being dropped. */
const TECHNIQUE_TACTIC: Record<string, string> = {
  T1003: 'credential-access', T1055: 'privilege-escalation',
  T1059: 'execution', T1053: 'persistence', T1547: 'persistence',
  T1070: 'defense-evasion', T1562: 'defense-evasion', T1021: 'lateral-movement',
  T1110: 'credential-access', T1490: 'impact', T1486: 'impact',
  T1078: 'initial-access', T1087: 'discovery', T1082: 'discovery',
  T1105: 'command-and-control', T1041: 'exfiltration', T1136: 'persistence',
  T1543: 'persistence', T1112: 'defense-evasion', T1140: 'defense-evasion',
  T1548: 'privilege-escalation', T1098: 'persistence', T1569: 'execution',
  T1497: 'defense-evasion', T1218: 'defense-evasion', T1027: 'defense-evasion',
  T1574: 'persistence', T1611: 'privilege-escalation',
  T1047: 'execution', T1566: 'initial-access',
  T1482: 'discovery', T1546: 'persistence', T1556: 'credential-access',
  T1563: 'lateral-movement',
};

const tacticOf = (technique: string): string =>
  TECHNIQUE_TACTIC[technique.split('.')[0]] || 'other';

const label = (tactic: string): string =>
  tactic.split('-').map(w => w[0].toUpperCase() + w.slice(1)).join(' ');

const AttackCoverage: React.FC = () => {
  const [data, setData] = useState<Coverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setFailed(false);
    try {
      setData(await agentService.getAttackCoverage());
    } catch (err) {
      console.error('ATT&CK coverage fetch failed', err);
      setFailed(true);
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const eventsFor = (technique: string): number =>
    data?.observed.find(o => o.technique === technique)?.events ?? 0;

  // Every technique this deployment knows about, from either direction.
  const all = Array.from(new Set([
    ...(data?.covered ?? []),
    ...(data?.observed ?? []).map(o => o.technique),
  ])).sort();

  const byTactic = new Map<string, string[]>();
  all.forEach(t => {
    const tactic = tacticOf(t);
    byTactic.set(tactic, [...(byTactic.get(tactic) ?? []), t]);
  });
  const tactics = [...TACTIC_ORDER, 'other'].filter(t => byTactic.has(t));

  const cellStyle = (technique: string): React.CSSProperties => {
    const seen = eventsFor(technique) > 0;
    const covered = data?.covered.includes(technique) ?? false;
    if (seen && covered) return { background: 'rgba(239,68,68,0.16)', borderColor: 'rgba(239,68,68,0.45)', color: '#fca5a5' };
    if (covered) return { background: 'rgba(16,185,129,0.10)', borderColor: 'rgba(16,185,129,0.30)', color: '#6ee7b7' };
    // Seen with no rule behind it: the AI or the regex list surfaced it.
    return { background: 'rgba(245,158,11,0.10)', borderColor: 'rgba(245,158,11,0.35)', color: '#fbbf24' };
  };

  return (
    <div style={{ paddingBottom: '60px' }}>
      <div style={{ marginBottom: '32px' }}>
        <h2 style={{ fontSize: '1.875rem', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Grid3x3 color="var(--accent-secondary)" /> ATT&amp;CK Coverage
        </h2>
        <p style={{ color: 'var(--text-secondary)', maxWidth: '70ch' }}>
          Which techniques this deployment can detect, and which have actually
          fired here. Read from the installed Sigma rules&rsquo; own tags plus
          the correlation rules, so nothing here claims coverage the platform
          does not have &mdash; a rule that failed to compile contributes none.
        </p>
      </div>

      {failed && (
        <div style={{
          marginBottom: '24px', padding: '12px 14px', borderRadius: '8px', fontSize: '0.8125rem',
          backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)',
          color: '#fca5a5', display: 'flex', gap: '10px', alignItems: 'center',
        }}>
          <AlertTriangle size={16} />
          Could not read coverage. This page is showing nothing, which is not
          the same as nothing being covered.
        </div>
      )}

      <div className="responsive-grid" style={{ marginBottom: '28px' }}>
        <StatCard
          label="Techniques covered" value={data?.covered_count ?? '—'}
          sub="a Sigma or correlation rule addresses these"
          color="#6ee7b7" icon={<ShieldCheck size={16} />}
        />
        <StatCard
          label="Seen here" value={data?.observed_count ?? '—'}
          sub="fired at least once on this estate"
          color="#fca5a5" icon={<ShieldAlert size={16} />}
        />
        <StatCard
          label="Seen with no rule" value={data?.uncovered_but_seen.length ?? '—'}
          sub="surfaced by the AI or the regex list, with no rule behind it"
          color="#fbbf24" icon={<EyeOff size={16} />}
        />
        <StatCard
          label="Covered only by a sibling"
          value={data?.covered_only_by_a_sibling?.length ?? '—'}
          sub="a rule exists for another sub-technique, not for this one"
          color="#f0abfc" icon={<GitBranch size={16} />}
        />
      </div>

      {!loading && !!data?.covered_only_by_a_sibling?.length && (
        <div style={{
          marginBottom: '24px', padding: '14px 16px', borderRadius: '8px',
          fontSize: '0.8125rem', backgroundColor: 'rgba(240,171,252,0.06)',
          border: '1px solid rgba(240,171,252,0.25)',
        }}>
          <strong>{data.covered_only_by_a_sibling.join(', ')}</strong> fired here,
          and the rules you have cover a <em>different</em> sub-technique of the
          same parent. The grid below is drawn at parent granularity, so those
          cells read as covered — they are not. Detecting one sub-technique says
          nothing about its siblings: they are different actions with different
          telemetry, and the rule for one will never fire on the other.
          <div style={{ marginTop: '6px', opacity: 0.75 }}>
            Usually cheaper to widen an existing rule than to write a new one.
          </div>
        </div>
      )}

      {!loading && data && data.covered_count === 0 && (
        <div style={{
          marginBottom: '24px', padding: '14px 16px', borderRadius: '8px', fontSize: '0.8125rem',
          backgroundColor: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)',
          color: '#fbbf24', lineHeight: 1.6,
        }}>
          <strong style={{ display: 'block', marginBottom: '4px' }}>No detection rules loaded.</strong>
          Nothing on this page is covered, so an empty grid below is a statement
          about the rules, not about the estate. Install rules into{' '}
          <code>conf/sigma/</code> &mdash; see the README there.
        </div>
      )}

      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', gap: '18px', flexWrap: 'wrap', marginBottom: '20px', fontSize: '0.75rem' }}>
          {[
            ['rgba(239,68,68,0.45)', '#fca5a5', 'Covered and seen'],
            ['rgba(16,185,129,0.30)', '#6ee7b7', 'Covered, never seen'],
            ['rgba(245,158,11,0.35)', '#fbbf24', 'Seen, no rule behind it'],
          ].map(([border, color, text]) => (
            <span key={text} style={{ display: 'flex', alignItems: 'center', gap: '7px', color: 'var(--text-secondary)' }}>
              <span style={{ width: '11px', height: '11px', borderRadius: '3px', border: `1px solid ${border}`, background: color, opacity: 0.5 }} />
              {text}
            </span>
          ))}
        </div>

        {loading && <div style={{ color: 'var(--text-secondary)' }}>Loading&hellip;</div>}

        {!loading && all.length === 0 && (
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            No techniques to show. With no rules installed and nothing observed,
            this grid is empty because there is nothing to say &mdash; not
            because the estate is clean.
          </div>
        )}

        <div style={{ display: 'flex', gap: '14px', overflowX: 'auto', paddingBottom: '8px' }}>
          {tactics.map(tactic => (
            <div key={tactic} style={{ minWidth: '190px', flex: '0 0 auto' }}>
              <div style={{
                fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase',
                letterSpacing: '0.04em', color: 'var(--text-secondary)',
                paddingBottom: '8px', borderBottom: '1px solid var(--border-color)', marginBottom: '10px',
              }}>
                {label(tactic)}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {(byTactic.get(tactic) ?? []).map(technique => {
                  const events = eventsFor(technique);
                  return (
                    <div
                      key={technique}
                      title={
                        events > 0
                          ? `${technique} — ${events} event${events === 1 ? '' : 's'}`
                          : `${technique} — covered, never seen here`
                      }
                      style={{
                        ...cellStyle(technique),
                        border: '1px solid', borderRadius: '6px',
                        padding: '9px 10px', fontSize: '0.78125rem',
                        display: 'flex', justifyContent: 'space-between', gap: '8px',
                      }}
                    >
                      <span style={{ fontWeight: 600 }}>{technique}</span>
                      {events > 0 && <span style={{ opacity: 0.85 }}>{events}</span>}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default AttackCoverage;
