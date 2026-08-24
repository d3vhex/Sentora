import React, { useCallback, useEffect, useState } from 'react';
import { Grid3x3, ShieldAlert, ShieldCheck, EyeOff, AlertTriangle } from 'lucide-react';
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
 * Techniques come from the installed Sigma rules' own `tags`, so this is
 * derived from what is actually loaded rather than from a hand-kept table
 * that can claim coverage the platform does not have.
 */

type Coverage = {
  covered: string[];
  observed: { technique: string; events: number }[];
  covered_count: number;
  observed_count: number;
  quiet: string[];
  uncovered_but_seen: string[];
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
};

const tacticOf = (technique: string): string =>
  TECHNIQUE_TACTIC[technique.split('.')[0]] || 'other';

const label = (tactic: string): string =>
  tactic.split('-').map(w => w[0].toUpperCase() + w.slice(1)).join(' ');

const StatCard: React.FC<{
  label: string; value: React.ReactNode; sub: string;
  color: string; icon: React.ReactNode;
}> = ({ label, value, sub, color, icon }) => (
  <div className="card" style={{ padding: '20px' }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px', color }}>
      {icon}
      <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>{label}</span>
    </div>
    <div style={{ fontSize: '1.75rem', fontWeight: 700, color }}>{value}</div>
    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px' }}>{sub}</div>
  </div>
);

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
          Which techniques the installed Sigma rules can detect, and which have
          actually fired here. Read from the rules&rsquo; own tags, so nothing
          here claims coverage the platform does not have.
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
          sub="an installed Sigma rule addresses these"
          color="#6ee7b7" icon={<ShieldCheck size={16} />}
        />
        <StatCard
          label="Seen here" value={data?.observed_count ?? '—'}
          sub="fired at least once on this estate"
          color="#fca5a5" icon={<ShieldAlert size={16} />}
        />
        <StatCard
          label="Seen with no rule" value={data?.uncovered_but_seen.length ?? '—'}
          sub="surfaced by the AI or the regex list, not by Sigma"
          color="#fbbf24" icon={<EyeOff size={16} />}
        />
      </div>

      {!loading && data && data.covered_count === 0 && (
        <div style={{
          marginBottom: '24px', padding: '14px 16px', borderRadius: '8px', fontSize: '0.8125rem',
          backgroundColor: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)',
          color: '#fbbf24', lineHeight: 1.6,
        }}>
          <strong style={{ display: 'block', marginBottom: '4px' }}>No Sigma rules installed.</strong>
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
