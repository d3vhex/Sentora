/**
 * What happened on one host, laid out as a kill chain.
 *
 * A list of techniques tells you what was seen. It does not tell you that
 * execution was followed by persistence and then credential access - and that
 * is the difference between a suspicious command and an intrusion, which is
 * exactly what an analyst is trying to establish when they open a host.
 *
 * Drawn in kill-chain order, not in time order, with the stages that did *not*
 * happen shown as gaps. The gaps are the point: a chain with holes in it is
 * readable, and a list of the four tactics that did fire is not - you cannot
 * see from it that nothing was ever exfiltrated.
 *
 * Timestamps sit alongside, because a chain whose stages are days apart is a
 * different story from one that completed inside a minute, and only the order
 * makes either legible.
 *
 * Written against `components/ui` rather than with its own inline styles.
 * That is the point of the new primitives, and this is the first page to use
 * them end to end.
 */
import { useCallback, useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { GitBranch, ChevronLeft } from 'lucide-react';
import api from '../services/api';
import {
  PageHeader, Card, Badge, EmptyState, ErrorState, LoadingState,
} from '../components/ui';

type Stage = {
  tactic: string;
  position: number;
  techniques: string[];
  events: number;
  first_seen: string | null;
  last_seen: string | null;
};

type ChainResponse = {
  chain: Stage[];
  tactic_order: string[];
  hours: number;
};

const RANGES = [
  { label: '24 hours', hours: 24 },
  { label: '7 days', hours: 168 },
  { label: '30 days', hours: 720 },
];

const readable = (tactic: string) =>
  tactic.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

const when = (value: string | null) => {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
};

export default function AttackChain() {
  const { agentName = '' } = useParams();
  const [data, setData] = useState<ChainResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [hours, setHours] = useState(168);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.get(`/attack-chain/${encodeURIComponent(agentName)}`, {
        params: { hours },
      });
      setData(res.data);
    } catch (e: any) {
      // Said out loud. An empty chain and a chain that failed to load look
      // identical, and only one of them means the host is quiet.
      setError(e?.response?.data?.message || e?.message || 'Request failed');
    } finally {
      setLoading(false);
    }
  }, [agentName, hours]);

  useEffect(() => { load(); }, [load]);

  const seen = new Map((data?.chain ?? []).map((s) => [s.tactic, s]));
  const order = data?.tactic_order ?? [];

  return (
    <div style={{ padding: 'var(--space-6)', animation: 'fadeIn 0.2s ease' }}>
      <PageHeader
        icon={<GitBranch size={20} style={{ color: 'var(--accent-secondary)' }} />}
        title={`Attack chain — ${agentName}`}
        subtitle="Tactics seen on this host, in kill-chain order. The stages that
                  did not happen are shown as gaps, because a chain with holes in
                  it says more than a list of the ones that fired."
        actions={
          <>
            <Link to={`/agent/${encodeURIComponent(agentName)}`} className="btn-secondary"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)' }}>
              <ChevronLeft size={14} /> Back to host
            </Link>
            {RANGES.map((r) => (
              <button
                key={r.hours}
                className={r.hours === hours ? 'btn-primary' : 'btn-secondary'}
                onClick={() => setHours(r.hours)}
              >
                {r.label}
              </button>
            ))}
          </>
        }
      />

      {loading && <LoadingState label="Reading this host's telemetry…" />}
      {!loading && error && (
        <ErrorState title="Could not load the chain" detail={error} />
      )}
      {!loading && !error && seen.size === 0 && (
        <EmptyState
          title="Nothing detected on this host in this window"
          detail="Which is the normal state. Widen the range if you are looking for
                  something specific."
        />
      )}

      {!loading && !error && seen.size > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
          {order.map((tactic) => {
            const stage = seen.get(tactic);
            return (
              <Card
                key={tactic}
                style={{
                  padding: 'var(--space-3) var(--space-4)',
                  opacity: stage ? 1 : 0.45,
                  borderStyle: stage ? 'solid' : 'dashed',
                }}
              >
                <div style={{
                  display: 'flex', flexWrap: 'wrap', gap: 'var(--space-3)',
                  alignItems: 'baseline', justifyContent: 'space-between',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    <span className="mono" style={{ color: 'var(--text-muted)' }}>
                      {String(order.indexOf(tactic) + 1).padStart(2, '0')}
                    </span>
                    <strong style={{ fontSize: 'var(--text-base)' }}>
                      {readable(tactic)}
                    </strong>
                    {stage
                      ? <Badge tone="critical">{stage.events} events</Badge>
                      : <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                          not seen
                        </span>}
                  </div>
                  {stage && (
                    <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                      {when(stage.first_seen)} → {when(stage.last_seen)}
                    </span>
                  )}
                </div>

                {stage && (
                  <div style={{
                    display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)',
                    marginTop: 'var(--space-2)', marginLeft: 'var(--space-6)',
                  }}>
                    {stage.techniques.map((t) => (
                      <span key={t} className="mono" style={{
                        fontSize: 'var(--text-xs)', color: 'var(--text-secondary)',
                        border: '1px solid var(--border-color)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '1px var(--space-2)',
                      }}>
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
