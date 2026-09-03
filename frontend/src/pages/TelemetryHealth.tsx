/**
 * Does this host's telemetry actually arrive? Per table, end to end.
 *
 * The page exists because five different failures all looked the same from
 * the console: an empty table. A collector that never ran, a batch the server
 * discarded, a send that has been failing for hours, data collected two
 * seconds ago and not yet shipped, and a host that genuinely has nothing to
 * report are five different problems needing five different people to do five
 * different things — and every one of them rendered as a blank list.
 *
 * The numbers on either side of each row are the whole point. The agent says
 * what it holds and believes it shipped; the server says what it holds. Where
 * those disagree, the chain is broken and the row says where.
 *
 * Broken rows sort first. A page that needs scrolling to find the problem is a
 * page nobody opens twice.
 */
import { useCallback, useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Activity, ChevronLeft, RefreshCw } from 'lucide-react';
import api from '../services/api';
import {
  PageHeader, Card, Badge, DataTable, Row, Cell,
  EmptyState, ErrorState, LoadingState, StatCard, Tone,
} from '../components/ui';

type TableHealth = {
  table: string;
  state: string;
  detail: string;
  agent_held: number | null;
  agent_unsent: number | null;
  agent_shipped: number | null;
  agent_last_error: string | null;
  server_rows: number | null;
};

/** Severity of each state, and the order they sort in. `lost in transit` is
 *  first because it is the one that is actively losing data right now. */
const STATE_TONE: Record<string, Tone> = {
  'lost in transit': 'critical',
  'send failing': 'critical',
  'not collected': 'high',
  'no table': 'medium',
  queued: 'low',
  empty: 'neutral',
  flowing: 'ok',
};

const STATE_RANK: Record<string, number> = {
  'lost in transit': 0,
  'send failing': 1,
  'not collected': 2,
  'no table': 3,
  queued: 4,
  empty: 5,
  flowing: 6,
};

const rank = (s: string) => STATE_RANK[s] ?? 99;
const tone = (s: string): Tone => STATE_TONE[s] ?? 'neutral';
const num = (v: number | null) => (v === null || v === undefined ? '—' : v);

export default function TelemetryHealth() {
  const { agentName = '' } = useParams();
  const [rows, setRows] = useState<TableHealth[]>([]);
  const [broken, setBroken] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.get(
        `/telemetry-health/${encodeURIComponent(agentName)}`);
      setRows(res.data?.tables ?? []);
      setBroken(res.data?.broken_count ?? 0);
    } catch (e: any) {
      // Said out loud, and distinguished from "everything is fine". An
      // unreachable agent and a healthy one must never render alike — that
      // ambiguity is the reason this page exists.
      setError(e?.response?.data?.message || e?.message || 'Request failed');
    } finally {
      setLoading(false);
    }
  }, [agentName]);

  useEffect(() => { load(); }, [load]);

  const sorted = [...rows].sort(
    (a, b) => rank(a.state) - rank(b.state) || a.table.localeCompare(b.table));
  const flowing = rows.filter((r) => r.state === 'flowing').length;

  return (
    <div style={{ padding: 'var(--space-6)', animation: 'fadeIn 0.2s ease' }}>
      <PageHeader
        icon={<Activity size={20} style={{ color: 'var(--accent-secondary)' }} />}
        title={`Telemetry health — ${agentName}`}
        subtitle="What the agent holds and believes it shipped, beside what this
                  server actually holds. Where the two disagree, the chain is
                  broken — and every one of those breaks used to look like an
                  ordinary empty table."
        actions={
          <>
            <Link to={`/agent/${encodeURIComponent(agentName)}`} className="btn-secondary"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)' }}>
              <ChevronLeft size={14} /> Back to host
            </Link>
            <button className="btn-secondary" onClick={load}
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)' }}>
              <RefreshCw size={14} /> Refresh
            </button>
          </>
        }
      />

      {loading && <LoadingState label="Asking the agent…" />}
      {!loading && error && (
        <ErrorState title="Could not reach this agent" detail={error} />
      )}

      {!loading && !error && (
        <>
          <div className="responsive-grid" style={{ marginBottom: 'var(--space-5)' }}>
            <StatCard
              label="Tables with a broken link" value={broken}
              sub="collected but not arriving, or not collected at all"
              color={broken ? 'var(--sev-critical)' : undefined}
            />
            <StatCard
              label="Flowing" value={flowing}
              sub="collected here, shipped, and present on this server"
              color="var(--accent-success)"
            />
            <StatCard
              label="Tables reported" value={rows.length}
              sub="everything this agent ships"
            />
          </div>

          {rows.length === 0 ? (
            <EmptyState
              title="The agent reported no tables"
              detail="Which is itself a finding — rebuild and reinstall it."
            />
          ) : (
            <Card>
              <DataTable columns={[
                'Table', 'State', 'Held', 'Unsent', 'Shipped', 'On server', 'Detail',
              ]}>
                {sorted.map((r) => (
                  <Row key={r.table}>
                    <Cell mono>{r.table}</Cell>
                    <Cell><Badge tone={tone(r.state)}>{r.state}</Badge></Cell>
                    <Cell mono align="right">{num(r.agent_held)}</Cell>
                    <Cell mono align="right">{num(r.agent_unsent)}</Cell>
                    <Cell mono align="right">{num(r.agent_shipped)}</Cell>
                    <Cell mono align="right">{num(r.server_rows)}</Cell>
                    <Cell>
                      {r.detail}
                      {r.agent_last_error && (
                        <div className="mono" style={{
                          marginTop: 'var(--space-1)',
                          color: 'var(--sev-critical)',
                          fontSize: 'var(--text-xs)',
                        }}>
                          {r.agent_last_error}
                        </div>
                      )}
                    </Cell>
                  </Row>
                ))}
              </DataTable>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
