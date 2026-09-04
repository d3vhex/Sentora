import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { StatCard, Card } from '../components/ui';
import { CategoryBars, ShareDonut } from '../components/ui/charts';
import { Radar, RefreshCw, Search, AlertTriangle, Globe, FileDigit, Link2, Server } from 'lucide-react';
import { agentService, adminService, authService } from '../services/api';

type Indicator = {
  id: number;
  type: string;
  value: string;
  source: string;
  severity: string;
  description: string;
  created_at?: string;
  last_seen?: string;
};

const chartNote: React.CSSProperties = {
  margin: '0 0 var(--space-3)', color: 'var(--text-muted)',
  fontSize: 'var(--text-xs)', maxWidth: '58ch',
};

const SEVERITY_STYLE: Record<string, { color: string; bg: string }> = {
  CRITICAL: { color: '#ef4444', bg: 'rgba(239,68,68,0.10)' },
  HIGH: { color: '#f97316', bg: 'rgba(249,115,22,0.10)' },
  MEDIUM: { color: '#facc15', bg: 'rgba(250,204,21,0.10)' },
  LOW: { color: '#34d399', bg: 'rgba(52,211,153,0.10)' },
};

const TYPE_ICON: Record<string, React.ReactNode> = {
  ip: <Server size={13} />,
  domain: <Globe size={13} />,
  url: <Link2 size={13} />,
  hash: <FileDigit size={13} />,
};

/** "3 hours ago" / "12 days ago" — the number that matters for a feed. */
const relativeAge = (iso?: string | null): string => {
  if (!iso) return 'never';
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return 'unknown';
  const mins = Math.max(0, Math.round((Date.now() - then) / 60000));
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} d ago`;
};

const ThreatIntel: React.FC = () => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshNote, setRefreshNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');

  const canRefresh = authService.hasPermission('manage_system');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setData(await agentService.getThreatIntel({
        q: query || undefined,
        type: typeFilter || undefined,
        source: sourceFilter || undefined,
        limit: 200,
      }));
    } catch (err) {
      console.error('Threat intel fetch failed', err);
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [query, typeFilter, sourceFilter]);

  // Debounced so typing in the search box does not fire a query per keystroke.
  useEffect(() => {
    const t = setTimeout(load, 350);
    return () => clearTimeout(t);
  }, [load]);

  const handleRefresh = async () => {
    setRefreshing(true);
    setRefreshNote(null);
    try {
      const res = await adminService.refreshThreatIntel();
      // Feed errors are shown rather than logged: an abuse.ch key requirement
      // is something the operator has to act on, and they are standing right
      // in front of this button.
      setRefreshNote({
        ok: !res.errors?.length,
        text: res.errors?.length
          ? `Fetched ${res.fetched}. Problems: ${res.errors.join(' · ')}`
          : `Fetched ${res.fetched} indicator(s), ${res.written} row(s) written.`,
      });
      load();
    } catch (err: any) {
      setRefreshNote({ ok: false, text: err?.response?.data?.message || 'Refresh failed.' });
    } finally {
      setRefreshing(false);
    }
  };

  const stats = data?.stats;
  const indicators: Indicator[] = data?.indicators || [];

  /* Both read the same `stats` the counters and the source list read, so a
     chart cannot disagree with the row beside it. */
  const typeShare = useMemo(() => (
    (stats?.by_type || [])
      .map((t: any) => ({ name: String(t.type || 'unknown'), value: Number(t.n) || 0 }))
      .sort((a: any, b: any) => b.value - a.value)
      .slice(0, 8)
  ), [stats]);

  const sourceShare = useMemo(() => (
    (stats?.by_source || [])
      .map((t: any) => ({ name: String(t.source || 'unknown'), value: Number(t.n) || 0 }))
      .sort((a: any, b: any) => b.value - a.value)
      .slice(0, 6)
  ), [stats]);
  const feedsOff = stats?.mode === 'off';

  return (
    <div style={{ paddingBottom: '60px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '32px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2 style={{ fontSize: '1.875rem', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Radar color="var(--accent-secondary)" /> Threat Intelligence
          </h2>
          <p style={{ color: 'var(--text-secondary)' }}>
            Known-bad indicators pulled from abuse.ch. Matched against incoming telemetry.
          </p>
        </div>
        {canRefresh && (
          <button
            onClick={handleRefresh}
            disabled={refreshing || feedsOff}
            title={feedsOff ? 'Feeds are disabled (THREAT_INTEL_MODE=off)' : 'Pull the feeds now'}
            style={{
              display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 18px',
              borderRadius: '8px', fontWeight: 600, fontSize: '0.875rem', color: 'white',
              backgroundColor: (refreshing || feedsOff) ? 'var(--border-color)' : 'var(--accent-secondary)',
              cursor: (refreshing || feedsOff) ? 'not-allowed' : 'pointer',
            }}
          >
            <RefreshCw size={16} className={refreshing ? 'animate-spin' : ''} />
            {refreshing ? 'Fetching…' : 'Refresh feeds'}
          </button>
        )}
      </div>

      {refreshNote && (
        <div style={{
          marginBottom: '20px', padding: '12px 14px', borderRadius: '8px', fontSize: '0.8125rem',
          backgroundColor: refreshNote.ok ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
          border: `1px solid ${refreshNote.ok ? 'rgba(16,185,129,0.25)' : 'rgba(239,68,68,0.25)'}`,
          color: refreshNote.ok ? 'var(--accent-success)' : '#fca5a5',
        }}>
          {refreshNote.text}
        </div>
      )}

      {feedsOff && (
        <div style={{
          marginBottom: '20px', padding: '12px 14px', borderRadius: '8px', fontSize: '0.8125rem',
          backgroundColor: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)',
          color: '#fbbf24', display: 'flex', gap: '10px', alignItems: 'center',
        }}>
          <AlertTriangle size={16} />
          Feeds are disabled (<code>THREAT_INTEL_MODE=off</code>). Indicators below are whatever
          was last stored — nothing is being refreshed.
        </div>
      )}

      {/* Freshness first. "Is this data current?" is the first question anyone
          has about a threat feed, and it used to be unanswerable. */}
      <div className="responsive-grid" style={{ marginBottom: '28px' }}>
        <StatCard label="Indicators" value={stats?.total ?? '—'} sub={`${stats?.by_type?.length ?? 0} types`} />
        <StatCard
          label="Last updated"
          value={relativeAge(stats?.newest)}
          sub={stats?.newest ? new Date(stats.newest).toLocaleString() : 'no data yet'}
          color={!stats?.newest ? 'var(--accent-warning)' : undefined}
        />
        <StatCard
          label="Feeds"
          value={feedsOff ? 'off' : String(stats?.feeds_enabled?.length ?? 0)}
          sub={feedsOff ? 'air-gap mode' : (stats?.feeds_enabled || []).join(', ')}
        />
        <StatCard
          label="Pruned after"
          value={`${stats?.stale_after_days ?? '—'} d`}
          sub="indicators not re-seen"
        />
      </div>

      {/* The counters say how many indicators are held; these say what kind
          they are and where they came from. Both matter, because a feed list
          that is 99% one source is one outage away from being empty, and a
          store that is all file hashes will not match network telemetry. */}
      <div className="responsive-grid" style={{ marginBottom: '28px' }}>
        <Card title="By indicator type">
          <p style={chartNote}>
            What the store can actually match on. Hashes match process
            telemetry; addresses and domains match connections.
          </p>
          <CategoryBars data={typeShare} />
        </Card>
        <Card title="Share by feed">
          <p style={chartNote}>
            How concentrated the intel is. One feed carrying nearly all of it
            means one broken key takes the coverage with it.
          </p>
          <ShareDonut data={sourceShare} />
        </Card>
      </div>

      {/* Per-source breakdown: a feed that stopped refreshing shows an old
          timestamp here instead of just quietly shrinking as pruning runs. */}
      {!!stats?.by_source?.length && (
        <div className="card" style={{ padding: '20px', marginBottom: '28px' }}>
          <h3 style={{ fontSize: '0.875rem', fontWeight: 700, marginBottom: '14px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-secondary)' }}>
            By source
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {stats.by_source.map((s: any) => {
              const ageMins = s.newest ? (Date.now() - Date.parse(s.newest)) / 60000 : Infinity;
              const stale = ageMins > 60 * 26;   // more than a day of missed hourly refreshes
              return (
                <div key={s.source} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8125rem', padding: '8px 0', borderTop: '1px solid var(--border-color)' }}>
                  <button
                    onClick={() => setSourceFilter(sourceFilter === s.source ? '' : s.source)}
                    style={{
                      fontWeight: 600, color: sourceFilter === s.source ? 'var(--accent-secondary)' : 'var(--text-primary)',
                      background: 'none', border: 'none', cursor: 'pointer', padding: 0, textAlign: 'left',
                    }}
                  >
                    {s.source || 'unknown'}
                  </button>
                  <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                    <span style={{ color: stale ? 'var(--accent-warning)' : 'var(--text-secondary)' }}>
                      {relativeAge(s.newest)}
                    </span>
                    <span style={{ fontWeight: 700, minWidth: '60px', textAlign: 'right' }}>
                      {s.n.toLocaleString()}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: '1 1 320px' }}>
          <Search size={18} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search an address, domain, URL or hash…"
            style={{
              width: '100%', backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)',
              borderRadius: '10px', padding: '12px 12px 12px 44px', color: 'var(--text-primary)',
              fontSize: '0.875rem', outline: 'none', fontFamily: 'monospace',
            }}
          />
        </div>
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          style={{ backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '12px 16px', color: 'var(--text-primary)', fontSize: '0.875rem', outline: 'none', cursor: 'pointer' }}
        >
          <option value="">All types</option>
          {(stats?.by_type || []).map((t: any) => (
            <option key={t.type} value={t.type}>{t.type} ({t.n})</option>
          ))}
        </select>
        {sourceFilter && (
          <button
            onClick={() => setSourceFilter('')}
            style={{ padding: '12px 16px', borderRadius: '10px', border: '1px solid var(--border-color)', color: 'var(--text-primary)', fontSize: '0.8125rem', fontWeight: 600 }}
          >
            {sourceFilter} ✕
          </button>
        )}
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: '60px', textAlign: 'center' }}>
            <RefreshCw size={36} className="animate-spin" style={{ opacity: 0.15 }} />
          </div>
        ) : indicators.length === 0 ? (
          <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <Radar size={44} style={{ opacity: 0.1, marginBottom: '14px' }} />
            <p style={{ fontSize: '0.9375rem', marginBottom: '6px' }}>
              {query || typeFilter || sourceFilter ? 'No indicators match this filter.' : 'No indicators stored yet.'}
            </p>
            {!query && !typeFilter && !sourceFilter && !feedsOff && (
              <p style={{ fontSize: '0.8125rem', opacity: 0.75 }}>
                Feeds refresh hourly. Use “Refresh feeds” to pull now — if a feed needs an
                abuse.ch key, the error will say so.
              </p>
            )}
          </div>
        ) : (
          <>
            <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border-color)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Showing {data.returned} of {data.matched.toLocaleString()} matching
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
                <tbody>
                  {indicators.map(ind => {
                    const sev = SEVERITY_STYLE[(ind.severity || '').toUpperCase()] || SEVERITY_STYLE.MEDIUM;
                    return (
                      <tr key={ind.id} style={{ borderTop: '1px solid var(--border-color)' }}>
                        <td style={{ padding: '12px 20px', width: '90px' }}>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '0.7rem', fontWeight: 700 }}>
                            {TYPE_ICON[ind.type] || null} {ind.type}
                          </span>
                        </td>
                        <td style={{ padding: '12px 0', fontFamily: 'monospace', color: 'var(--text-primary)', wordBreak: 'break-all', maxWidth: '380px' }}>
                          {ind.value}
                        </td>
                        <td style={{ padding: '12px 16px', width: '110px' }}>
                          <span style={{ padding: '3px 9px', borderRadius: '5px', fontSize: '0.68rem', fontWeight: 700, color: sev.color, backgroundColor: sev.bg, border: `1px solid ${sev.color}33` }}>
                            {ind.severity}
                          </span>
                        </td>
                        <td style={{ padding: '12px 16px', color: 'var(--text-secondary)', maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ind.description}>
                          {ind.description}
                        </td>
                        <td style={{ padding: '12px 20px', color: 'var(--text-secondary)', whiteSpace: 'nowrap', textAlign: 'right', fontSize: '0.75rem' }}>
                          {ind.source}
                          <div style={{ opacity: 0.65 }}>{relativeAge(ind.last_seen)}</div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default ThreatIntel;
