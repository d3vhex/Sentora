/**
 * Search, with the three things it could not do.
 *
 * The previous version was free text across every field, over the whole
 * retention, first N results, no way to reach the N+1th. So the question an
 * operator actually has — "what happened on that host between two and four,
 * with severity critical" — could not be asked at all.
 *
 * Filters and text are the same thing here. Clicking a filter writes the
 * query; the query stays editable, so somebody who knows the syntax is never
 * fighting the builder, and somebody who does not can learn it by watching
 * what their clicks produce. A builder that hides the query teaches nothing
 * and a bare text box helps nobody on their first day.
 *
 * Two tabs, not one ranked list. Logs are raw telemetry and Events are what
 * the rules decided about it; merging them would mean deciding whether a log
 * line outranks a detection, and there is no answer to that.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Search as SearchIcon, Plus, X, ChevronLeft, ChevronRight } from 'lucide-react';
import api from '../services/api';
import {
  PageHeader, Card, Badge, DataTable, Row, Cell,
  EmptyState, ErrorState, LoadingState, Tone,
} from '../components/ui';

type Tab = 'logs' | 'events';

type Filter = { field: string; op: ':' | '!='; value: string };

const RANGES = [
  { label: '1h', from: 'now-1h' },
  { label: '24h', from: 'now-24h' },
  { label: '7d', from: 'now-7d' },
  { label: '30d', from: 'now-30d' },
];

const SEVERITY_TONE: Record<string, Tone> = {
  critical: 'critical', high: 'high', medium: 'medium',
  low: 'low', info: 'info',
};

/** Filters -> the Lucene the server runs. The one place the two agree. */
function toQuery(filters: Filter[]): string {
  return filters
    .filter((f) => f.field && f.value)
    .map((f) => {
      const value = /[\s"]/.test(f.value) ? `"${f.value.replace(/"/g, '\\"')}"`
                                          : f.value;
      return f.op === ':' ? `${f.field}:${value}` : `NOT ${f.field}:${value}`;
    })
    .join(' AND ');
}

export default function Search() {
  const [tab, setTab] = useState<Tab>('logs');
  const [filters, setFilters] = useState<Filter[]>([]);
  const [query, setQuery] = useState('');
  const [range, setRange] = useState('now-24h');
  const [fields, setFields] = useState<string[]>([]);
  const [hits, setHits] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [ran, setRan] = useState(false);

  useEffect(() => {
    api.get('/api/logs/fields')
      .then((r) => setFields(r.data?.fields ?? []))
      .catch(() => setFields([]));
  }, []);

  const run = useCallback(async (nextPage = 1) => {
    setLoading(true);
    setError('');
    try {
      const path = tab === 'logs' ? '/api/logs/search' : '/api/events/search';
      const params: any = { q: query, page: nextPage, size: 50 };
      if (tab === 'logs') params.from = range;
      else params.hours = { 'now-1h': 1, 'now-24h': 24, 'now-7d': 168, 'now-30d': 720 }[range] ?? 24;

      const res = await api.get(path, { params });
      setHits(res.data?.hits ?? []);
      setTotal(res.data?.total ?? 0);
      setPages(res.data?.pages ?? 1);
      setPage(nextPage);
    } catch (e: any) {
      // A search that could not run must never render as one that found
      // nothing. The engine's own message is what tells somebody they wrote
      // `severtiy:high`.
      setError(e?.response?.data?.message || e?.message || 'Search failed');
      setHits([]);
      setTotal(0);
    } finally {
      setLoading(false);
      setRan(true);
    }
  }, [tab, query, range]);

  const addFilter = (field: string, value: string, op: Filter['op'] = ':') => {
    const next = [...filters, { field, op, value: String(value) }];
    setFilters(next);
    setQuery(toQuery(next));
  };

  const dropFilter = (index: number) => {
    const next = filters.filter((_, i) => i !== index);
    setFilters(next);
    setQuery(toQuery(next));
  };

  const columns = useMemo(() => {
    if (!hits.length) return [];
    const seen = new Set<string>();
    for (const hit of hits.slice(0, 20)) Object.keys(hit).forEach((k) => seen.add(k));
    // Time and host first; they are what a result is read by.
    const preferred = ['@timestamp', 'created_at', 'agent_name', 'agent',
                       'severity', 'source', 'message'];
    const rest = [...seen].filter((c) => !preferred.includes(c) && !c.startsWith('_'));
    return [...preferred.filter((c) => seen.has(c)), ...rest].slice(0, 8);
  }, [hits]);

  const agentOf = (hit: any) => hit.agent_name || hit.agent || '';

  return (
    <div style={{ padding: 'var(--space-6)', animation: 'fadeIn 0.2s ease' }}>
      <PageHeader
        icon={<SearchIcon size={20} style={{ color: 'var(--accent-secondary)' }} />}
        title="Search"
        subtitle="Logs are the raw telemetry; Events are what the rules decided
                  about it. Filters write the query below, and the query stays
                  editable."
      />

      <Card style={{ marginBottom: 'var(--space-5)' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)',
                      marginBottom: 'var(--space-4)' }}>
          {(['logs', 'events'] as Tab[]).map((t) => (
            <button key={t} className={tab === t ? 'btn-primary' : 'btn-secondary'}
                    onClick={() => { setTab(t); setHits([]); setRan(false); }}>
              {t === 'logs' ? 'Logs' : 'Events'}
            </button>
          ))}
          <div style={{ flex: 1 }} />
          {RANGES.map((r) => (
            <button key={r.from}
                    className={range === r.from ? 'btn-primary' : 'btn-secondary'}
                    onClick={() => setRange(r.from)}>
              {r.label}
            </button>
          ))}
        </div>

        <FilterBuilder fields={fields} onAdd={addFilter} />

        {filters.length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)',
                        margin: 'var(--space-3) 0' }}>
            {filters.map((f, i) => (
              <span key={`${f.field}-${i}`} className="mono" style={{
                display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)',
                border: '1px solid var(--border-color)',
                borderRadius: 'var(--radius-sm)', padding: '1px var(--space-2)',
                fontSize: 'var(--text-xs)',
              }}>
                {f.op === '!=' && <span style={{ color: 'var(--sev-critical)' }}>NOT</span>}
                {f.field}:{f.value}
                <button onClick={() => dropFilter(i)}
                        style={{ color: 'var(--text-muted)', display: 'flex' }}>
                  <X size={11} />
                </button>
              </span>
            ))}
          </div>
        )}

        <form onSubmit={(e) => { e.preventDefault(); run(1); }}
              style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-3)' }}>
          <input
            className="mono"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={tab === 'logs'
              ? 'severity:critical AND source:sshd'
              : 'free text across the decrypted fields'}
            style={{ flex: 1, minWidth: 0 }}
          />
          <button type="submit" className="btn-primary">Search</button>
        </form>
        {tab === 'events' && (
          <div style={{ marginTop: 'var(--space-2)', color: 'var(--text-muted)',
                        fontSize: 'var(--text-xs)' }}>
            Events are stored encrypted, so this matches after decryption rather
            than in SQL — free text, not field syntax.
          </div>
        )}
      </Card>

      {loading && <LoadingState label="Searching…" />}
      {!loading && error && <ErrorState title="The search did not run" detail={error} />}
      {!loading && !error && ran && hits.length === 0 && (
        <EmptyState
          title="No matches in this window"
          detail="Which is an answer, not a failure — widen the range or drop a filter."
        />
      )}

      {!loading && !error && hits.length > 0 && (
        <Card
          title={`${total} match${total === 1 ? '' : 'es'}`}
          actions={
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <button className="btn-secondary" disabled={page <= 1}
                      onClick={() => run(page - 1)}><ChevronLeft size={14} /></button>
              <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                {page} / {pages}
              </span>
              <button className="btn-secondary" disabled={page >= pages}
                      onClick={() => run(page + 1)}><ChevronRight size={14} /></button>
            </div>
          }
        >
          <DataTable columns={[...columns, '']}>
            {hits.map((hit, i) => (
              <Row key={hit.id ?? i}>
                {columns.map((col) => (
                  <Cell key={col} mono={col !== 'message'}>
                    {col === 'severity' && hit[col] ? (
                      <Badge tone={SEVERITY_TONE[String(hit[col]).toLowerCase()] ?? 'neutral'}>
                        {hit[col]}
                      </Badge>
                    ) : (
                      /* Click a value to narrow, which is how a search
                         becomes an investigation rather than one question. */
                      <button
                        onClick={() => addFilter(col, hit[col])}
                        title={`Narrow to ${col}:${hit[col]}`}
                        style={{ color: 'inherit', textAlign: 'left',
                                 maxWidth: '46ch', overflow: 'hidden',
                                 textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                      >
                        {String(hit[col] ?? '')}
                      </button>
                    )}
                  </Cell>
                ))}
                <Cell>
                  {agentOf(hit) && (
                    <Link to={`/agent/${encodeURIComponent(agentOf(hit))}`}
                          style={{ color: 'var(--accent-secondary)',
                                   fontSize: 'var(--text-xs)', whiteSpace: 'nowrap' }}>
                      Open host
                    </Link>
                  )}
                </Cell>
              </Row>
            ))}
          </DataTable>
        </Card>
      )}
    </div>
  );
}

function FilterBuilder({
  fields, onAdd,
}: { fields: string[]; onAdd: (f: string, v: string, op: Filter['op']) => void }) {
  const [field, setField] = useState('');
  const [op, setOp] = useState<Filter['op']>(':');
  const [value, setValue] = useState('');

  const add = () => {
    if (!field || !value) return;
    onAdd(field, value, op);
    setValue('');
  };

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)',
                  alignItems: 'center' }}>
      <input list="search-fields" value={field} placeholder="field"
             onChange={(e) => setField(e.target.value)} style={{ minWidth: '180px' }} />
      <datalist id="search-fields">
        {fields.map((f) => <option key={f} value={f} />)}
      </datalist>
      <select value={op} onChange={(e) => setOp(e.target.value as Filter['op'])}>
        <option value=":">is</option>
        <option value="!=">is not</option>
      </select>
      <input value={value} placeholder="value" onChange={(e) => setValue(e.target.value)}
             onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add(); } }}
             style={{ minWidth: '180px' }} />
      <button className="btn-secondary" onClick={add}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)' }}>
        <Plus size={14} /> Filter
      </button>
    </div>
  );
}
