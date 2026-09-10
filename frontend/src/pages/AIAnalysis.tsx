/**
 * What the triage model has said about this estate, and what it could not say.
 *
 * Two things were wrong here beyond the styling.
 *
 * The header carried a green pill reading "RabbitMQ Worker Active". It was
 * hardcoded - a `<div>` with a green dot, rendered unconditionally, with no
 * request behind it. It said the worker was up while the worker was down,
 * which on a security console is worse than saying nothing: a health light
 * that is always green is a health light nobody can use. It is gone. The
 * defensive scan below reports what actually happened, including the case
 * where the worker never answers.
 *
 * And `fetchGlobalInsights` caught its own failure, logged it, and set the
 * list to empty - so a failed request rendered "No insights found. System is
 * monitoring." That is a claim, and it was false exactly when it mattered.
 *
 * The filtering logic is unchanged. It was already careful about the
 * difference between "no critical findings" and "no verdict recorded", and
 * that distinction is the point of the page.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  BrainCircuit, Play, Clock, Search, ShieldAlert, Cpu, RefreshCw, Layers,
} from 'lucide-react';
import api, { agentService } from '../services/api';
import { InsightCard } from './AgentDetail';
import { isUnanswered, countUnanswered } from '../lib/insightTriage';
import {
  PageHeader, Card, Field, EmptyState, ErrorState, LoadingState,
} from '../components/ui';

const VERDICTS = [
  'CRITICAL', 'SUSPICIOUS', 'ACT', 'MONITOR',
  'NOT_CRITICAL', 'IGNORE', 'INSUFFICIENT_DATA',
];

const AIAnalysis: React.FC = () => {
  const [agents, setAgents] = useState<any[]>([]);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [agentFilter, setAgentFilter] = useState<string>('all');
  const [insights, setInsights] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [filter, setFilter] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<string>('all');
  const [minConfidence, setMinConfidence] = useState(0);
  const [refreshTick, setRefreshTick] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<string>('');

  const say = (err: any, fallback: string) =>
    err?.response?.data?.error || err?.response?.data?.message || err?.message || fallback;

  const fetchGlobalInsights = useCallback(async () => {
    try {
      const res = await api.get('/api/ai-insights/all');
      if (res.data?.success) {
        setInsights(Array.isArray(res.data.results) ? res.data.results : []);
        setError(null);
      } else {
        // A successful HTTP call that reports failure is still a failure, and
        // it used to land in the same empty list as "there is nothing".
        setError(res.data?.error || 'The insights endpoint reported failure');
      }
    } catch (err) {
      setError(say(err, 'Could not load insights'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchGlobalInsights();
    agentService.getAgents()
      .then((list: any[]) => {
        setAgents(list);
        const first = list.length
          ? (typeof list[0] === 'string' ? list[0] : list[0].name)
          : '';
        setSelectedAgent((current) => current || first);
      })
      .catch(() => { /* the insight list carries its own error; agents are secondary */ });

    const interval = setInterval(() => setRefreshTick((t) => t + 1), 15000);
    return () => clearInterval(interval);
  }, [fetchGlobalInsights]);

  useEffect(() => {
    if (refreshTick) fetchGlobalInsights();
  }, [refreshTick, fetchGlobalInsights]);

  const runManualAnalysis = () => {
    if (!selectedAgent) return;
    setAnalyzing(true);
    agentService.runManualAnalysis(selectedAgent, 100)
      .then((res) => {
        setScanStatus(res.message || 'Manual analysis queued.');
        fetchGlobalInsights();
      })
      .catch((err) => setScanStatus(say(err, 'Failed to start manual analysis')))
      .finally(() => setAnalyzing(false));
  };

  const triggerDefensiveScan = async () => {
    if (!selectedAgent) return;
    setScanning(true);
    setScanStatus('Pushing alerts to the defensive queue…');
    try {
      // Small batch by default — local Ollama models take 20-60s per event;
      // pushing 25 at once means the user waits 10+ minutes for the worker
      // to drain the queue. 5 gives meaningful feedback in ~2 minutes.
      const res = await api.post(`/analyze-defensive/${selectedAgent}`, { limit: 5 });
      const queued = res.data?.queued ?? 0;
      const total = res.data?.total_rows ?? 0;
      const reason = res.data?.reason || '';
      if (!queued) {
        setScanStatus(reason
          ? `Nothing queued (${reason}).`
          : `No alerts for ${selectedAgent}. The agent has to produce events_alert rows first.`);
        setScanning(false);
        return;
      }
      const baselineSnap = (await api.get('/api/ai-insights/all')).data?.results || [];
      const baselineForAgent = baselineSnap.filter((x: any) => x.agent === selectedAgent).length;
      setScanStatus(`Queued ${queued}/${total}. The local model answers roughly one every 20-60s — polling.`);

      const t0 = Date.now();
      const maxIters = 48;          // 8 minutes; each event can take a full minute on CPU
      let producedTotal = 0;
      for (let i = 0; i < maxIters; i++) {
        await new Promise((r) => setTimeout(r, 10000));
        const fresh = (await api.get('/api/ai-insights/all')).data?.results || [];
        setInsights(fresh);
        const agentFresh = fresh.filter((x: any) => x.agent === selectedAgent);
        const producedNow = Math.max(0, agentFresh.length - baselineForAgent);
        producedTotal = producedNow;
        const elapsed = Math.round((Date.now() - t0) / 1000);
        if (producedNow >= queued) {
          setScanStatus(`Done — ${producedNow} new insight(s) for ${selectedAgent} in ${elapsed}s.`);
          break;
        }
        setScanStatus(
          `${producedNow}/${queued} produced · ${elapsed}s elapsed`
          + (producedNow > 0
            ? ` · last at ${agentFresh[0]?.created_at || 'just now'}`
            : ' · still waiting for the first answer'),
        );
      }
      if (producedTotal === 0) {
        setScanStatus(
          'Timed out after 8 minutes with nothing produced. The worker is not answering: '
          + 'check `docker logs sentora-ai-worker-defensive`, and that the model is installed '
          + '(`docker exec sentora-ollama ollama list`).',
        );
      }
      setScanning(false);
    } catch (err) {
      setScanStatus(say(err, 'Defensive scan failed'));
      setScanning(false);
    }
  };

  // Both the live agent list AND every agent that has produced an insight, so
  // the dropdown is not empty just because a newly connected agent has not
  // been analysed yet.
  const agentList = React.useMemo(() => {
    const set = new Set<string>();
    for (const i of insights) if (i.agent) set.add(String(i.agent));
    for (const a of agents) {
      const name = typeof a === 'string' ? a : a?.name;
      if (name) set.add(String(name));
    }
    // localeCompare: agent hostnames can carry Turkish characters, which the
    // default UTF-16 sort pushes past Z.
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [insights, agents]);

  // Verdict and confidence are columns, so these are real filters rather than
  // a substring search over a rendered line. Rows written before those columns
  // existed carry NULL and are excluded once a verdict filter is on — showing
  // them would imply a verdict nobody recorded.
  const filteredInsights = insights.filter((i) => {
    // Rows the model could not answer on are not findings about a host: it
    // contradicted itself, returned nothing parseable, or the event never
    // reached it because it would not decrypt. They stay recorded and stay
    // counted below, but they do not sit in the feed burying real ones.
    if (verdictFilter !== 'INSUFFICIENT_DATA' && isUnanswered(i)) return false;
    if (agentFilter !== 'all' && i.agent !== agentFilter) return false;
    if (verdictFilter !== 'all' && (i.verdict || '') !== verdictFilter) return false;
    if (minConfidence > 0 && Number(i.confidence ?? 0) < minConfidence) return false;
    if (!filter) return true;
    const needle = filter.toLowerCase();
    return (i.agent || '').toLowerCase().includes(needle)
      || (i.critical_summary || '').toLowerCase().includes(needle)
      || (i.source_file || '').toLowerCase().includes(needle);
  });

  // How many rows the verdict filter cannot speak for. Stating this is the
  // difference between "no CRITICAL findings" and "no CRITICAL findings among
  // the rows that carry a verdict".
  const legacyRows = insights.filter((i) => i.verdict == null).length;
  const unansweredRows = countUnanswered(insights);

  const feed = () => {
    if (loading) return <LoadingState label="Reading insights…" />;
    if (error) {
      return (
        <ErrorState
          title="Could not load insights"
          detail={`${error}. This is not "nothing was found" — nothing was read.`}
        />
      );
    }
    if (filteredInsights.length === 0) {
      return (
        <EmptyState
          title={insights.length === 0 ? 'No insights yet' : 'Nothing matches these filters'}
          detail={insights.length === 0
            ? 'Events are triaged as they arrive. Force a defensive scan on the right to push existing alerts through now.'
            : 'Widen the verdict or confidence filter.'}
          icon={<Layers size={18} style={{ color: 'var(--text-muted)' }} />}
        />
      );
    }
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
        {filteredInsights.map((insight, idx) => (
          <div key={insight.id ?? `insight-${idx}`}>
            <div
              style={{
                display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                marginBottom: 'var(--space-2)', fontSize: 'var(--text-xs)',
              }}
            >
              <ShieldAlert size={13} style={{ color: 'var(--text-muted)' }} />
              <span style={{ color: 'var(--text-primary)' }}>{insight.agent || 'unknown'}</span>
              <span
                style={{
                  display: 'flex', alignItems: 'center', gap: 'var(--space-1)',
                  color: 'var(--text-muted)',
                }}
              >
                <Clock size={11} />
                {insight.created_at ? new Date(insight.created_at).toLocaleString() : ''}
              </span>
            </div>
            <InsightCard insight={insight} />
          </div>
        ))}
      </div>
    );
  };

  return (
    <div>
      <PageHeader
        title="AI Triage"
        subtitle="What the model concluded from each event, and — just as importantly — which events it could not answer on."
        icon={<BrainCircuit size={22} />}
        actions={
          <button className="btn-secondary" onClick={fetchGlobalInsights}>
            <RefreshCw size={15} className={loading ? 'animate-spin' : undefined} /> Refresh
          </button>
        }
      />

      <div
        style={{
          display: 'grid', gap: 'var(--space-5)', alignItems: 'start',
          gridTemplateColumns: 'minmax(0, 3fr) minmax(240px, 1fr)',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', flex: '1 1 260px' }}>
              <Search
                size={15}
                style={{
                  position: 'absolute', left: 12, top: '50%',
                  transform: 'translateY(-50%)', color: 'var(--text-muted)',
                }}
              />
              <input
                type="text"
                placeholder="Agent, threat or source…"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                style={{ width: '100%', paddingLeft: 34 }}
              />
            </div>
            <select value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)}>
              <option value="all">Every agent ({insights.length})</option>
              {agentList.map((a) => (
                <option key={a} value={a}>
                  {a} ({insights.filter((i) => i.agent === a).length})
                </option>
              ))}
            </select>
            <select value={verdictFilter} onChange={(e) => setVerdictFilter(e.target.value)}>
              <option value="all">Any verdict</option>
              {VERDICTS.map((v) => (
                <option key={v} value={v}>
                  {v.replace(/_/g, ' ')} ({insights.filter((i) => i.verdict === v).length})
                </option>
              ))}
            </select>
            <select
              value={minConfidence}
              onChange={(e) => setMinConfidence(Number(e.target.value))}
              title="Minimum model confidence"
            >
              <option value={0}>Any confidence</option>
              <option value={0.5}>≥ 0.50</option>
              <option value={0.8}>≥ 0.80</option>
              <option value={0.9}>≥ 0.90</option>
            </select>
          </div>

          {/* A filter that silently drops rows it cannot evaluate would let
              "no CRITICAL findings" stand in for "no verdict recorded". */}
          {(verdictFilter !== 'all' || minConfidence > 0) && legacyRows > 0 && (
            <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--sev-medium)' }}>
              {legacyRows} older insight{legacyRows === 1 ? '' : 's'} carry no verdict column
              and are not included in this filter.
            </p>
          )}

          {/* Hidden as rows, still visible as a number — and reachable, so
              nobody has to guess whether the model is answering at all. */}
          {verdictFilter !== 'INSUFFICIENT_DATA' && unansweredRows > 0 && (
            <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
              {unansweredRows} event{unansweredRows === 1 ? '' : 's'} produced no usable verdict
              and {unansweredRows === 1 ? 'is' : 'are'} not shown —{' '}
              <button
                onClick={() => setVerdictFilter('INSUFFICIENT_DATA')}
                style={{
                  background: 'none', border: 'none', padding: 0, font: 'inherit',
                  color: 'var(--accent-secondary)', cursor: 'pointer',
                  textDecoration: 'underline',
                }}
              >
                show them
              </button>.
            </p>
          )}

          {feed()}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <Card title={<><Cpu size={16} /> Run analysis now</>}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <Field label="Agent">
                <select
                  value={selectedAgent}
                  onChange={(e) => setSelectedAgent(e.target.value)}
                  disabled={agents.length === 0}
                >
                  {agents.length === 0 && <option>No agents</option>}
                  {agents.map((a) => {
                    const name = typeof a === 'string' ? a : a.name;
                    return <option key={name} value={name}>{name}</option>;
                  })}
                </select>
              </Field>

              <button
                className="btn-primary"
                onClick={runManualAnalysis}
                disabled={analyzing || !selectedAgent}
              >
                {analyzing
                  ? <RefreshCw size={15} className="animate-spin" />
                  : <Play size={15} />}
                {analyzing ? 'Queued…' : 'Backfill this agent'}
              </button>

              <button
                className="btn-secondary"
                onClick={triggerDefensiveScan}
                disabled={!selectedAgent || scanning}
                title="Push this agent's most recent alerts back through the defensive worker."
              >
                {scanning
                  ? <RefreshCw size={15} className="animate-spin" />
                  : <ShieldAlert size={15} />}
                {scanning ? 'Scanning…' : 'Force defensive scan'}
              </button>

              {scanStatus && (
                <p
                  style={{
                    margin: 0, padding: 'var(--space-3)',
                    border: '1px solid var(--border-color)',
                    borderRadius: 'var(--radius-md)',
                    fontSize: 'var(--text-xs)', lineHeight: 1.6,
                    color: 'var(--text-secondary)', wordBreak: 'break-word',
                  }}
                >
                  {scanStatus}
                </p>
              )}
            </div>
          </Card>

          <Card title="Counts">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {[
                ['Insights held', insights.length],
                ['Shown by these filters', filteredInsights.length],
                ['No usable verdict', unansweredRows],
                ['Agents with insights', agentList.length],
                ['Agents connected', agents.length],
              ].map(([label, value]) => (
                <div
                  key={label as string}
                  style={{
                    display: 'flex', justifyContent: 'space-between',
                    fontSize: 'var(--text-sm)', color: 'var(--text-secondary)',
                  }}
                >
                  <span>{label}</span>
                  <span style={{ color: 'var(--text-primary)' }}>{value}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default AIAnalysis;
