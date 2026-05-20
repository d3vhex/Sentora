import React, { useState, useEffect } from 'react';
import { BrainCircuit, Play, Clock, Search, ShieldAlert, Cpu, RefreshCw, Layers } from 'lucide-react';
import api, { agentService } from '../services/api';
import { InsightCard } from './AgentDetail';

const AIAnalysis: React.FC = () => {
  const [agents, setAgents] = useState<any[]>([]);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [agentFilter, setAgentFilter] = useState<string>('all');
  const [insights, setInsights] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [filter, setFilter] = useState('');
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    fetchGlobalInsights();
    agentService.getAgents().then(list => {
      setAgents(list);
      if (list.length > 0) {
        const first = typeof list[0] === 'string' ? list[0] : list[0].name;
        setSelectedAgent(first);
      }
    });

    const interval = setInterval(() => setRefreshTick(t => t + 1), 15000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    fetchGlobalInsights();
  }, [refreshTick]);

  const fetchGlobalInsights = async () => {
    try {
      const res = await api.get('/api/ai-insights/all');
      if (res.data?.success) {
        setInsights(Array.isArray(res.data.results) ? res.data.results : []);
      } else {
        setInsights([]);
      }
    } catch (err) {
      console.error('AI Insights fetch error', err);
      setInsights([]);
    } finally {
      setLoading(false);
    }
  };

  const runManualAnalysis = () => {
    if (!selectedAgent) return;
    setAnalyzing(true);
    agentService.runManualAnalysis(selectedAgent, 100)
      .then((res) => {
        alert(res.message || 'Manual analysis queued in background.');
        fetchGlobalInsights();
      })
      .catch(err => {
        console.error('Manual analysis error', err);
        alert('Failed to start manual analysis.');
      })
      .finally(() => setAnalyzing(false));
  };

  const [scanning, setScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<string>('');

  const triggerDefensiveScan = async () => {
    if (!selectedAgent) return;
    setScanning(true);
    setScanStatus('Pushing alerts to defensive AI queue...');
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
          ? `No alerts queued (${reason}). Nothing to analyze for ${selectedAgent}.`
          : `No alerts found for ${selectedAgent}. The agent must produce events_alert rows first.`);
        setScanning(false);
        return;
      }
      const baselineSnap = (await api.get('/api/ai-insights/all')).data?.results || [];
      const baselineForAgent = baselineSnap.filter((x: any) => x.agent === selectedAgent).length;
      setScanStatus(`Queued ${queued}/${total} alerts. Local model processes ~1 every 20-60s — polling...`);

      const t0 = Date.now();
      // Poll for up to 8 minutes — each event can take a full minute on CPU.
      const maxIters = 48;
      let producedTotal = 0;
      for (let i = 0; i < maxIters; i++) {
        await new Promise(r => setTimeout(r, 10000));
        const fresh = (await api.get('/api/ai-insights/all')).data?.results || [];
        setInsights(fresh);
        const agentFresh = fresh.filter((x: any) => x.agent === selectedAgent);
        const producedNow = Math.max(0, agentFresh.length - baselineForAgent);
        producedTotal = producedNow;
        const elapsed = Math.round((Date.now() - t0) / 1000);
        if (producedNow >= queued) {
          setScanStatus(`✓ Done. AI produced ${producedNow} new insight(s) for ${selectedAgent} in ${elapsed}s.`);
          break;
        }
        setScanStatus(
          `Progress: ${producedNow}/${queued} insights produced · ${elapsed}s elapsed` +
          (producedNow > 0 ? ` · last at ${agentFresh[0]?.created_at || 'just now'}` : ' · still waiting for first response')
        );
      }
      if (producedTotal === 0) {
        setScanStatus(
          `Timed out after 8 minutes with 0 new insights. ` +
          `Check: docker logs zer0vuln-ai-worker-defensive — the worker may be stuck on Ollama, ` +
          `or the model isn't installed (docker exec zer0vuln-ollama ollama list).`
        );
      }
      setScanning(false);
    } catch (err: any) {
      console.error('Defensive scan failed', err);
      setScanStatus(`Failed: ${err?.response?.data?.error || err?.message || 'unknown error'}`);
      setScanning(false);
    }
  };

  // Build the dropdown list from BOTH the live agents list AND every agent
  // that has ever produced an insight — so the dropdown isn't empty just
  // because no insight has been emitted yet for a newly-connected agent.
  const agentList = React.useMemo(() => {
    const set = new Set<string>();
    for (const i of insights) if (i.agent) set.add(String(i.agent));
    for (const a of agents) {
      const name = typeof a === 'string' ? a : a?.name;
      if (name) set.add(String(name));
    }
    return Array.from(set).sort();
  }, [insights, agents]);

  const filteredInsights = insights.filter(i => {
    if (agentFilter !== 'all' && i.agent !== agentFilter) return false;
    if (!filter) return true;
    const needle = filter.toLowerCase();
    return (i.agent || '').toLowerCase().includes(needle)
      || (i.critical_summary || '').toLowerCase().includes(needle)
      || (i.source_file || '').toLowerCase().includes(needle);
  });

  return (
    <div style={{ paddingBottom: '60px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '40px', flexWrap: 'wrap', gap: '20px' }}>
        <div>
          <h2 style={{ fontSize: '2.25rem', fontWeight: 800, letterSpacing: '-0.025em', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '16px' }}>
            <BrainCircuit size={36} color="var(--accent-secondary)" />
            AI Security Pulse
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '1.1rem' }}>
            Continuous real-time log triage powered by <strong>Ollama Local AI</strong>.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button
            onClick={fetchGlobalInsights}
            style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 16px', borderRadius: '20px', backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600 }}
            title="Refresh insights"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 16px', backgroundColor: 'rgba(34, 197, 94, 0.1)', color: 'var(--accent-success)', borderRadius: '20px', fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', border: '1px solid rgba(34, 197, 94, 0.2)' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--accent-success)', boxShadow: '0 0 10px var(--accent-success)' }}></div>
            RabbitMQ Worker Active
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 3fr) 1fr', gap: '32px', alignItems: 'start' }}>

        {/* Main Insights Feed */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
            <div style={{ position: 'relative', flex: '1 1 320px' }}>
              <Search style={{ position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} size={20} />
              <input
                type="text"
                placeholder="Search insights by agent, threat, or source..."
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                style={{
                  width: '100%',
                  backgroundColor: 'var(--card-bg)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '12px',
                  padding: '14px 14px 14px 48px',
                  color: 'var(--text-primary)',
                  fontSize: '0.9375rem',
                  outline: 'none',
                }}
              />
            </div>
            <select
              value={agentFilter}
              onChange={(e) => setAgentFilter(e.target.value)}
              style={{
                backgroundColor: 'var(--card-bg)',
                border: '1px solid var(--border-color)',
                borderRadius: '12px',
                padding: '14px 18px',
                color: 'var(--text-primary)',
                fontSize: '0.875rem',
                outline: 'none',
                cursor: 'pointer',
                minWidth: '200px',
              }}
            >
              <option value="all">All Agents ({insights.length})</option>
              {agentList.map(a => (
                <option key={a} value={a}>
                  {a} ({insights.filter(i => i.agent === a).length})
                </option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {loading ? (
              <div style={{ padding: '100px', textAlign: 'center' }}>
                <RefreshCw className="animate-spin" size={48} style={{ opacity: 0.1, marginBottom: '20px' }} />
                <p style={{ color: 'var(--text-secondary)' }}>Loading AI Intelligence...</p>
              </div>
            ) : filteredInsights.length > 0 ? (
              filteredInsights.map((insight, idx) => (
                <div key={insight.id ?? idx}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px', paddingLeft: '4px' }}>
                    <ShieldAlert size={14} color="var(--accent-secondary)" />
                    <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)' }}>{insight.agent || 'unknown'}</span>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Clock size={11} /> {insight.created_at ? new Date(insight.created_at).toLocaleString() : ''}
                    </span>
                  </div>
                  <InsightCard insight={insight} />
                </div>
              ))
            ) : (
              <div style={{ textAlign: 'center', padding: '100px 0', border: '2px dashed var(--border-color)', borderRadius: '24px' }}>
                <Layers size={64} style={{ opacity: 0.1, marginBottom: '24px' }} />
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '8px' }}>No Insights Found</h3>
                <p style={{ color: 'var(--text-secondary)' }}>System is monitoring. Automatic analysis will appear here.</p>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '8px', opacity: 0.7 }}>
                  Use "Force Defensive Scan" on the right to push existing alerts through the AI.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Sidebar Controls */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div className="card" style={{ padding: '24px' }}>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Cpu size={18} /> Manual Scanner
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '20px', lineHeight: 1.5 }}>
              Force a manual scan on a specific agent to backfill missing analysis.
            </p>

            <label style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>Target Agent</label>
            <select
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              style={{
                width: '100%',
                backgroundColor: 'var(--bg-color)',
                border: '1px solid var(--border-color)',
                borderRadius: '10px',
                padding: '12px',
                color: 'var(--text-primary)',
                fontSize: '0.875rem',
                outline: 'none',
                marginBottom: '20px',
                cursor: 'pointer'
              }}
            >
              {agents.map(a => (
                <option key={typeof a === 'string' ? a : a.name} value={typeof a === 'string' ? a : a.name}>
                  {typeof a === 'string' ? a : a.name}
                </option>
              ))}
            </select>

            <button
              onClick={runManualAnalysis}
              disabled={analyzing || !selectedAgent}
              style={{
                width: '100%',
                backgroundColor: analyzing ? 'var(--border-color)' : 'var(--accent-secondary)',
                color: 'white',
                padding: '14px',
                borderRadius: '10px',
                fontWeight: 600,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                cursor: analyzing ? 'not-allowed' : 'pointer',
                marginBottom: '12px',
              }}
            >
              {analyzing ? <RefreshCw size={18} className="animate-spin" /> : <Play size={18} />}
              {analyzing ? 'Processing...' : 'Start Manual Scan'}
            </button>

            <button
              onClick={triggerDefensiveScan}
              disabled={!selectedAgent || scanning}
              style={{
                width: '100%',
                backgroundColor: 'transparent',
                color: 'var(--accent-secondary)',
                padding: '12px',
                borderRadius: '10px',
                fontWeight: 600,
                border: '1px solid var(--border-color)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                cursor: (!selectedAgent || scanning) ? 'not-allowed' : 'pointer',
                fontSize: '0.8125rem',
                opacity: scanning ? 0.6 : 1,
              }}
              title="Force the defensive worker to re-evaluate this agent's most recent alerts and emit comments / SOAR recommendations."
            >
              {scanning ? <RefreshCw size={16} className="animate-spin" /> : <ShieldAlert size={16} />}
              {scanning ? 'Scanning...' : 'Force Defensive Scan'}
            </button>

            {scanStatus && (
              <div
                style={{
                  marginTop: '12px',
                  padding: '10px 12px',
                  borderRadius: '8px',
                  backgroundColor: 'rgba(96, 165, 250, 0.06)',
                  border: '1px solid rgba(96, 165, 250, 0.18)',
                  fontSize: '0.75rem',
                  lineHeight: 1.5,
                  color: 'var(--text-secondary)',
                  wordBreak: 'break-word',
                }}
              >
                {scanStatus}
              </div>
            )}
          </div>

          <div className="card" style={{ padding: '24px', backgroundColor: 'rgba(96, 165, 250, 0.03)' }}>
            <h4 style={{ fontSize: '0.875rem', fontWeight: 700, marginBottom: '12px' }}>System Stats</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Total Insights</span>
                <span style={{ fontWeight: 700 }}>{insights.length}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>After Filter</span>
                <span style={{ fontWeight: 700 }}>{filteredInsights.length}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Agents Reporting</span>
                <span style={{ fontWeight: 700 }}>{agentList.length}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Connected Agents</span>
                <span style={{ fontWeight: 700 }}>{agents.length}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AIAnalysis;
