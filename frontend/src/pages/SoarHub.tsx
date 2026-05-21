import React, { useEffect, useState } from 'react';
import {
  Zap,
  Activity,
  ShieldCheck,
  ShieldAlert,
  Clock,
  ArrowRight,
  RefreshCw,
  Terminal,
  Server,
  AlertTriangle,
  Eye,
  Check,
  X
} from 'lucide-react';
import { agentService } from '../services/api';
import { Link } from 'react-router-dom';

type Tab = 'overview' | 'shadow';

const SoarHub: React.FC = () => {
  const [tab, setTab] = useState<Tab>('overview');
  const [stats, setStats] = useState({
    totalActions: 0,
    successful: 0,
    failed: 0,
    pending: 0,
    activeBlocks: 0
  });
  const [recentActions, setRecentActions] = useState<any[]>([]);
  const [allActionsCache, setAllActionsCache] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterMode, setFilterMode] = useState<'all' | 'failed'>('all');
  const [aiAdvice, setAiAdvice] = useState<any[]>([]);
  const [shadowList, setShadowList] = useState<any[]>([]);
  const [shadowLoading, setShadowLoading] = useState(false);
  const [shadowBusy, setShadowBusy] = useState<number | null>(null);

  const fetchShadow = async () => {
    setShadowLoading(true);
    try {
      const res = await agentService.getShadowPendingAll();
      setShadowList(Array.isArray(res?.results) ? res.results : []);
    } catch (err) {
      console.error('Shadow fetch failed', err);
      setShadowList([]);
    } finally {
      setShadowLoading(false);
    }
  };

  const handleApprove = async (item: any) => {
    if (!item?.agent || !item?.id) return;
    if (!window.confirm(`Approve ${item.proposed_action?.toUpperCase()} on ${item.proposed_target}?`)) return;
    setShadowBusy(item.id);
    try {
      const res = await agentService.approveShadow(item.agent, item.id);
      if (res?.success) {
        alert(`Approved. SOAR call: ${res.soar_result?.message || (res.dispatched ? 'dispatched' : 'queued')}`);
        fetchShadow();
      } else {
        alert(`Approve failed: ${res?.error || 'unknown'}`);
      }
    } catch (err: any) {
      alert(`Approve failed: ${err?.response?.data?.error || err?.message}`);
    } finally {
      setShadowBusy(null);
    }
  };

  const handleReject = async (item: any) => {
    if (!item?.agent || !item?.id) return;
    const note = window.prompt('Reject reason (optional):', '') || '';
    setShadowBusy(item.id);
    try {
      const res = await agentService.rejectShadow(item.agent, item.id, note);
      if (res?.success) {
        fetchShadow();
      } else {
        alert(`Reject failed: ${res?.error || 'unknown'}`);
      }
    } catch (err: any) {
      alert(`Reject failed: ${err?.response?.data?.error || err?.message}`);
    } finally {
      setShadowBusy(null);
    }
  };

  const fetchAIData = async () => {
    try {
      const res = await agentService.getCustom('/api/ai-insights/all');
      if (res.results && Array.isArray(res.results)) {
        // Pick up either the defensive-advice marker or the auto-dispatched
        // marker (worker emits one of these for every actionable AI verdict).
        const MARKERS = ['[AI DEFENSIVE ADVICE]', 'AUTO-DISPATCHED'];
        const isAdvice = (s: string) => !!s && MARKERS.some(m => s.includes(m));
        const advice: any[] = res.results
          .filter((r: any) => r && r.critical_summary && (
            isAdvice(r.critical_summary) ||
            (r.source_file && (r.source_file.includes('AI_DEFENSIVE') || r.source_file === 'SOAR_Recommender'))
          ))
          .map((r: any) => ({
            agent: r.agent || 'Global',
            text: r.critical_summary.replace('[AI DEFENSIVE ADVICE]', '').trim(),
            auto: r.critical_summary.includes('AUTO-DISPATCHED'),
            date: r.timestamp || r.created_at || new Date().toISOString(),
          }));
        setAiAdvice(advice.sort((a,b) => new Date(b.date).getTime() - new Date(a.date).getTime()).slice(0, 5));
      }
    } catch (err) {
      console.error("Failed to fetch AI advice", err);
    }
  };

  useEffect(() => {
    fetchData();
    fetchAIData();
    fetchShadow();
    const interval = setInterval(() => {
      fetchData();
      fetchAIData();
      if (tab === 'shadow') fetchShadow();
    }, 30000);
    return () => clearInterval(interval);
  }, [tab]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const agentList = await agentService.getAgents();

      // /devices returns objects ({name, status, ...}); extract the name field.
      const agentNames: string[] = (agentList || [])
        .map((a: any) => (typeof a === 'string' ? a : a?.name))
        .filter(Boolean);

      // Fetch actions from all agents to aggregate
      const allActions = await Promise.all(
        agentNames.map((name: string) =>
          agentService.getSoarActions(name)
            .then((actions: any) => Array.isArray(actions)
              ? actions.map((a: any) => ({ ...a, agent: name }))
              : [])
            .catch(() => [])
        )
      );

      // Backend returns timestamps as Unix-seconds floats — convert to ms for sorting.
      const _ts = (v: any): number => {
        if (typeof v === 'number') return v < 1e12 ? v * 1000 : v;
        const t = new Date(v).getTime();
        return isNaN(t) ? 0 : t;
      };

      const flattened = allActions.flat().sort((a, b) => _ts(b.timestamp) - _ts(a.timestamp));

      setAllActionsCache(flattened);
      setRecentActions(flattened.slice(0, 50)); // Increased limit to 50

      const success = flattened.filter(a => a.status === 'success' || a.status === 'completed').length;
      const failed = flattened.filter(a => a.status === 'failed').length;
      const pending = flattened.filter(a => a.status === 'active' || a.status === 'pending').length;
      const blocks = flattened.filter(a => a.action === 'block_ip' && (a.status === 'success' || a.status === 'completed')).length;

      setStats({
        totalActions: flattened.length,
        successful: success,
        failed: failed,
        pending: pending,
        activeBlocks: blocks
      });
    } catch (err) {
      console.error("Failed to fetch SOAR data", err);
    } finally {
      setLoading(false);
    }
  };
  const [searchTerm, setSearchTerm] = useState('');

  const filteredActions = (filterMode === 'failed' 
    ? allActionsCache.filter(a => a.status === 'failed') 
    : allActionsCache
  ).filter(a => 
    !searchTerm || 
    a.action?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    a.target?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    a.agent?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    a.status?.toLowerCase().includes(searchTerm.toLowerCase())
  ).slice(0, 50);

  return (
    <div style={{ animation: 'fadeIn 0.4s ease-out' }}>
      <div className="flex-responsive" style={{ justifyContent: 'space-between', marginBottom: '32px' }}>
        <div>
          <h2 style={{ fontSize: '2rem', fontWeight: 800, letterSpacing: '-0.025em', marginBottom: '8px' }}>SOAR</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Automated response monitoring and incident mitigation center.</p>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button onClick={() => { fetchData(); fetchAIData(); fetchShadow(); }} style={{ padding: '10px 20px', borderRadius: '10px', backgroundColor: 'rgba(255,255,255,0.03)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.875rem', fontWeight: 600 }}>
            <RefreshCw size={16} className={loading || shadowLoading ? 'animate-spin' : ''} /> Refresh Hub
          </button>
          <Link to="/automations" style={{ padding: '10px 20px', borderRadius: '10px', backgroundColor: 'var(--accent-secondary)', color: 'white', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.875rem', fontWeight: 700 }}>
            <Zap size={16} /> Manage Rules
          </Link>
        </div>
      </div>

      {/* Tab switcher */}
      <div style={{ display: 'flex', gap: '4px', marginBottom: '24px', padding: '4px', backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', width: 'fit-content' }}>
        <button
          onClick={() => setTab('overview')}
          style={{
            padding: '10px 20px',
            borderRadius: '8px',
            backgroundColor: tab === 'overview' ? 'rgba(96, 165, 250, 0.15)' : 'transparent',
            color: tab === 'overview' ? 'var(--accent-secondary)' : 'var(--text-secondary)',
            border: 'none',
            cursor: 'pointer',
            fontSize: '0.875rem',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Activity size={16} /> Overview
        </button>
        <button
          onClick={() => setTab('shadow')}
          style={{
            padding: '10px 20px',
            borderRadius: '8px',
            backgroundColor: tab === 'shadow' ? 'rgba(167, 139, 250, 0.15)' : 'transparent',
            color: tab === 'shadow' ? '#a78bfa' : 'var(--text-secondary)',
            border: 'none',
            cursor: 'pointer',
            fontSize: '0.875rem',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Eye size={16} /> Shadow Queue
          {shadowList.length > 0 && (
            <span style={{ backgroundColor: '#a78bfa', color: 'white', borderRadius: '10px', padding: '1px 8px', fontSize: '0.7rem', fontWeight: 800 }}>
              {shadowList.length}
            </span>
          )}
        </button>
      </div>

      {tab === 'shadow' && (
        <ShadowQueue
          items={shadowList}
          loading={shadowLoading}
          busyId={shadowBusy}
          onApprove={handleApprove}
          onReject={handleReject}
          onRefresh={fetchShadow}
        />
      )}

      {tab === 'overview' && (
      <>
      {/* Stats Overview */}
      <div className="responsive-grid" style={{ marginBottom: '32px' }}>
        <SoarStatCard label="Mitigated Threats" value={stats.successful} icon={<ShieldCheck color="var(--accent-success)" />} color="var(--accent-success)" />
        <SoarStatCard label="Active IP Blocks" value={stats.activeBlocks} icon={<AlertTriangle color="var(--accent-warning)" />} color="var(--accent-warning)" />
        <SoarStatCard label="Pending Tasks" value={stats.pending} icon={<Clock color="var(--accent-secondary)" />} color="var(--accent-secondary)" />
        <SoarStatCard label="Failed Responses" value={stats.failed} icon={<ShieldAlert color="var(--accent-color)" />} color="var(--accent-color)" />
      </div>

      <div className="responsive-grid" style={{ alignItems: 'start' }}>
        {/* Real-time Action Stream */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', backgroundColor: 'rgba(255,255,255,0.01)' }}>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Recent Automation Events</h3>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <select 
                value={filterMode} 
                onChange={(e) => setFilterMode(e.target.value as 'all' | 'failed')}
                style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '6px 12px', color: 'white', fontSize: '0.875rem' }}
              >
                <option value="all">All Events</option>
                <option value="failed">Failed Only</option>
              </select>
              <div style={{ position: 'relative' }}>
                <Terminal size={16} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
                <input 
                  type="text" 
                  placeholder="Filter events..." 
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '6px 12px 6px 32px', fontSize: '0.875rem', color: 'white', width: '200px' }} 
                />
              </div>
              <Activity size={18} color="var(--accent-secondary)" />
            </div>
          </div>
          <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
            {filteredActions.map((action, i) => (
              <div key={i} style={{ 
                padding: '20px 24px', 
                borderBottom: i < recentActions.length - 1 ? '1px solid rgba(255,255,255,0.03)' : 'none', 
                display: 'flex', 
                gap: '20px',
                transition: 'all 0.2s ease',
                backgroundColor: 'transparent',
                cursor: 'pointer'
              }}
              onMouseOver={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)'} 
              onMouseOut={e => e.currentTarget.style.backgroundColor = 'transparent'}
              >
                <div style={{ 
                  padding: '12px', 
                  borderRadius: '14px', 
                  background: action.status === 'failed' ? 'linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(220, 38, 38, 0.05) 100%)' : 'linear-gradient(135deg, rgba(52, 211, 153, 0.15) 0%, rgba(16, 185, 129, 0.05) 100%)', 
                  border: action.status === 'failed' ? '1px solid rgba(239,68,68,0.2)' : '1px solid rgba(52,211,153,0.2)',
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  height: '50px', 
                  width: '50px',
                  boxShadow: action.status === 'failed' ? '0 0 15px rgba(239,68,68,0.1)' : '0 0 15px rgba(52,211,153,0.1)'
                }}>
                  <Terminal size={24} color={action.status === 'failed' ? '#ef4444' : '#34d399'} />
                </div>
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', alignItems: 'center' }}>
                    <span style={{ fontWeight: 800, textTransform: 'uppercase', fontSize: '0.85rem', color: 'var(--text-primary)', letterSpacing: '0.05em' }}>{action.action}</span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 500, backgroundColor: 'rgba(255,255,255,0.05)', padding: '4px 10px', borderRadius: '12px' }}>
                      {(() => {
                        const t = action.timestamp;
                        if (typeof t === 'number') {
                          const ms = t < 1e12 ? t * 1000 : t;
                          return new Date(ms).toLocaleString();
                        }
                        return t || '-';
                      })()}
                    </span>
                  </div>
                  <div style={{ marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>Target: </span>
                    <code style={{ fontSize: '0.8125rem', color: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.1)', border: '1px solid rgba(251, 191, 36, 0.2)', padding: '2px 8px', borderRadius: '6px' }}>{action.target}</code>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
                      <Server size={14} /> {action.agent}
                    </div>
                    <div style={{ width: '4px', height: '4px', borderRadius: '50%', backgroundColor: 'rgba(255,255,255,0.1)' }}></div>
                    <span style={{ 
                      fontSize: '0.7rem', 
                      fontWeight: 800, 
                      padding: '4px 10px', 
                      borderRadius: '12px', 
                      backgroundColor: action.status === 'success' || action.status === 'completed' ? 'rgba(52, 211, 153, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                      color: action.status === 'success' || action.status === 'completed' ? '#34d399' : '#ef4444',
                      border: action.status === 'success' || action.status === 'completed' ? '1px solid rgba(52,211,153,0.2)' : '1px solid rgba(239,68,68,0.2)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.05em'
                    }}>
                      {action.status}
                    </span>
                  </div>
                </div>
              </div>
            ))}
            {recentActions.length === 0 && (
              <div style={{ padding: '80px 24px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                <Zap size={48} style={{ opacity: 0.1, marginBottom: '16px', margin: '0 auto' }} />
                <p>No recent SOAR actions detected.</p>
              </div>
            )}
          </div>
        </div>

        {/* Integration & Playbook Status */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
          <div className="card">
            <h3 style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '24px' }}>Response Playbooks</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <PlaybookStatusItem name="Brute-Force Auto-Block" status="Active" triggers={stats.activeBlocks} />
              <PlaybookStatusItem name="Malware Quarantine" status="Active" triggers={recentActions.filter(a=>a.action==='quarantine_file').length} />
              <PlaybookStatusItem name="Docker Escape Containment" status="Active" triggers={recentActions.filter(a=>a.action.startsWith('container')).length} />
              <PlaybookStatusItem name="Ransomware Killswitch" status="Idle" triggers={0} />
            </div>
            <Link to="/playbooks" style={{ marginTop: '24px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent-secondary)', fontSize: '0.875rem', fontWeight: 700, transition: 'color 0.2s ease' }} onMouseOver={(e) => e.currentTarget.style.color = 'white'} onMouseOut={(e) => e.currentTarget.style.color = 'var(--accent-secondary)'}>
              Go to Playbook Designer <ArrowRight size={16} />
            </Link>
          </div>

          <div style={{ background: 'linear-gradient(135deg, rgba(96, 165, 250, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%)', border: '1px solid rgba(96, 165, 250, 0.2)', borderRadius: '16px', padding: '24px', boxShadow: '0 10px 30px rgba(0,0,0,0.2)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ padding: '10px', backgroundColor: 'rgba(96, 165, 250, 0.1)', borderRadius: '12px' }}>
                <ShieldCheck size={24} color="var(--accent-secondary)" />
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>AI Recommended Actions</h3>
            </div>
            {aiAdvice.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {aiAdvice.map((item, idx) => (
                  <div key={idx} style={{ fontSize: '0.875rem', color: 'var(--text-primary)', borderLeft: `3px solid ${item.auto ? '#ef4444' : 'var(--accent-secondary)'}`, paddingLeft: '12px', marginBottom: '8px' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span>{item.agent}</span>
                      <span>·</span>
                      <span>{new Date(item.date).toLocaleString()}</span>
                      {item.auto && (
                        <span style={{ marginLeft: 'auto', padding: '2px 8px', fontSize: '0.625rem', fontWeight: 800, color: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Auto</span>
                      )}
                    </div>
                    {item.text.replace('RECOMMENDED_ACTION:', '').trim()}
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
                The <strong>Ollama AI engine</strong> is analyzing your global events. No critical remediation needed at this time.
              </p>
            )}
          </div>
        </div>
      </div>
      </>
      )}
    </div>
  );
};

const ShadowQueue: React.FC<{
  items: any[];
  loading: boolean;
  busyId: number | null;
  onApprove: (item: any) => void;
  onReject: (item: any) => void;
  onRefresh: () => void;
}> = ({ items, loading, busyId, onApprove, onReject, onRefresh }) => {
  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h3 style={{ fontSize: '1.125rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Eye size={18} color="#a78bfa" />
            Shadow Mode Queue
          </h3>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Defensive AI verdicts staged for operator review. Approving dispatches the real SOAR action; rejecting records the decision and clears it from this list.
          </p>
        </div>
        <button onClick={onRefresh} style={{ padding: '8px 14px', borderRadius: '8px', backgroundColor: 'rgba(255,255,255,0.03)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8125rem', fontWeight: 600, cursor: 'pointer' }}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      <div style={{ maxHeight: '720px', overflowY: 'auto' }}>
        {loading && items.length === 0 ? (
          <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <RefreshCw size={32} className="animate-spin" style={{ opacity: 0.3, marginBottom: '12px' }} />
            <p>Loading shadow queue...</p>
          </div>
        ) : items.length === 0 ? (
          <div style={{ padding: '80px 24px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <Eye size={48} style={{ opacity: 0.1, marginBottom: '16px', margin: '0 auto' }} />
            <p style={{ fontWeight: 600 }}>No shadow proposals pending.</p>
            <p style={{ fontSize: '0.8125rem', marginTop: '6px', maxWidth: '420px', margin: '6px auto 0' }}>
              When <code style={{ fontSize: '0.75rem', backgroundColor: 'rgba(167,139,250,0.1)', padding: '1px 6px', borderRadius: '4px' }}>AI_SHADOW_MODE=1</code> is set on <code style={{ fontSize: '0.75rem', backgroundColor: 'rgba(167,139,250,0.1)', padding: '1px 6px', borderRadius: '4px' }}>zer0vuln-ai-worker-defensive</code>, autonomous verdicts land here instead of being executed.
            </p>
          </div>
        ) : (
          items.map((item) => {
            const busy = busyId === item.id;
            const action = (item.proposed_action || '').toUpperCase();
            return (
              <div key={item.id} style={{ padding: '20px 24px', borderBottom: '1px solid rgba(255,255,255,0.04)', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px', flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ padding: '4px 10px', backgroundColor: 'rgba(167,139,250,0.12)', border: '1px solid rgba(167,139,250,0.3)', borderRadius: '6px', fontSize: '0.7rem', fontWeight: 800, color: '#a78bfa', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      PROPOSED {action}
                    </span>
                    <span style={{ padding: '4px 10px', backgroundColor: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-color)', borderRadius: '6px', fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Server size={12} /> {item.agent}
                    </span>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Clock size={11} /> {item.created_at ? new Date(item.created_at).toLocaleString() : item.timestamp}
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      onClick={() => onApprove(item)}
                      disabled={busy}
                      style={{
                        padding: '8px 16px',
                        borderRadius: '8px',
                        backgroundColor: busy ? 'rgba(52,211,153,0.05)' : 'rgba(52,211,153,0.12)',
                        border: '1px solid rgba(52,211,153,0.35)',
                        color: '#34d399',
                        fontWeight: 700,
                        fontSize: '0.8125rem',
                        cursor: busy ? 'not-allowed' : 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        opacity: busy ? 0.6 : 1,
                      }}
                    >
                      <Check size={14} /> Approve
                    </button>
                    <button
                      onClick={() => onReject(item)}
                      disabled={busy}
                      style={{
                        padding: '8px 16px',
                        borderRadius: '8px',
                        backgroundColor: busy ? 'rgba(239,68,68,0.05)' : 'rgba(239,68,68,0.10)',
                        border: '1px solid rgba(239,68,68,0.30)',
                        color: '#ef4444',
                        fontWeight: 700,
                        fontSize: '0.8125rem',
                        cursor: busy ? 'not-allowed' : 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        opacity: busy ? 0.6 : 1,
                      }}
                    >
                      <X size={14} /> Reject
                    </button>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>Target:</span>
                  <code style={{ fontSize: '0.8125rem', padding: '4px 10px', borderRadius: '6px', backgroundColor: 'rgba(251,191,36,0.10)', border: '1px solid rgba(251,191,36,0.2)', color: '#fbbf24', wordBreak: 'break-all' }}>
                    {item.proposed_target}
                  </code>
                </div>

                <div style={{ fontSize: '0.875rem', color: 'var(--text-primary)', lineHeight: 1.55, whiteSpace: 'pre-wrap', wordBreak: 'break-word', padding: '12px 14px', backgroundColor: 'rgba(0,0,0,0.18)', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                  {item.critical_summary}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

const SoarStatCard: React.FC<{ label: string, value: number, icon: any, color: string }> = ({ label, value, icon, color }) => (
  <div className="card" style={{ 
    display: 'flex', 
    alignItems: 'center', 
    gap: '20px', 
    padding: '24px', 
    background: 'linear-gradient(145deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.01) 100%)',
    boxShadow: '0 4px 20px rgba(0,0,0,0.1)',
    cursor: 'default'
  }}
  onMouseOver={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = `0 10px 25px ${color.replace(')', ', 0.15)').replace('var(--', 'rgba(')}`; }} // extremely rough approximation for glow
  onMouseOut={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = '0 4px 20px rgba(0,0,0,0.1)'; }}
  >
    <div style={{ 
      padding: '16px', 
      borderRadius: '14px', 
      background: `linear-gradient(135deg, ${color.replace(')', ', 0.1)').replace('var(--', 'rgba(')} 0%, rgba(0,0,0,0) 100%)`, 
      border: `1px solid ${color.replace(')', ', 0.2)').replace('var(--', 'rgba(')}`,
      color: color,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center'
    }}>
      {icon}
    </div>
    <div>
      <div style={{ fontSize: '0.75rem', fontWeight: 800, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>{label}</div>
      <div style={{ fontSize: '2rem', fontWeight: 900, letterSpacing: '-0.025em', color: 'var(--text-primary)' }}>{value}</div>
    </div>
  </div>
);

const PlaybookStatusItem: React.FC<{ name: string, status: string, triggers: number }> = ({ name, status, triggers }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px', borderRadius: '12px', background: 'linear-gradient(90deg, rgba(255,255,255,0.02) 0%, rgba(255,255,255,0) 100%)', borderLeft: status === 'Active' ? '3px solid #34d399' : '3px solid rgba(255,255,255,0.1)' }}>
    <div>
      <div style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>{name}</div>
      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 500 }}>Total Triggers: <span style={{ color: 'white' }}>{triggers}</span></div>
    </div>
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', backgroundColor: status === 'Active' ? 'rgba(52, 211, 153, 0.1)' : 'rgba(255,255,255,0.05)', padding: '6px 12px', borderRadius: '20px', border: status === 'Active' ? '1px solid rgba(52,211,153,0.2)' : '1px solid rgba(255,255,255,0.1)' }}>
      <div style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: status === 'Active' ? '#34d399' : 'var(--text-secondary)', boxShadow: status === 'Active' ? '0 0 8px #34d399' : 'none' }}></div>
      <span style={{ fontSize: '0.75rem', fontWeight: 800, color: status === 'Active' ? '#34d399' : 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{status}</span>
    </div>
  </div>
);

export default SoarHub;
