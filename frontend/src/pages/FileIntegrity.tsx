import React, { useState, useEffect, useMemo } from 'react';
import { Card } from '../components/ui';
import { CategoryBars } from '../components/ui/charts';

const chartNote: React.CSSProperties = {
  margin: '0 0 var(--space-3)', color: 'var(--text-muted)',
  fontSize: 'var(--text-xs)', maxWidth: '58ch',
};

/** These are states, so they take the semantic colours. A deletion is not
 *  worse than a modification because it is drawn in a different hue - it is
 *  worse, and the hue says so. */
const STATUS_TONE: Record<string, string> = {
  deleted: 'var(--sev-critical)',
  changed: 'var(--sev-high)',
  modified: 'var(--sev-high)',
  created: 'var(--sev-medium)',
  baseline: 'var(--accent-neutral)',
};
import { 
  ShieldCheck, 
  Search, 
  Clock, 
  FileText, 
  AlertTriangle, 
  RefreshCw,
  Server,
  ChevronRight,
  Info,
  Activity
} from 'lucide-react';
import { agentService } from '../services/api';

const FileIntegrity: React.FC = () => {
    const [agents, setAgents] = useState<any[]>([]);
    const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
    const [data, setData] = useState<any[]>([]);
    const [loading, setLoading] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        fetchAgents();
    }, []);

    useEffect(() => {
        if (selectedAgent) {
            fetchFimData();
        }
    }, [selectedAgent]);

    const fetchAgents = async () => {
        try {
            const list = await agentService.getAgents();
            setAgents(list || []);
            if (list?.length > 0 && !selectedAgent) {
                setSelectedAgent(list[0].name);
            }
        } catch (err) {
            console.error("Failed to fetch agents", err);
        }
    };

    const fetchFimData = async () => {
        if (!selectedAgent) return;
        setLoading(true);
        try {
            const endpoint = `/api/agent/${selectedAgent}/fim`;
            const res = await agentService.getCustom(endpoint);
            setData(res || []);
        } catch (err) {
            console.error("Failed to fetch FIM data", err);
            setData([]);
        } finally {
            setLoading(false);
        }
    };

    const filteredData = data.filter(item => {
        const searchStr = (item.path + item.status).toLowerCase();
        return searchStr.includes(searchTerm.toLowerCase());
    });

    /* Derived from the rows already loaded, so the charts and the timeline
       below can never disagree about the same events. */
    const byStatus = useMemo(() => {
        const counts = new Map<string, number>();
        for (const e of data) {
            const key = String(e.status || 'unknown');
            counts.set(key, (counts.get(key) ?? 0) + 1);
        }
        return [...counts.entries()]
            .map(([name, value]) => ({ name, value }))
            .sort((a, b) => b.value - a.value);
    }, [data]);

    const byDirectory = useMemo(() => {
        const counts = new Map<string, number>();
        for (const e of data) {
            const path = String(e.path || '');
            const cut = Math.max(path.lastIndexOf('\\'), path.lastIndexOf('/'));
            const dir = cut > 0 ? path.slice(0, cut) : path || 'unknown';
            counts.set(dir, (counts.get(dir) ?? 0) + 1);
        }
        return [...counts.entries()]
            // Only the tail of a long path fits on an axis, and the tail is
            // the part that distinguishes them.
            .map(([name, value]) => ({
                name: name.length > 28 ? '…' + name.slice(-27) : name,
                value,
            }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 6);
    }, [data]);

    return (
        <div style={{ padding: '32px', maxWidth: '1600px', margin: '0 auto', animation: 'fadeIn 0.5s ease-out' }}>
            {/* Header Section */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '32px' }}>
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                        <div style={{ background: 'linear-gradient(135deg, #f43f5e, #e11d48)', padding: '10px', borderRadius: '12px', display: 'flex' }}>
                            <ShieldCheck size={24} color="white" />
                        </div>
                        <h1 style={{ fontSize: '2rem', fontWeight: 800, background: 'linear-gradient(to right, #fff, #a1a1aa)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>File Integrity Monitoring</h1>
                    </div>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '1rem', fontWeight: 500 }}>Real-time detection of unauthorized file system changes.</p>
                </div>
                
                <div style={{ display: 'flex', gap: '12px' }}>
                    <div style={{ position: 'relative' }}>
                        <Search size={18} style={{ position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
                        <input 
                            type="text" 
                            placeholder="Filter by path or status..." 
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            style={{ 
                                backgroundColor: 'rgba(255,255,255,0.03)', 
                                border: '1px solid var(--border-color)', 
                                padding: '12px 16px 12px 48px', 
                                borderRadius: '12px', 
                                color: 'white',
                                width: '300px',
                                fontSize: '0.9rem',
                                transition: 'all 0.3s ease',
                                outline: 'none'
                             }} 
                        />
                    </div>
                    <button 
                        onClick={fetchFimData}
                        style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-color)', color: 'white', padding: '12px 20px', borderRadius: '12px', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600 }}
                    >
                        <RefreshCw size={18} className={loading ? 'animate-spin' : ''} /> Refresh
                    </button>
                </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: '32px' }}>
                {/* Agents Sidebar */}
                <div style={{ background: 'var(--card-bg)', borderRadius: '20px', border: '1px solid var(--border-color)', overflow: 'hidden', height: 'fit-content' }}>
                    <div style={{ padding: '20px', borderBottom: '1px solid var(--border-color)', backgroundColor: 'rgba(255,255,255,0.02)' }}>
                        <h3 style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Managed Agents</h3>
                    </div>
                    <div style={{ maxHeight: '70vh', overflowY: 'auto' }}>
                        {agents.map((agent) => (
                            <button
                                key={agent.name}
                                onClick={() => setSelectedAgent(agent.name)}
                                style={{
                                    width: '100%',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '12px',
                                    padding: '16px 20px',
                                    border: 'none',
                                    borderBottom: '1px solid rgba(255,255,255,0.03)',
                                    backgroundColor: selectedAgent === agent.name ? 'rgba(225, 29, 72, 0.1)' : 'transparent',
                                    color: selectedAgent === agent.name ? 'white' : 'var(--text-secondary)',
                                    textAlign: 'left',
                                    transition: 'all 0.2s',
                                    cursor: 'pointer'
                                }}
                            >
                                <div style={{ 
                                    width: '32px', height: '32px', borderRadius: '8px', 
                                    backgroundColor: selectedAgent === agent.name ? '#e11d48' : 'rgba(255,255,255,0.05)',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center'
                                }}>
                                    <Server size={16} color={selectedAgent === agent.name ? 'white' : 'var(--text-secondary)'} />
                                </div>
                                <div style={{ flex: 1, overflow: 'hidden' }}>
                                    <div style={{ fontWeight: 600, fontSize: '0.9rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{agent.name}</div>
                                    <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>{agent.status} • {agent.public_ip}</div>
                                </div>
                                {selectedAgent === agent.name && <ChevronRight size={16} />}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Main Content: Timeline */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

                    {/* A timeline reads one event at a time, which is right
                        once you know which event. These two say which: what
                        kind of change, and where they are concentrated. A
                        directory producing hundreds of "modified" is a watch
                        list that needs narrowing, not an intrusion. */}
                    <div className="responsive-grid">
                        <Card title="By change">
                            <p style={chartNote}>
                                Created and deleted are rarer than modified, and
                                worth more when they happen.
                            </p>
                            <CategoryBars data={byStatus}
                                          colorFor={(row) => STATUS_TONE[row.name] ?? 'var(--chart-1)'} />
                        </Card>
                        <Card title="Busiest directories">
                            <p style={chartNote}>
                                Where the events cluster. One directory carrying
                                most of them usually means the watch list is too
                                wide rather than the host is busy.
                            </p>
                            <CategoryBars data={byDirectory} />
                        </Card>
                    </div>

                    <div style={{ background: 'var(--card-bg)', borderRadius: '20px', border: '1px solid var(--border-color)', padding: '24px', display: 'flex', alignItems: 'center', gap: '20px', boxShadow: '0 4px 20px rgba(0,0,0,0.1)' }}>
                        <div style={{ background: 'rgba(34, 197, 94, 0.1)', padding: '12px', borderRadius: '12px' }}>
                            <Activity size={24} color="#4ade80" />
                        </div>
                        <div>
                            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 600 }}>Active Monitoring Status</p>
                            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#4ade80' }}>Watching for recursive changes in /etc, /bin, C:\Windows\System32...</h2>
                        </div>
                    </div>

                    <div style={{ position: 'relative', paddingLeft: '32px' }}>
                        {/* Vertical Line */}
                        <div style={{ position: 'absolute', left: '7px', top: '0', bottom: '0', width: '2px', background: 'linear-gradient(to bottom, var(--accent-color), transparent)', opacity: 0.2 }}></div>

                        {loading ? (
                            <div style={{ padding: '64px', textAlign: 'center', background: 'var(--card-bg)', borderRadius: '20px', border: '1px solid var(--border-color)' }}>
                                <RefreshCw size={24} className="animate-spin" style={{ opacity: 0.5, marginBottom: '12px' }} />
                                <p style={{ color: 'var(--text-secondary)' }}>Gathering file system events...</p>
                            </div>
                        ) : filteredData.length === 0 ? (
                            <div style={{ padding: '64px', textAlign: 'center', background: 'var(--card-bg)', borderRadius: '20px', border: '1px solid var(--border-color)' }}>
                                <Info size={32} style={{ opacity: 0.2, marginBottom: '12px' }} />
                                <p style={{ color: 'var(--text-secondary)' }}>No file system changes detected yet.</p>
                            </div>
                        ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                                {filteredData.map((event, idx) => (
                                    <div key={idx} style={{ 
                                        background: 'var(--card-bg)', 
                                        border: '1px solid var(--border-color)', 
                                        borderRadius: '16px', 
                                        padding: '20px',
                                        display: 'flex',
                                        gap: '20px',
                                        alignItems: 'center',
                                        transition: 'all 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
                                        position: 'relative',
                                        cursor: 'default'
                                    }} onMouseOver={e => { e.currentTarget.style.transform = 'translateX(8px)'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.15)'; }}
                                       onMouseOut={e => { e.currentTarget.style.transform = 'translateX(0)'; e.currentTarget.style.borderColor = 'var(--border-color)'; }}>
                                        
                                        {/* Point on timeline */}
                                        <div style={{ position: 'absolute', left: '-31px', top: '50%', transform: 'translateY(-50%)', width: '12px', height: '12px', borderRadius: '50%', background: getStatusColor(event.status), boxShadow: `0 0 10px ${getStatusColor(event.status)}` }}></div>

                                        <div style={{ background: 'rgba(255,255,255,0.03)', padding: '12px', borderRadius: '12px' }}>
                                            <FileText size={20} color={getStatusColor(event.status)} />
                                        </div>

                                        <div style={{ flex: 1, overflow: 'hidden' }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                                                <span style={{ fontSize: '0.75rem', fontWeight: 800, textTransform: 'uppercase', color: getStatusColor(event.status), letterSpacing: '0.05em' }}>{event.status}</span>
                                                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                                    <Clock size={12} /> {event.last_seen}
                                                </span>
                                            </div>
                                            <div style={{ fontSize: '1rem', fontWeight: 600, wordBreak: 'break-all', marginBottom: '8px' }}>{event.path}</div>
                                            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                <span style={{ opacity: 0.6 }}>SHA256:</span>
                                                <span style={{ fontFamily: 'monospace', fontSize: '0.7rem' }}>{event.hash_sha256 || 'N/A (Directory or Deleted)'}</span>
                                            </div>
                                        </div>

                                        {event.status === 'changed' && (
                                            <div style={{ background: 'rgba(239, 68, 68, 0.1)', color: 'var(--accent-color)', padding: '8px 12px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', fontWeight: 700 }}>
                                                <AlertTriangle size={16} /> Integrity Violation
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </div>

            <style>{`
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(10px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                .animate-spin {
                    animation: spin 1s linear infinite;
                }
                @keyframes spin {
                    from { transform: rotate(0deg); }
                    to { transform: rotate(360deg); }
                }
            `}</style>
        </div>
    );
};

const getStatusColor = (status: string) => {
    switch (status) {
        case 'changed': return '#ef4444';
        case 'deleted': return '#f472b6';
        case 'new': return '#4ade80';
        case 'baseline': return '#3b82f6';
        default: return 'var(--text-secondary)';
    }
};

export default FileIntegrity;
