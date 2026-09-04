import React, { useEffect, useMemo, useState } from 'react';
import { Card } from '../components/ui';
import { CategoryBars } from '../components/ui/charts';

const chartNote: React.CSSProperties = {
  margin: '0 0 var(--space-3)', color: 'var(--text-muted)',
  fontSize: 'var(--text-xs)', maxWidth: '58ch',
};

/** Reachability is a state, so it takes the semantic colours rather than the
 *  chart palette. */
const REACH_TONE: Record<string, string> = {
  Commandable: 'var(--accent-success)',
  'No channel': 'var(--sev-critical)',
};
import {
  Monitor,
  Search,
  Filter,
  Clock,
  RefreshCw,
  FileDown,
  ChevronRight,
  Trash2,
  AlertTriangle
} from 'lucide-react';
import { agentService } from '../services/api';
import { saveBlobResponse } from '../utils/downloadBlob';
import { Link } from 'react-router-dom';

const Agents: React.FC = () => {
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  // The agent awaiting confirmation. Deleting drops its telemetry database,
  // so the destructive click is never the first one.
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [reporting, setReporting] = useState(false);

  useEffect(() => {
    fetchAgents(true);
    const interval = setInterval(() => {
      fetchAgents(false);
    }, 30000); // 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchAgents = async (showLoading = true) => {
    if (showLoading) setLoading(true);
    try {
      const list = await agentService.getAgents();
      setAgents(list);
    } catch (err) {
      console.error("Failed to fetch agents", err);
    } finally {
      setLoading(false);
    }
  };

  const downloadFleetReport = async () => {
    setReporting(true);
    try {
      const res = await agentService.downloadFleetReport();
      saveBlobResponse(res, 'fleet-report.pdf');
    } catch (err) {
      console.error('Fleet report failed', err);
      alert('Could not generate the fleet report.');
    } finally {
      setReporting(false);
    }
  };

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await agentService.deleteAgent(pendingDelete);
      setPendingDelete(null);
      await fetchAgents(false);
    } catch (err: any) {
      // Shown rather than swallowed: a failed delete that closes the dialog
      // looks exactly like a successful one until the row reappears.
      setDeleteError(err?.response?.data?.message || err?.message || 'Delete failed');
    } finally {
      setDeleting(false);
    }
  };

  /* Both derived from the list already loaded. A chart with its own request
     is a chart that can disagree with the table under it. */
  const osSpread = useMemo(() => {
    const counts = new Map<string, number>();
    for (const a of agents) {
      // "Windows-11-10.0.26200-SP0" -> "Windows 11". The build number is what
      // the row is for; the chart is about which platforms exist.
      const raw = String(a.os_info || 'Unknown');
      const family = raw.split('-').slice(0, 2).join(' ').trim() || 'Unknown';
      counts.set(family, (counts.get(family) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 6);
  }, [agents]);

  const reachability = useMemo(() => ([
    { name: 'Commandable', value: agents.filter(a => a.channel_connected).length },
    { name: 'No channel', value: agents.filter(a => !a.channel_connected).length },
  ]), [agents]);

  const filteredAgents = agents.filter(agent =>
    agent.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (agent.display_name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (agent.public_ip || '').includes(searchTerm) ||
    (agent.os_info || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div style={{ animation: 'fadeIn 0.3s ease' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px', flexWrap: 'wrap', gap: '20px' }}>
        <div>
          <h2 style={{ fontSize: '2rem', fontWeight: 800, letterSpacing: '-0.025em', marginBottom: '8px' }}>Security Agents</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Manage and monitor all endpoints connected to the Sentora network.</p>
        </div>
        <div className="flex-responsive" style={{ gap: '12px' }}>
          <button className="btn-secondary" onClick={downloadFleetReport} disabled={reporting}
            title="Download a PDF report covering every enrolled host"
            style={{ padding: '8px 16px', borderRadius: '6px', display: 'flex', alignItems: 'center', gap: '8px', backgroundColor: 'var(--bg-color)' }}>
            <FileDown size={16} /> {reporting ? 'Building…' : 'Fleet report'}
          </button>
          <button className="btn-secondary" onClick={() => fetchAgents(true)} style={{ padding: '8px 16px', borderRadius: '6px', display: 'flex', alignItems: 'center', gap: '8px', backgroundColor: 'var(--bg-color)' }}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* The shape of the estate, before the list of it. Deliberately not the
          dashboard's cards again: that one answers "what needs attention",
          this one answers "what am I actually running" — which is the
          question you have when you open the agent list. */}
      <div className="responsive-grid" style={{ marginBottom: 'var(--space-5)' }}>
        <Card title="Operating systems">
          <p style={chartNote}>
            What the fleet is made of. A single host on an old build is a
            different problem from half the estate on one.
          </p>
          <CategoryBars data={osSpread} />
        </Card>
        <Card title="Reachability">
          <p style={chartNote}>
            Whether a command would reach the host now. Telemetry travels on a
            separate connection, so an agent can be reporting and still be
            uncommandable.
          </p>
          <CategoryBars data={reachability} colorFor={(row) => REACH_TONE[row.name]} />
        </Card>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '20px', alignItems: 'center', flexWrap: 'wrap', backgroundColor: 'var(--bg-color)' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: '280px' }}>
            <Search size={18} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
            <input 
              type="text" 
              placeholder="Search by name, IP, or OS..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ 
                width: '100%', 
                backgroundColor: 'var(--bg-color)', 
                border: '1px solid var(--border-color)', 
                borderRadius: '4px', 
                padding: '8px 12px 8px 42px', 
                color: 'white', 
                fontSize: '0.875rem',
                fontFamily: 'Source Code Pro'
              }} 
            />
          </div>
          <div className="flex-responsive" style={{ gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '0 8px' }}>
              <Filter size={18} color="var(--text-secondary)" />
              <select style={{ backgroundColor: 'transparent', border: 'none', color: 'white', fontSize: '0.875rem', fontWeight: 600, outline: 'none', cursor: 'pointer' }}>
                <option>All Platforms</option>
                <option>Linux</option>
                <option>Windows</option>
              </select>
            </div>
          </div>
        </div>
        <div className="table-responsive">
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ backgroundColor: 'var(--bg-color)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '14px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>Agent</th>
                <th style={{ padding: '14px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>IP Address</th>
                <th style={{ padding: '14px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>Status</th>
                <th style={{ padding: '14px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>Last Check-in</th>
                <th style={{ padding: '14px 20px', fontWeight: 600, color: 'var(--text-secondary)', textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredAgents.map((agent) => {
                const isOnline = agent.status === 'Online';
                return (
                  <tr key={agent.name} style={{ borderBottom: '1px solid var(--border-color)', transition: 'background-color 0.2s ease' }} onMouseOver={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.01)'} onMouseOut={e => e.currentTarget.style.backgroundColor = 'transparent'}>
                    <td style={{ padding: '16px 20px' }}>
                      <Link to={`/agent/${agent.name}`} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div style={{ width: '32px', height: '32px', borderRadius: '6px', backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <Monitor size={16} color="var(--text-secondary)" />
                        </div>
                        <div>
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                            {agent.display_name || agent.name}
                          </div>
                          {/* The real name stays visible when a label is set.
                              It is what the database, the agent's own config
                              and every SOAR action are keyed on, so hiding it
                              would make a renamed host hard to correlate with
                              anything else. */}
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                            {agent.display_name ? agent.name : (agent.os_info || 'Generic Linux')}
                          </div>
                        </div>
                      </Link>
                    </td>
                    <td className="mono" style={{ padding: '16px 20px', color: 'var(--text-secondary)' }}>{agent.public_ip || '-'}</td>
                    <td style={{ padding: '16px 20px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', backgroundColor: 'transparent', padding: '0', borderRadius: '4px', width: 'fit-content' }}>
                        <div style={{ width: '8px', height: '8px', borderRadius: '2px', backgroundColor: isOnline ? 'var(--accent-success)' : 'var(--accent-color)' }}></div>
                        <span className="mono" style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>{agent.status}</span>
                      </div>
                    </td>
                    <td style={{ padding: '16px 20px', color: 'var(--text-secondary)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <Clock size={14} /> {agent.last_seen || 'Just now'}
                      </div>
                    </td>
                    <td style={{ padding: '16px 20px', textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '16px' }}>
                        <Link to={`/agent/${agent.name}`} style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'var(--accent-secondary)', fontWeight: 600, fontSize: '0.8125rem' }}>
                          Manage <ChevronRight size={14} />
                        </Link>
                        <button
                          title={`Delete ${agent.name} and its telemetry`}
                          aria-label={`Delete ${agent.name}`}
                          onClick={() => { setDeleteError(null); setPendingDelete(agent.name); }}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', display: 'inline-flex', padding: '4px' }}
                          onMouseOver={e => e.currentTarget.style.color = 'var(--accent-color)'}
                          onMouseOut={e => e.currentTarget.style.color = 'var(--text-secondary)'}
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {pendingDelete && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-agent-title"
          onClick={() => !deleting && setPendingDelete(null)}
          style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '20px' }}
        >
          <div className="card" onClick={e => e.stopPropagation()} style={{ maxWidth: '480px', width: '100%', padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px', marginBottom: '16px' }}>
              <AlertTriangle size={22} color="var(--accent-color)" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <h3 id="delete-agent-title" style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '8px' }}>
                  Delete {pendingDelete}?
                </h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', lineHeight: 1.6 }}>
                  This drops the agent's telemetry database and removes its
                  enrolment identity. Every event, alert and AI verdict it
                  produced is deleted. This cannot be undone.
                </p>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.8125rem', lineHeight: 1.6, marginTop: '10px' }}>
                  A running agent will re-enrol under a new name. Uninstall it
                  first, or use Self-Destruct from its detail page.
                </p>
              </div>
            </div>

            {deleteError && (
              <div style={{ padding: '10px 12px', borderRadius: '4px', border: '1px solid var(--accent-color)', color: 'var(--accent-color)', fontSize: '0.8125rem', marginBottom: '16px' }}>
                {deleteError}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
              <button
                className="btn-secondary"
                disabled={deleting}
                onClick={() => setPendingDelete(null)}
                style={{ padding: '8px 16px', borderRadius: '6px', cursor: deleting ? 'not-allowed' : 'pointer' }}
              >
                Cancel
              </button>
              <button
                disabled={deleting}
                onClick={confirmDelete}
                style={{ padding: '8px 16px', borderRadius: '6px', border: 'none', backgroundColor: 'var(--accent-color)', color: 'white', fontWeight: 600, cursor: deleting ? 'not-allowed' : 'pointer', opacity: deleting ? 0.7 : 1 }}
              >
                {deleting ? 'Deleting...' : 'Delete permanently'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Agents;
