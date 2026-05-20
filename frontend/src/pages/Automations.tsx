import React, { useEffect, useState } from 'react';
import { 
  Zap,
  CheckCircle2,
  AlertCircle,
  Clock,
  Terminal,
  Activity,
  Plus,
  Edit2,
  Trash2,
  X,
  Save,
  RefreshCw
} from 'lucide-react';
import { agentService } from '../services/api';

const Automations: React.FC = () => {
  const [agents, setAgents] = useState<string[]>([]);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [automations, setAutomations] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState('all');

  // Modal states
  const [showModal, setShowModal] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [formData, setFormData] = useState({
    action: 'block_ip',
    target: '',
    comment: '',
    event_id: ''
  });

  useEffect(() => {
    agentService.getAgents().then(list => {
      const agentNames = list.map((a: any) => typeof a === 'string' ? a : a.name);
      setAgents(agentNames);
      if (agentNames.length > 0) setSelectedAgent(agentNames[0]);
    });
  }, []);

  useEffect(() => {
    if (selectedAgent) {
      fetchData();
    }
  }, [selectedAgent]);

  const fetchData = () => {
    if (!selectedAgent) return;
    setLoading(true);
    agentService.getAutomations(selectedAgent)
      .then(setAutomations)
      .finally(() => setLoading(false));
  };

  const handleOpenCreate = () => {
    setIsEditing(false);
    setEditingId(null);
    setFormData({
      action: 'block_ip',
      target: '',
      comment: 'Manual SOAR trigger',
      event_id: ''
    });
    setShowModal(true);
  };

  const handleOpenEdit = (auto: any) => {
    setIsEditing(true);
    setEditingId(auto.id);
    setFormData({
      action: auto.action,
      target: auto.target,
      comment: auto.comment || '',
      event_id: auto.event_id?.toString() || ''
    });
    setShowModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAgent) return;
    try {
      const payload = {
        ...formData,
        event_id: formData.event_id ? parseInt(formData.event_id) : null
      };

      if (isEditing && editingId) {
        await agentService.updateAutomation(selectedAgent, editingId, payload);
      } else {
        await agentService.createAutomation(selectedAgent, payload);
      }
      setShowModal(false);
      fetchData();
    } catch (err: any) {
      alert("Error saving automation: " + (err.response?.data?.error || err.message));
    }
  };

  const handleDelete = async (id: number) => {
    if (!selectedAgent) return;
    if (window.confirm("Delete this automation rule?")) {
      try {
        await agentService.deleteAutomation(selectedAgent, id);
        fetchData();
      } catch (err) {
        alert("Failed to delete automation");
      }
    }
  };

  const filteredAutomations = automations.filter(a => {
    if (filter === 'active') return a.status === 'active' || a.status === 'pending';
    if (filter === 'completed') return a.status === 'completed' || a.status === 'success';
    if (filter === 'failed') return a.status === 'failed';
    return true;
  });

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h2 style={{ fontSize: '1.875rem', marginBottom: '8px' }}>Global SOAR Automations</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Manage automated response rules and view execution history.</p>
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <select 
            value={selectedAgent}
            onChange={(e) => setSelectedAgent(e.target.value)}
            style={{
              backgroundColor: 'var(--card-bg)',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              padding: '10px 16px',
              color: 'var(--text-primary)',
              fontSize: '0.875rem',
              outline: 'none'
            }}
          >
            {agents.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
          <button 
            onClick={handleOpenCreate}
            disabled={!selectedAgent}
            style={{ 
              backgroundColor: !selectedAgent ? 'var(--border-color)' : 'var(--accent-secondary)', 
              color: 'white', 
              padding: '10px 20px', 
              borderRadius: '8px', 
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              cursor: !selectedAgent ? 'not-allowed' : 'pointer'
            }}
          >
            <Plus size={18} /> New Automation
          </button>
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: '16px' }}>
            <FilterButton label="All" active={filter === 'all'} onClick={() => setFilter('all')} />
            <FilterButton label="Active" active={filter === 'active'} onClick={() => setFilter('active')} />
            <FilterButton label="Completed" active={filter === 'completed'} onClick={() => setFilter('completed')} />
            <FilterButton label="Failed" active={filter === 'failed'} onClick={() => setFilter('failed')} />
          </div>
          <button onClick={fetchData} style={{ color: 'var(--text-secondary)' }}><RefreshCw size={18} className={loading ? 'animate-spin' : ''} /></button>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ backgroundColor: 'rgba(255,255,255,0.02)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>ID / Time</th>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>Action</th>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>Target</th>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>Status</th>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>Reason / Detail</th>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAutomations.map((auto) => (
                <tr key={auto.id} style={{ borderBottom: '1px solid var(--border-color)', transition: 'background-color 0.2s ease' }} onMouseOver={(e) => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.01)'} onMouseOut={(e) => e.currentTarget.style.backgroundColor = 'transparent'}>
                  <td style={{ padding: '16px 20px' }}>
                    <div style={{ fontWeight: 600 }}>#{auto.id}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px', marginTop: '4px' }}>
                      <Clock size={12} /> {auto.timestamp}
                    </div>
                  </td>
                  <td style={{ padding: '16px 20px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 500 }}>
                      <Terminal size={16} color="var(--accent-secondary)" />
                      {auto.action?.toUpperCase()}
                    </div>
                  </td>
                  <td style={{ padding: '16px 20px', color: 'var(--text-secondary)', verticalAlign: 'top', minWidth: '180px', maxWidth: '260px' }}>
                    <TargetCell auto={auto} />
                  </td>
                  <td style={{ padding: '16px 20px', verticalAlign: 'top', whiteSpace: 'nowrap' }}>
                    <StatusBadge status={auto.status} />
                  </td>
                  <td style={{ padding: '16px 20px', verticalAlign: 'top', minWidth: '260px' }}>
                    <ReasonCell auto={auto} />
                  </td>
                  <td style={{ padding: '16px 20px', textAlign: 'right' }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                      <button onClick={() => handleOpenEdit(auto)} style={{ color: 'var(--text-secondary)' }}><Edit2 size={16} /></button>
                      <button onClick={() => handleDelete(auto.id)} style={{ color: 'var(--accent-color)' }}><Trash2 size={16} /></button>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredAutomations.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} style={{ padding: '60px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                    <Zap size={48} style={{ opacity: 0.1, marginBottom: '16px', margin: '0 auto' }} />
                    <p>No automations found matching the criteria.</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Automation Modal */}
      {showModal && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '20px' }}>
          <div style={{ backgroundColor: 'var(--card-bg)', backdropFilter: 'blur(20px)', width: '100%', maxWidth: '500px', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-neon)', padding: '32px', boxShadow: '0 20px 50px rgba(0,0,0,0.5)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <h3 style={{ fontSize: '1.25rem' }}>{isEditing ? 'Edit Automation' : 'New SOAR Automation'}</h3>
              <button onClick={() => setShowModal(false)} style={{ color: 'var(--text-secondary)' }}><X size={24} /></button>
            </div>
            
            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <label style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Action Type</label>
                <select 
                  value={formData.action} 
                  onChange={e => setFormData({...formData, action: e.target.value})}
                  style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px', color: 'white' }}
                >
                  <option value="block_ip">Block IP Address</option>
                  <option value="unblock_ip">Unblock IP Address</option>
                  <option value="disable_user">Disable User Account</option>
                  <option value="enable_user">Enable User Account</option>
                  <option value="quarantine_file">Quarantine File</option>
                  <option value="delete_file">Delete File</option>
                  <option value="kill_process">Kill Process</option>
                  <option value="suspend_process">Suspend Process (Dondur)</option>
                  <option value="delete_registry_key">Delete Registry Key</option>
                  <option value="protect_shadows">Protect Volume Shadows</option>
                  <option value="restart_service">Restart Service</option>
                  <option value="isolate_host">Isolate Host</option>
                  <option value="lock_machine">Lock Machine</option>
                  <option value="tail_log">Tail Log File</option>
                  <option value="run_cmd">Run Custom Command</option>
                </select>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <label style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Target (IP, Path, PID, etc.)</label>
                <input 
                  type="text" 
                  value={formData.target} 
                  onChange={e => setFormData({...formData, target: e.target.value})} 
                  required 
                  placeholder="e.g. 192.168.1.100"
                  style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px', color: 'white' }} 
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <label style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Comment / Reason</label>
                <input 
                  type="text" 
                  value={formData.comment} 
                  onChange={e => setFormData({...formData, comment: e.target.value})} 
                  style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px', color: 'white' }} 
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <label style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>SIEM Event ID (Optional)</label>
                <input 
                  type="number" 
                  value={formData.event_id} 
                  onChange={e => setFormData({...formData, event_id: e.target.value})} 
                  placeholder="Link to a specific alert"
                  style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px', color: 'white' }} 
                />
              </div>

              <div style={{ display: 'flex', gap: '12px', marginTop: '12px' }}>
                <button type="button" onClick={() => setShowModal(false)} style={{ flex: 1, padding: '14px', borderRadius: '8px', border: '1px solid var(--border-color)', color: 'white', fontWeight: 600 }}>Cancel</button>
                <button type="submit" style={{ flex: 1, padding: '14px', borderRadius: '8px', backgroundColor: 'var(--accent-secondary)', color: 'white', fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                  <Save size={18} /> {isEditing ? 'Update Rule' : 'Execute Now'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

const FilterButton: React.FC<{ label: string, active: boolean, onClick: () => void }> = ({ label, active, onClick }) => (
  <button 
    onClick={onClick}
    style={{
      padding: '6px 12px',
      borderRadius: '6px',
      fontSize: '0.875rem',
      fontWeight: 500,
      backgroundColor: active ? 'var(--accent-secondary)' : 'transparent',
      color: active ? 'white' : 'var(--text-secondary)',
      transition: 'all 0.2s ease'
    }}
  >
    {label}
  </button>
);

const ReasonCell: React.FC<{ auto: any }> = ({ auto }) => {
  const status = (auto.status || '').toLowerCase();
  const isFailure = status === 'failed';
  const text = (auto.last_error || auto.error || auto.comment || '').toString().trim();
  if (!text) {
    return <span style={{ opacity: 0.5 }}>—</span>;
  }
  return (
    <div
      style={{
        color: isFailure ? 'var(--accent-color)' : 'var(--text-secondary)',
        whiteSpace: 'normal',
        wordBreak: 'break-word',
        overflowWrap: 'anywhere',
        lineHeight: 1.4,
        fontSize: '0.8125rem',
      }}
    >
      {text}
    </div>
  );
};

const TargetCell: React.FC<{ auto: any }> = ({ auto }) => {
  let display = auto.target;
  if (typeof display === 'string') {
    const trimmed = display.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      try {
        const arr = JSON.parse(trimmed);
        if (Array.isArray(arr)) {
          display = arr.join(' ');
        }
      } catch {
        // leave as-is
      }
    }
  } else if (Array.isArray(display)) {
    display = display.join(' ');
  }
  return (
    <span style={{ fontFamily: 'monospace', wordBreak: 'break-word', overflowWrap: 'anywhere' }}>
      {display}
    </span>
  );
};

const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const normalized = (status || '').toLowerCase();
  let color = 'var(--text-secondary)';
  let bg = 'rgba(255,255,255,0.05)';
  let icon = <Clock size={14} />;

  if (normalized === 'completed' || normalized === 'success') {
    color = 'var(--accent-success)';
    bg = 'rgba(16, 185, 129, 0.1)';
    icon = <CheckCircle2 size={14} />;
  } else if (normalized === 'failed') {
    color = 'var(--accent-color)';
    bg = 'rgba(239, 68, 68, 0.1)';
    icon = <AlertCircle size={14} />;
  } else if (normalized === 'active' || normalized === 'pending') {
    color = 'var(--accent-warning)';
    bg = 'rgba(245, 158, 11, 0.1)';
    icon = <Activity size={14} className="animate-spin" />;
  }

  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 10px', borderRadius: '20px', backgroundColor: bg, color: color, fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase' }}>
      {icon} {status || 'PENDING'}
    </div>
  );
};

export default Automations;
