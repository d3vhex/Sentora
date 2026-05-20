import React, { useEffect, useState } from 'react';
import {
  Monitor,
  Search,
  Filter,
  Clock,
  RefreshCw,
  ChevronRight
} from 'lucide-react';
import { agentService } from '../services/api';
import { Link } from 'react-router-dom';

const Agents: React.FC = () => {
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

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

  const filteredAgents = agents.filter(agent => 
    agent.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (agent.public_ip || '').includes(searchTerm) ||
    (agent.os_info || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div style={{ animation: 'fadeIn 0.3s ease' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px', flexWrap: 'wrap', gap: '20px' }}>
        <div>
          <h2 style={{ fontSize: '2rem', fontWeight: 800, letterSpacing: '-0.025em', marginBottom: '8px' }}>Security Agents</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Manage and monitor all endpoints connected to the Zer0Vuln network.</p>
        </div>
        <div className="flex-responsive" style={{ gap: '12px' }}>
          <button className="btn-secondary" onClick={() => fetchAgents(true)} style={{ padding: '8px 16px', borderRadius: '6px', display: 'flex', alignItems: 'center', gap: '8px', backgroundColor: 'var(--bg-color)' }}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
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
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{agent.name}</div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{agent.os_info || 'Generic Linux'}</div>
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
                      <Link to={`/agent/${agent.name}`} style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'var(--accent-secondary)', fontWeight: 600, fontSize: '0.8125rem' }}>
                        Manage <ChevronRight size={14} />
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Agents;
