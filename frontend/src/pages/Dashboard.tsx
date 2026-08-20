import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, 
  Monitor, 
  Activity, 
  Cpu,
  Database,
  HardDrive,
  RefreshCw
} from 'lucide-react';
import { agentService } from '../services/api';
import { Link } from 'react-router-dom';

const Dashboard: React.FC = () => {
  const [agents, setAgents] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [resources, setResources] = useState<any>(null);
  const [globalStats, setGlobalStats] = useState<any>(null);
  const [aiInsights, setAiInsights] = useState<any[]>([]);
  const [allInsights, setAllInsights] = useState<any[]>([]);
  const [dbStatus, setDbStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [agentList, allAlerts, serverRes, gStats, aiRes, dbRes] = await Promise.all([
        agentService.getAgents(),
        agentService.getAllAlerts(),
        agentService.getServerResources(),
        agentService.getGlobalStats(),
        agentService.getCustom('/api/ai-insights/all'),
        agentService.getCustom('/db-status').catch(() => null),
      ]);
      setAgents(agentList || []);
      setAlerts(allAlerts || []);
      setResources(serverRes);
      setGlobalStats(gStats);
      setDbStatus(dbRes);
      if (aiRes && aiRes.results) {
        setAllInsights(aiRes.results || []);
        setAiInsights(aiRes.results.slice(0, 3)); // Only show top 3 on dashboard
      }
    } catch (err) {
      console.error("Dashboard fetch error", err);
    } finally {
      setLoading(false);
    }
  };

  const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL');

  // Global Health, computed rather than asserted. "Alert Coverage: 100%" and
  // "DB Integrity: Verified" used to be literal strings in the JSX — they
  // never read anything and would have kept saying the same thing with the
  // database down. On a security dashboard a metric nobody computes is worse
  // than no metric, because it gets trusted.
  const health = React.useMemo(() => {
    const online = agents.filter(a => a?.status === 'Online').length;
    const total = agents.length;

    // Agents the platform has actually received alert telemetry from. An
    // enrolled agent that is online but has never reported is a blind spot,
    // and that distinction is the whole point of a coverage number.
    const reporting = new Set(
      alerts.map(a => a?.agent).filter(Boolean)
    ).size;

    // Insights produced in the last hour — shows the worker fleet is draining
    // its queue, not just that rows exist from some point in the past.
    const hourAgo = Date.now() - 3600_000;
    const recentInsights = allInsights.filter(i => {
      const t = Date.parse(i?.created_at || i?.timestamp || '');
      return Number.isFinite(t) && t >= hourAgo;
    }).length;

    return {
      online,
      total,
      reporting,
      coverage: total > 0 ? Math.round((reporting / total) * 100) : null,
      recentInsights,
      dbOnline: typeof dbStatus?.mysql === 'string' && dbStatus.mysql.startsWith('online'),
      dbDetail: dbStatus?.mysql || dbStatus?.error || 'unreachable',
    };
  }, [agents, alerts, allInsights, dbStatus]);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px', flexWrap: 'wrap', gap: '20px' }}>
        <div>
          <h2 style={{ fontSize: '2rem', fontWeight: 800, letterSpacing: '-0.025em', marginBottom: '8px' }}>Security Command Center</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Enterprise-wide security posture and system health monitoring.</p>
        </div>
        <button onClick={fetchData} className="btn-secondary" style={{ padding: '10px 20px', borderRadius: '10px', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.875rem', fontWeight: 600 }}>
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> Refresh Metrics
        </button>
      </div>

      {/* Resource Meters Row */}
      <div className="responsive-grid" style={{ marginBottom: '32px' }}>
        <ResourceCard 
          label="Server CPU" 
          value={resources?.cpu_usage || 0} 
          icon={<Cpu size={20} color="var(--accent-secondary)" />} 
        />
        <ResourceCard 
          label="Server RAM" 
          value={resources?.ram_usage || 0} 
          icon={<Database size={20} color="var(--accent-warning)" />} 
        />
        <ResourceCard 
          label="System Disk" 
          value={resources?.disk_usage || 0} 
          icon={<HardDrive size={20} color="var(--accent-success)" />} 
        />
      </div>

      {/* Main Stats Row */}
      <div className="responsive-grid" style={{ marginBottom: '24px' }}>
        <StatCard 
          icon={<Monitor color="var(--accent-secondary)" />} 
          label="Connected Agents" 
          value={agents.length.toString()} 
          link="/agents"
        />
        <StatCard 
          icon={<ShieldAlert color="var(--accent-color)" />} 
          label="Critical Alerts" 
          value={criticalAlerts.length.toString()} 
          warning={criticalAlerts.length > 0}
          link="/all-alerts"
        />
        <StatCard 
          icon={<Database color="var(--accent-warning)" />} 
          label="Assets Discovered" 
          value={((globalStats?.total_hardware || 0) + (globalStats?.total_software || 0)).toString()} 
          link="/assets"
        />
        <StatCard 
          icon={<ShieldAlert color="#f472b6" />} 
          label="FIM Violations" 
          value={(globalStats?.total_fim_events || 0).toString()} 
          warning={(globalStats?.total_fim_events || 0) > 0}
          link="/fim"
        />
      </div>

      <div className="responsive-grid" style={{ alignItems: 'start' }}>
        {/* Recent Alerts Feed */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', backgroundColor: 'var(--sidebar-bg)' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>Recent Global Alerts</h3>
            <Link to="/all-alerts" style={{ fontSize: '0.75rem', color: 'var(--accent-secondary)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>View All</Link>
          </div>
          <div style={{ padding: '0' }}>
            {alerts.slice(0, 6).map((alert, i) => (
              <div key={i} style={{ padding: '16px 24px', borderBottom: i < alerts.slice(0,6).length - 1 ? '1px solid var(--border-color)' : 'none', display: 'flex', gap: '16px', alignItems: 'flex-start', transition: 'background-color 0.2s ease' }}
                onMouseOver={e => e.currentTarget.style.backgroundColor = 'var(--bg-color)'}
                onMouseOut={e => e.currentTarget.style.backgroundColor = 'transparent'}
              >
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: alert.severity === 'CRITICAL' ? 'var(--accent-color)' : 'var(--accent-warning)', marginTop: '6px', flexShrink: 0 }}></div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', flexWrap: 'wrap', gap: '8px' }}>
                    <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>{alert.agent}</span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 500 }}>{alert.timestamp}</span>
                  </div>
                  <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{alert.message}</p>
                </div>
              </div>
            ))}
            {alerts.length === 0 && (
              <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
                <Activity size={48} style={{ opacity: 0.1 }} />
                <p>No recent alerts detected in the system.</p>
              </div>
            )}
          </div>
        </div>

        {/* Quick Actions & Health */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* AI Intelligence Feed */}
          <div className="card" style={{ 
            background: 'linear-gradient(135deg, rgba(37, 99, 235, 0.1) 0%, rgba(29, 78, 216, 0.05) 100%)',
            border: '1px solid rgba(37, 99, 235, 0.2)',
            padding: '24px',
            boxShadow: '0 10px 30px rgba(0,0,0,0.2)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
              <div style={{ padding: '8px', backgroundColor: 'rgba(37, 99, 235, 0.2)', borderRadius: '10px' }}>
                <Activity size={20} color="var(--accent-secondary)" />
              </div>
              <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>AI Security Intelligence</h3>
            </div>
            
            {aiInsights.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {aiInsights.map((insight, idx) => (
                  <div key={idx} style={{ 
                    padding: '12px', 
                    borderRadius: '12px', 
                    backgroundColor: 'rgba(0,0,0,0.2)', 
                    border: '1px solid rgba(255,255,255,0.05)' 
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                      <span style={{ fontWeight: 700, color: 'var(--accent-secondary)' }}>{insight.agent?.toUpperCase()}</span>
                      <span>{insight.timestamp}</span>
                    </div>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', lineHeight: 1.4 }}>
                      {insight.critical_summary?.substring(0, 120)}...
                    </p>
                  </div>
                ))}
                <Link to="/soar-hub" style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-secondary)', textAlign: 'center', marginTop: '8px' }}>VIEW FULL INTELLIGENCE HUB</Link>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '20px 0' }}>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>AI models are currently scanning for threats...</p>
              </div>
            )}
          </div>

          <div className="card" style={{ padding: '24px' }}>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '24px' }}>Global Health</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <HealthRow
                label="Agents Online"
                hint="Reported telemetry within the last 90 seconds"
                value={`${health.online} / ${health.total}`}
                color={
                  health.total === 0 ? 'var(--text-secondary)'
                    : health.online === health.total ? 'var(--accent-success)'
                    : health.online === 0 ? 'var(--accent-color)'
                    : 'var(--accent-warning)'
                }
              />
              <HealthRow
                label="Alert Coverage"
                hint="Enrolled agents the platform has received alerts from. The rest are blind spots."
                value={health.coverage === null ? 'No agents' : `${health.coverage}%`}
                color={
                  health.coverage === null ? 'var(--text-secondary)'
                    : health.coverage >= 100 ? 'var(--accent-success)'
                    : health.coverage >= 50 ? 'var(--accent-warning)'
                    : 'var(--accent-color)'
                }
                sub={health.coverage === null ? undefined : `${health.reporting} of ${health.total} reporting`}
              />
              <HealthRow
                label="AI Triage"
                hint="Insights written by the worker fleet in the last hour"
                value={health.recentInsights > 0 ? `${health.recentInsights} / hr` : 'Idle'}
                color={health.recentInsights > 0 ? 'var(--accent-success)' : 'var(--text-secondary)'}
              />
              <HealthRow
                label="Database"
                hint={String(health.dbDetail)}
                value={health.dbOnline ? 'Online' : 'Unreachable'}
                color={health.dbOnline ? 'var(--accent-success)' : 'var(--accent-color)'}
              />
            </div>
          </div>
          
          <Link to="/ai-analysis" className="card" style={{ 
            borderColor: 'var(--border-color)', 
            padding: '24px', 
            display: 'flex', 
            flexDirection: 'column', 
            gap: '16px',
            backgroundColor: 'var(--card-bg)'
          }} onMouseOver={e => e.currentTarget.style.borderColor = 'var(--accent-secondary)'} onMouseOut={e => e.currentTarget.style.borderColor = 'var(--border-color)'}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ padding: '10px', backgroundColor: 'rgba(96, 165, 250, 0.1)', borderRadius: '12px' }}>
                <Activity size={24} color="var(--accent-secondary)" />
              </div>
              <div>
                <h4 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--accent-secondary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  AI Security Pulse
                  <span style={{ fontSize: '0.625rem', padding: '2px 6px', backgroundColor: 'var(--accent-success)', color: 'black', borderRadius: '4px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Live</span>
                </h4>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '2px' }}>Continuous background analysis via RabbitMQ</p>
              </div>
            </div>
          </Link>
        </div>
      </div>
    </div>
  );
};

// `hint` goes on the title attribute so the definition of each number is
// reachable — a coverage percentage nobody can define is a number nobody can
// act on.
const HealthRow: React.FC<{
  label: string;
  value: string;
  color: string;
  hint?: string;
  sub?: string;
}> = ({ label, value, color, hint, sub }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', fontSize: '0.875rem', gap: '12px' }} title={hint}>
    <span style={{ color: 'var(--text-secondary)', fontWeight: 500, cursor: hint ? 'help' : 'default' }}>{label}</span>
    <div style={{ textAlign: 'right' }}>
      <div style={{ fontWeight: 700, color }}>{value}</div>
      {sub && (
        <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '2px', fontWeight: 500 }}>
          {sub}
        </div>
      )}
    </div>
  </div>
);

const ResourceCard: React.FC<{ label: string, value: number, icon: React.ReactNode }> = ({ label, value, icon }) => (
  <div className="card">
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
      <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-secondary)' }}>{label}</span>
      {icon}
    </div>
    <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '12px' }}>
      <span className="mono" style={{ fontSize: '2rem', fontWeight: 600 }}>{Math.round(value)}%</span>
    </div>
    <div style={{ height: '4px', backgroundColor: 'var(--border-color)', borderRadius: '2px', overflow: 'hidden' }}>
      <div 
        style={{ 
          width: `${value}%`, 
          height: '100%', 
          backgroundColor: value > 85 ? 'var(--accent-color)' : value > 60 ? 'var(--accent-warning)' : 'var(--accent-success)',
          transition: 'width 1s cubic-bezier(0.4, 0, 0.2, 1)'
        }} 
      />
    </div>
  </div>
);

const StatCard: React.FC<{ 
  icon: React.ReactNode, 
  label: string, 
  value: string, 
  warning?: boolean,
  link?: string
}> = ({ icon, label, value, warning, link }) => {
  const content = (
    <div className="card" style={{ cursor: link ? 'pointer' : 'default', padding: '24px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
        <div style={{ width: '40px', height: '40px', borderRadius: '12px', backgroundColor: 'rgba(255,255,255,0.03)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--border-color)' }}>
          {icon}
        </div>
        <span style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', fontWeight: 600, letterSpacing: '0.01em' }}>{label}</span>
      </div>
      <div className="mono" style={{ fontSize: '2.25rem', fontWeight: 800, color: warning ? 'var(--accent-color)' : 'var(--text-primary)', letterSpacing: '-0.025em' }}>{value}</div>
    </div>
  );

  return link ? <Link to={link}>{content}</Link> : content;
};

export default Dashboard;
