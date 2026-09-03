import React, { useEffect, useMemo, useState } from 'react';
import { Card, StatCard } from '../components/ui';
import { CategoryBars, ShareDonut, TrendChart } from '../components/ui/charts';

const chartNote: React.CSSProperties = {
  margin: '0 0 var(--space-3)', color: 'var(--text-muted)',
  fontSize: 'var(--text-xs)', maxWidth: '58ch',
};

/** Severity, not series: these categories *are* states, so they take the
 *  semantic colours rather than the chart palette. */
const ATTENTION_TONE: Record<string, string> = {
  'No channel': 'var(--sev-critical)',
  'Unsupported agent': 'var(--sev-high)',
  'Version unknown': 'var(--sev-medium)',
  'Behind': 'var(--sev-low)',
};

const CONNECTION_TONE: Record<string, string> = {
  Connected: 'var(--accent-success)',
  Disconnected: 'var(--sev-critical)',
};
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
  const [resources, setResources] = useState<any>(null);
  const [globalStats, setGlobalStats] = useState<any>(null);
  const [aiInsights, setAiInsights] = useState<any[]>([]);
  const [dbStatus, setDbStatus] = useState<any>(null);
  const [summary, setSummary] = useState<any>(null);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [trend, setTrend] = useState<{ date: string; detections: number; distinct: number }[]>([]);

  /* Derived on the page rather than asked of the server: the agents list
     already carries every field these count, and a second endpoint would be
     a second place for the definition of "needs attention" to live. */
  const attentionBuckets = useMemo(() => {
    const count = (fn: (a: any) => boolean) => agents.filter(fn).length;
    return [
      { name: 'No channel', value: count((a) => a.channel_connected === false) },
      { name: 'Unsupported agent', value: count((a) => a.version_state === 'unsupported') },
      { name: 'Version unknown', value: count((a) => a.version_state === 'unknown') },
      { name: 'Behind', value: count((a) => a.version_state === 'behind') },
    ];
  }, [agents]);

  const connectionBuckets = useMemo(() => ([
    { name: 'Connected', value: agents.filter((a: any) => a.channel_connected).length },
    { name: 'Disconnected', value: agents.filter((a: any) => !a.channel_connected).length },
  ]), [agents]);

  const versionSpread = useMemo(() => {
    const counts = new Map<string, number>();
    for (const a of agents as any[]) {
      // Null is a real answer, not a gap: it means the agent sent no version
      // at all, which is a different fact from being old.
      const key = a.agent_version || 'Not reported';
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);
  }, [agents]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      // Four fan-out requests collapsed into one aggregate. The page was
      // downloading up to 100 decrypted alerts per agent, and every AI
      // insight with its full raw log attached, only to count them.
      const [agentList, summary, serverRes, gStats, dbRes, aiRes, recent, trendRes] = await Promise.all([
        agentService.getAgents(),
        agentService.getDashboardSummary(),
        agentService.getServerResources(),
        agentService.getGlobalStats(),
        agentService.getCustom('/db-status').catch(() => null),
        // Still needed, but only for the three headlines shown here.
        agentService.getCustom('/api/ai-insights/all?limit=3&per_agent=3').catch(() => null),
        // The feed below shows six rows; it used to pull a hundred per agent.
        agentService.getCustom('/all_alerts?per_agent=3').catch(() => []),
        // Fleet-wide detections per day. Its own request because it walks
        // every agent database and must not hold up the tiles above it.
        agentService.getCustom('/threat-trend?days=14').catch(() => null),
      ]);
      setTrend(trendRes?.series || []);
      setAgents(agentList || []);
      setSummary(summary?.status === 'success' ? summary : null);
      setResources(serverRes);
      setGlobalStats(gStats);
      setDbStatus(dbRes);
      setAiInsights(aiRes?.results?.slice(0, 3) || []);
      setRecentAlerts(Array.isArray(recent) ? recent.slice(0, 6) : []);
    } catch (err) {
      console.error("Dashboard fetch error", err);
    } finally {
      setLoading(false);
    }
  };

  // Global Health, computed rather than asserted. "Alert Coverage: 100%" and
  // "DB Integrity: Verified" used to be literal strings in the JSX — they
  // never read anything and would have kept saying the same thing with the
  // database down. On a security dashboard a metric nobody computes is worse
  // than no metric, because it gets trusted.
  //
  // The counts now arrive already aggregated, so none of this depends on
  // having downloaded the underlying rows.
  const health = React.useMemo(() => {
    const online = agents.filter(a => a?.status === 'Online').length;
    const total = agents.length;
    const cov = summary?.coverage;
    const reporting = cov?.agents_reporting ?? 0;

    return {
      online,
      total,
      reporting,
      coverage: total > 0 ? Math.round((reporting / total) * 100) : null,
      recentInsights: summary?.totals?.insights_1h ?? 0,
      dbOnline: typeof dbStatus?.mysql === 'string' && dbStatus.mysql.startsWith('online'),
      dbDetail: dbStatus?.mysql || dbStatus?.error || 'unreachable',
    };
  }, [agents, summary, dbStatus]);

  const criticalCount = summary?.totals?.critical ?? 0;
  const alertCount = summary?.totals?.alerts ?? 0;

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
        <LinkedStat 
          icon={<Monitor color="var(--accent-secondary)" />} 
          label="Connected Agents" 
          value={agents.length.toString()} 
          link="/agents"
        />
        <LinkedStat 
          icon={<ShieldAlert color="var(--accent-color)" />} 
          label="Critical Alerts" 
          value={criticalCount.toString()}
          warning={criticalCount > 0}
          link="/all-alerts"
        />
        <LinkedStat 
          icon={<Database color="var(--accent-warning)" />} 
          label="Assets Discovered" 
          value={((globalStats?.total_hardware || 0) + (globalStats?.total_software || 0)).toString()} 
          link="/assets"
        />
        <LinkedStat 
          icon={<ShieldAlert color="#f472b6" />} 
          label="FIM Violations" 
          value={(globalStats?.total_fim_events || 0).toString()} 
          warning={(globalStats?.total_fim_events || 0) > 0}
          link="/fim"
        />
      </div>

      {/* Fleet health, as shapes rather than as numbers.
          Four counts an operator scans rather than reads: which hosts need
          attention, whether commands can actually reach them, what is
          installed out there, and whether today is unusual. */}
      <div className="responsive-grid" style={{ marginBottom: 'var(--space-5)' }}>
        <Card title="Agents requiring attention">
          <p style={chartNote}>
            Not an ideal operational state. Each bar is a different problem
            with a different fix.
          </p>
          <CategoryBars data={attentionBuckets} colorFor={(row) => ATTENTION_TONE[row.name]} />
        </Card>

        <Card title="Endpoint connection status">
          <p style={chartNote}>
            Whether a command would reach the host now. Telemetry travels on a
            separate connection, so an agent can be reporting and still be
            uncommandable.
          </p>
          <CategoryBars data={connectionBuckets} colorFor={(row) => CONNECTION_TONE[row.name]} />
        </Card>

        <Card title="Agent version coverage">
          <p style={chartNote}>
            What is actually installed across the fleet. Hosts that report no
            version predate version reporting entirely.
          </p>
          <ShareDonut data={versionSpread} />
        </Card>
      </div>

      <Card title="Threat trend" style={{ marginBottom: 'var(--space-5)' }}>
        <p style={chartNote}>
          Detections a day against how many <em>different</em> techniques were
          behind them. A spike in the bars with a flat line is almost always
          one noisy rule rather than an incident — which is why both are drawn.
        </p>
        <TrendChart data={trend} />
      </Card>

      <div className="responsive-grid" style={{ alignItems: 'start' }}>
        {/* Recent Alerts Feed */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '16px 24px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', backgroundColor: 'var(--sidebar-bg)' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>Recent Global Alerts</h3>
            <Link to="/all-alerts" style={{ fontSize: '0.75rem', color: 'var(--accent-secondary)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>View All</Link>
          </div>
          <div style={{ padding: '0' }}>
            {recentAlerts.map((alert, i) => (
              <div key={i} style={{ padding: '16px 24px', borderBottom: i < recentAlerts.length - 1 ? '1px solid var(--border-color)' : 'none', display: 'flex', gap: '16px', alignItems: 'flex-start', transition: 'background-color 0.2s ease' }}
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
            {recentAlerts.length === 0 && (
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
          
          {/* Fleet Exposure — counts, not a score. The endpoint behind this
              used to return "compliance: 100 - vulns*2 - fim*5", which pinned
              to zero on any real fleet and mapped to no framework. */}
          <div className="card" style={{ padding: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: '20px', gap: '12px' }}>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Fleet Exposure</h3>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>FIM: last 24h</span>
            </div>

            {!summary ? (
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Exposure data unavailable.
              </p>
            ) : (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
                  <ExposureStat
                    label="Vulnerabilities"
                    value={summary.totals?.vulnerabilities ?? 0}
                    tone={summary.totals?.vulnerabilities > 0 ? 'warn' : 'ok'}
                  />
                  <ExposureStat
                    label="File events 24h"
                    value={summary.totals?.fim_24h ?? 0}
                    tone={summary.totals?.fim_24h > 0 ? 'warn' : 'ok'}
                  />
                  <ExposureStat
                    label="Total alerts"
                    value={alertCount}
                    tone="neutral"
                  />
                  <ExposureStat
                    label="Critical"
                    value={criticalCount}
                    tone={criticalCount > 0 ? 'bad' : 'ok'}
                  />
                </div>

                {/* Worst agents first — where to start, not just how bad. */}
                {(summary.agents || []).slice(0, 3).map((a: any) => (
                  <div key={a.agent} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', padding: '6px 0', borderTop: '1px solid var(--border-color)' }}>
                    <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{a.agent}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>
                      {a.critical} critical · {a.vulnerabilities} vulns · {a.fim_24h} file events
                    </span>
                  </div>
                ))}

                {/* Partial numbers must say so. A total over half the fleet is
                    not a fleet total. */}
                {summary.coverage && !summary.coverage.complete && (
                  <p style={{ fontSize: '0.7rem', color: 'var(--accent-warning)', marginTop: '12px', lineHeight: 1.5 }}>
                    Partial: {summary.coverage.agents_scanned} of {summary.coverage.agents_total} agents scanned
                    {summary.coverage.agents_unreachable?.length
                      ? ` (no data from ${summary.coverage.agents_unreachable.join(', ')})`
                      : ''}
                  </p>
                )}
              </>
            )}
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

const ExposureStat: React.FC<{ label: string; value: number; tone: 'ok' | 'warn' | 'bad' | 'neutral' }> = ({ label, value, tone }) => {
  const color = value === 0
    ? 'var(--text-secondary)'
    : tone === 'bad' ? 'var(--accent-color)'
      : tone === 'warn' ? 'var(--accent-warning)'
        : tone === 'ok' ? 'var(--accent-success)'
          : 'var(--text-primary)';
  return (
    <div>
      <div style={{ fontSize: '1.5rem', fontWeight: 800, color, lineHeight: 1.2 }}>{value}</div>
      <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{label}</div>
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

/** A dashboard tile that navigates. The shared `StatCard` deliberately knows
 *  nothing about routing - a primitive that takes a `link` is a primitive that
 *  will be asked to take an `onClick`, then a `target`, and stop being one. */
const LinkedStat = ({ icon, label, value, warning, link }: {
  icon: React.ReactNode; label: string; value: string;
  warning?: boolean; link?: string;
}) => {
  const tile = (
    <StatCard
      icon={icon}
      label={label}
      value={value}
      color={warning ? 'var(--accent-color)' : undefined}
    />
  );
  return link ? <Link to={link} style={{ display: 'block' }}>{tile}</Link> : tile;
};

export default Dashboard;
