import React, { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { useParams, Link } from 'react-router-dom';
import { 
  ShieldAlert, 
  Cpu, 
  AlertTriangle,
  Activity,
  Zap,
  Package,
  FileSearch,
  HardDrive,
  BrainCircuit,
  Network,
  LayoutGrid,
  ChevronLeft,
  RefreshCw,
  Settings,
  Save,
  RotateCcw,
  ShieldCheck,
  Bomb,
  MonitorPlay,
  Box
} from 'lucide-react';
import { agentService } from '../services/api';
import VncViewer from '../components/VncViewer';
import Fuse from 'fuse.js';

// log_extractor often stuffs the enriched event into the `message` column as a
// JSON string. Surface the inner fields so the table shows real columns instead
// of a wall of red JSON.
function parseSiemRow(r: any) {
  let inner: any = null;
  if (typeof r?.message === 'string' && r.message.trim().startsWith('{')) {
    try { inner = JSON.parse(r.message); } catch { inner = null; }
  }
  const get = (k: string) => (inner && inner[k] != null ? inner[k] : r?.[k]) ?? '';
  return {
    timestamp: get('timestamp') || get('datetime') || '',
    severity: String(get('severity') || '').toUpperCase(),
    // events_alert stores the event type in `categories`; siem_events stuffs it
    // into `event_type` inside the message JSON. Read both so the column isn't
    // blank for alert rows.
    event_type: get('event_type') || get('categories') || '',
    source: get('source') || '',
    message: (inner && inner.message) ? inner.message : (r?.message ?? ''),
  };
}

const AgentDetail: React.FC = () => {
  const { agentName } = useParams<{ agentName: string }>();
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<any>({
    info: [],
    resources: [],
    siem: [],
    alerts: [],
    vulnerabilities: [],
    soar: [],
    disks: [],
    portscans: [],
    criticalFiles: [],
    packages: [],
    containers: [],
    aiInsights: []
  });

  // Config tab states
  const [configType, setConfigType] = useState('rules');
  const [configContent, setConfigContent] = useState('');
  const [configLoading, setConfigLoading] = useState(false);
  const [configIssues, setConfigIssues] = useState<ConfigIssue[]>([]);
  const [configChecking, setConfigChecking] = useState(false);
  const [configStatus, setConfigStatus] = useState<{ ok: boolean; message: string } | null>(null);
  const configTextareaRef = React.useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (agentName) {
      fetchAgentData(true);
      const interval = setInterval(() => {
        fetchAgentData(false);
      }, 45000); // Poll every 45 seconds
      
      return () => clearInterval(interval);
    }
  }, [agentName]);

  const fetchAgentData = async (showLoading = true) => {
    if (!agentName) return;
    if (showLoading) setLoading(true);
    try {
      const results = await Promise.all([
        agentService.getAgentInfo(agentName),
        agentService.getAgentResources(agentName),
        agentService.getSiemEvents(agentName),
        agentService.getEventsAlert(agentName),
        agentService.getVulnerabilities(agentName),
        agentService.getSoarActions(agentName),
        agentService.getAgentDisk(agentName),
        agentService.getPortscans(agentName),
        agentService.getCriticalFiles(agentName),
        agentService.getPackages(agentName),
        agentService.getDockerContainers(agentName),
        agentService.getAiInsights(agentName)
      ]);
      const [info, resources, siem, alerts, vulnerabilities, soar, disks, portscans, files, pkgs, containers, aiInsightsData] = results;
      setData({ 
        info, resources, siem, alerts, vulnerabilities, soar, disks, 
        portscans, criticalFiles: files, packages: pkgs, containers,
        aiInsights: aiInsightsData || []
      });
    } catch (err) {
      console.error("Failed to fetch agent data", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchConfig = async (type: string) => {
    if (!agentName) return;
    setConfigLoading(true);
    try {
      const res = await agentService.getAgentYamlConfig(agentName, type);
      setConfigContent(res.content);
    } catch (err) {
      console.error("Failed to fetch config", err);
      setConfigContent("# Error loading config from agent.");
    } finally {
      setConfigLoading(false);
    }
  };

  // Lint as you type, debounced. The server owns the rules — duplicating them
  // in the browser would mean two implementations drifting apart, and the
  // browser's copy being the one operators trust.
  useEffect(() => {
    if (!agentName || activeTab !== 'config' || !configContent.trim()) {
      setConfigIssues([]);
      return;
    }
    const t = setTimeout(async () => {
      setConfigChecking(true);
      try {
        const res = await agentService.validateAgentConfig(agentName, configType, configContent);
        setConfigIssues(res.issues || []);
      } catch {
        setConfigIssues([]);   // lint is advisory; the save still validates
      } finally {
        setConfigChecking(false);
      }
    }, 600);
    return () => clearTimeout(t);
  }, [configContent, configType, agentName, activeTab]);

  const handleSaveConfig = async () => {
    if (!agentName) return;
    setConfigLoading(true);
    setConfigStatus(null);
    try {
      const res = await agentService.setAgentYamlConfig(agentName, configType, configContent);
      setConfigIssues(res.issues || []);
      setConfigStatus({ ok: true, message: res.message || 'Configuration pushed to the agent.' });
    } catch (err: any) {
      // A 400 carries the validation issues; nothing reached the agent.
      const body = err?.response?.data;
      setConfigIssues(body?.issues || []);
      setConfigStatus({
        ok: false,
        message: body?.message || 'Failed to update configuration. Ensure the agent is reachable.',
      });
    } finally {
      setConfigLoading(false);
    }
  };

  const handleRestart = async () => {
    if (window.confirm("Restart agent service?")) {
      try {
        await agentService.restartAgent(agentName!);
        alert("Restart command sent.");
      } catch (err) { alert("Failed to send restart command."); }
    }
  };

  const handleReloadLicense = async () => {
    try {
      await agentService.reloadAgentLicense(agentName!);
      alert("License reload command sent.");
    } catch (err) { alert("Failed to reload license."); }
  };

  const handleSelfDestruct = async () => {
    if (window.confirm("DANGER: This will UNINSTALL and DELETE the agent from the remote host. Proceed?")) {
      try {
        await agentService.selfDestructAgent(agentName!);
        alert("Self-destruct command sent.");
      } catch (err) { alert("Failed to send command."); }
    }
  };

  useEffect(() => {
    if (activeTab === 'config') {
      fetchConfig(configType);
    }
  }, [activeTab, configType]);

  const tabs = [
    { id: 'overview', label: 'Overview', icon: <LayoutGrid size={18} /> },
    { id: 'siem', label: 'SIEM Logs', icon: <Activity size={18} /> },
    { id: 'alerts', label: 'Alerts', icon: <ShieldAlert size={18} /> },
    { id: 'vulnerabilities', label: 'Vulns', icon: <AlertTriangle size={18} /> },
    { id: 'packages', label: 'Packages', icon: <Package size={18} /> },
    { id: 'docker', label: 'Docker', icon: <Box size={18} /> },
    { id: 'portscan', label: 'Ports', icon: <Network size={18} /> },
    { id: 'files', label: 'Files', icon: <FileSearch size={18} /> },
    { id: 'vnc', label: 'VNC', icon: <MonitorPlay size={18} /> },
    { id: 'config', label: 'Config', icon: <Settings size={18} /> },
    { id: 'ai', label: 'AI Analysis', icon: <BrainCircuit size={18} /> },
    { id: 'soar', label: 'SOAR', icon: <Zap size={18} /> },
    { id: 'system', label: 'System', icon: <Cpu size={18} /> },
  ];

  if (loading && !data.info.length) {
    return (
      <div style={{ height: '80vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <RefreshCw size={48} color="var(--accent-secondary)" style={{ animation: 'spin 1s linear infinite' }} />
      </div>
    );
  }

  const agentInfo = data.info[0] || {};
  let isOnline = false;
  if (agentInfo.status === 'Online') {
    isOnline = true;
  } else if (agentInfo.last_seen) {
    // Server emits naive timestamps as "YYYY-MM-DD HH:MM:SS" with no TZ info.
    // The backend container is UTC; treat the value as UTC so a UTC+N user
    // doesn't see their own (still-active) agent flagged offline.
    const ls = String(agentInfo.last_seen).trim();
    const isoLike = /[zZ]|[+-]\d{2}:?\d{2}$/.test(ls)
      ? ls
      : ls.replace(' ', 'T') + 'Z';
    const lastSeenDate = new Date(isoLike);
    const now = new Date();
    // Match server-side window (/devices). abs() guards against any TZ skew.
    if (!isNaN(lastSeenDate.getTime()) &&
        Math.abs(now.getTime() - lastSeenDate.getTime()) < 90 * 1000) {
      isOnline = true;
    }
  }

  return (
    <div style={{ animation: 'fadeIn 0.3s ease' }}>
      <div style={{ marginBottom: '24px' }}>
        <Link to="/agents" style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '16px' }}>
          <ChevronLeft size={16} /> Back to Agents
        </Link>
        <div className="flex-responsive" style={{ justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '8px' }}>
              <h2 style={{ fontSize: '2rem', fontWeight: 700 }}>{agentName}</h2>
              <div style={{ 
                padding: '4px 12px', 
                borderRadius: '20px', 
                backgroundColor: isOnline ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)', 
                color: isOnline ? 'var(--accent-success)' : 'var(--accent-color)', 
                fontSize: '0.75rem', 
                fontWeight: 700, 
                textTransform: 'uppercase' 
              }}>
                {isOnline ? 'Online' : 'Offline'}
              </div>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
              {agentInfo.os_info || 'Generic Linux'} | {agentInfo.public_ip || 'No IP'} | Last seen: {agentInfo.last_seen || 'Just now'}
            </p>
          </div>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            <button onClick={handleReloadLicense} title="Reload License" style={{ padding: '10px', borderRadius: '8px', border: '1px solid var(--border-color)', color: 'var(--accent-success)' }}><ShieldCheck size={18} /></button>
            <button onClick={handleRestart} title="Restart Agent" style={{ padding: '10px', borderRadius: '8px', border: '1px solid var(--border-color)', color: 'var(--accent-warning)' }}><RotateCcw size={18} /></button>
            <button onClick={handleSelfDestruct} title="Self Destruct" style={{ padding: '10px', borderRadius: '8px', border: '1px solid var(--border-color)', color: 'var(--accent-color)' }}><Bomb size={18} /></button>
            <button onClick={() => fetchAgentData(true)} style={{ padding: '10px 16px', borderRadius: '8px', border: '1px solid var(--border-color)', color: 'white', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.875rem' }}>
              <RefreshCw size={16} /> Refresh
            </button>
            <button 
              onClick={async () => {
                if (window.confirm("Isolate host? This will block all incoming/outgoing traffic except to the management server.")) {
                   try {
                     await agentService.executeSoarAction(agentName!, { action: "block_ip", target: "0.0.0.0", comment: "Manual Isolation" });
                     alert("Isolation command sent.");
                   } catch (err) { alert("Failed to send isolation command."); }
                }
              }}
              style={{ padding: '10px 20px', borderRadius: '8px', backgroundColor: 'var(--accent-color)', color: 'white', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.875rem' }}>
              <Zap size={18} /> Isolate
            </button>
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div style={{ 
        display: 'flex', 
        gap: '4px', 
        borderBottom: '1px solid var(--border-color)', 
        marginBottom: '32px',
        overflowX: 'auto',
        paddingBottom: '1px'
      }}>
        {tabs.map(tab => (
          <button 
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              padding: '12px 20px',
              fontSize: '0.875rem',
              fontWeight: 600,
              color: activeTab === tab.id ? 'var(--accent-secondary)' : 'var(--text-secondary)',
              borderBottom: activeTab === tab.id ? '2px solid var(--accent-secondary)' : '2px solid transparent',
              transition: 'all 0.2s ease',
              whiteSpace: 'nowrap',
              backgroundColor: activeTab === tab.id ? 'rgba(59, 130, 246, 0.05)' : 'transparent'
            }}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content Area */}
      <div className="table-responsive">
        {activeTab === 'overview' && <OverviewTab data={data} />}
        {activeTab === 'siem' && (
          <TableTab
            title="SIEM Events"
            columns={['Timestamp', 'Severity', 'Event Type', 'Source', 'Message']}
            columnConfig={[
              { minWidth: '170px', nowrap: true },
              { minWidth: '100px', nowrap: true, align: 'center' },
              { minWidth: '180px' },
              { minWidth: '260px' },
              { minWidth: '320px' },
            ]}
            data={data.siem.map((r: any) => {
              const p = parseSiemRow(r);
              return [p.timestamp, p.severity, p.event_type, p.source, p.message];
            })}
          />
        )}
        {activeTab === 'alerts' && (
          <AlertsTab rows={data.alerts.map((r: any) => parseSiemRow(r))} />
        )}
        {activeTab === 'vulnerabilities' && <VulnsTab agentName={agentName!} data={data.vulnerabilities} onRefresh={() => fetchAgentData(false)} />}
        {activeTab === 'packages' && (
          <TableTab
            title="Installed Packages"
            columns={['Package Name', 'Version']}
            columnConfig={[
              { minWidth: '320px' },
              { minWidth: '160px' },
            ]}
            data={data.packages.map((r: any) => [r.package, r.version])}
          />
        )}
        {activeTab === 'portscan' && (
          <TableTab
            title="Open Ports & Services"
            columns={['Port', 'Protocol', 'Service', 'State']}
            columnConfig={[
              { minWidth: '90px', nowrap: true, align: 'center' },
              { minWidth: '110px', nowrap: true, align: 'center' },
              { minWidth: '200px' },
              { minWidth: '120px', nowrap: true, align: 'center' },
            ]}
            data={data.portscans.map((r: any) => [r.port, r.protocol, r.service, r.state])}
          />
        )}
        {activeTab === 'files' && (
          <TableTab
            title="Critical File Monitor"
            columns={['Path', 'Owner', 'Group', 'Permissions', 'Last Opened']}
            columnConfig={[
              { minWidth: '320px' },
              { minWidth: '140px' },
              { minWidth: '140px' },
              { minWidth: '140px', align: 'center' },
              { minWidth: '180px', nowrap: true },
            ]}
            data={data.criticalFiles.map((r: any) => [r.path, r.owner, r.grp, r.permissions, r.last_opened])}
          />
        )}
        {activeTab === 'vnc' && (
          <div style={{ backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', overflow: 'hidden', height: '700px' }}>
            {agentName && <VncViewer agentName={agentName} />}
          </div>
        )}
        {activeTab === 'config' && (
          <div style={{ backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: window.innerWidth > 768 ? '32px' : '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
              <div style={{ display: 'flex', gap: '8px', overflowX: 'auto' }}>
                <ConfigTypeButton label="Rules" active={configType === 'rules'} onClick={() => setConfigType('rules')} />
                <ConfigTypeButton label="Paths" active={configType === 'log_paths'} onClick={() => setConfigType('log_paths')} />
                <ConfigTypeButton label="Scan" active={configType === 'file_scan'} onClick={() => setConfigType('file_scan')} />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                {configChecking && (
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Checking…</span>
                )}
                {!configChecking && configContent.trim() && (
                  <ConfigVerdict issues={configIssues} />
                )}
                <button
                  onClick={handleSaveConfig}
                  disabled={configLoading || configIssues.some(i => i.severity === 'error')}
                  title={
                    configIssues.some(i => i.severity === 'error')
                      ? 'Fix the errors below first — a broken config stops the sensor detecting anything'
                      : 'Push this config to the agent'
                  }
                  style={{
                    backgroundColor: configIssues.some(i => i.severity === 'error')
                      ? 'var(--border-color)' : 'var(--accent-secondary)',
                    color: 'white', padding: '10px 20px', borderRadius: '8px', fontWeight: 700,
                    display: 'flex', alignItems: 'center', gap: '8px',
                    opacity: configLoading ? 0.5 : 1,
                    cursor: configIssues.some(i => i.severity === 'error') ? 'not-allowed' : 'pointer',
                  }}
                >
                  {configLoading ? <RefreshCw size={18} className="animate-spin" /> : <Save size={18} />}
                  Save
                </button>
              </div>
            </div>

            {configStatus && (
              <div style={{
                marginBottom: '16px', padding: '12px 14px', borderRadius: '8px', fontSize: '0.8125rem',
                backgroundColor: configStatus.ok ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
                border: `1px solid ${configStatus.ok ? 'rgba(16,185,129,0.25)' : 'rgba(239,68,68,0.25)'}`,
                color: configStatus.ok ? 'var(--accent-success)' : '#fca5a5',
              }}>
                {configStatus.message}
              </div>
            )}

            <ConfigIssueList
              issues={configIssues}
              onJump={(line) => {
                // Put the caret on the offending line so the operator lands on
                // it instead of counting rows in a 2000-line rules file.
                const ta = configTextareaRef.current;
                if (!ta) return;
                const offset = configContent.split('\n').slice(0, line - 1).join('\n').length;
                ta.focus();
                ta.setSelectionRange(offset, offset);
                const lineHeight = 22;
                ta.scrollTop = Math.max(0, (line - 4) * lineHeight);
              }}
            />

            <div style={{ position: 'relative' }}>
              <textarea
                ref={configTextareaRef}
                value={configContent}
                onChange={e => setConfigContent(e.target.value)}
                spellCheck={false}
                style={{
                  width: '100%',
                  height: '600px',
                  backgroundColor: 'var(--bg-color)',
                  border: `1px solid ${configIssues.some(i => i.severity === 'error') ? 'rgba(239,68,68,0.4)' : 'var(--border-color)'}`,
                  borderRadius: 'var(--radius-md)',
                  padding: '24px',
                  color: 'white',
                  fontFamily: 'monospace',
                  fontSize: '0.875rem',
                  lineHeight: '1.6',
                  outline: 'none',
                  resize: 'none'
                }}
              />
            </div>
          </div>
        )}
        {activeTab === 'docker' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
            <TableTab
              title="Docker Container Inventory"
              columns={['Container ID', 'Name', 'Image', 'Status', 'State', 'Created At']}
              columnConfig={[
                { minWidth: '130px', nowrap: true },
                { minWidth: '160px' },
                { minWidth: '220px' },
                { minWidth: '120px', align: 'center' },
                { minWidth: '100px', nowrap: true, align: 'center' },
                { minWidth: '170px', nowrap: true },
              ]}
              data={data.containers.map((c: any) => [
                c.container_id?.substring(0, 12),
                c.name,
                c.image,
                c.status,
                c.state,
                c.created_at
              ])}
            />
            <TableTab
              title="Docker Events (Activity Logs)"
              columns={['Timestamp', 'Event', 'Details']}
              columnConfig={[
                { minWidth: '170px', nowrap: true },
                { minWidth: '140px' },
                { minWidth: '320px' },
              ]}
              data={data.siem
                .filter((e: any) => e.source === 'DockerMonitor' || e.message?.includes('docker event:'))
                .map((e: any) => [
                  e.timestamp,
                  e.message?.split('docker event: ')[1]?.split(' ')[0] || 'event',
                  e.message
                ])}
            />
          </div>
        )}
        {activeTab === 'ai' && <AIAnalysisTab insights={data.aiInsights || []} agentName={agentName!} />}
        {activeTab === 'soar' && <SoarTab data={data} agentName={agentName!} onRefresh={fetchAgentData} />}
        {activeTab === 'system' && <SystemTab data={data} />}
      </div>
    </div>
  );
};

const ConfigTypeButton: React.FC<{ label: string, active: boolean, onClick: () => void }> = ({ label, active, onClick }) => (
  <button 
    onClick={onClick}
    style={{
      padding: '8px 16px',
      borderRadius: '6px',
      fontSize: '0.8125rem',
      fontWeight: 600,
      backgroundColor: active ? 'rgba(59, 130, 246, 0.1)' : 'transparent',
      color: active ? 'var(--accent-secondary)' : 'var(--text-secondary)',
      border: active ? '1px solid rgba(59, 130, 246, 0.2)' : '1px solid transparent',
      transition: 'all 0.2s ease',
      whiteSpace: 'nowrap'
    }}
  >
    {label}
  </button>
);

const OverviewTab: React.FC<{ data: any }> = ({ data }) => {
  const latestResources = data.resources[0] || {};
  const latestDisk = data.disks[0] || {};

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '32px' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '24px' }}>
          <ResourceMiniCard label="CPU" value={latestResources.cpu_percent || 0} color="var(--accent-secondary)" icon={<Cpu size={16} />} />
          <ResourceMiniCard label="RAM" value={latestResources.mem_percent || 0} color="var(--accent-warning)" icon={<HardDrive size={16} />} />
          <ResourceMiniCard label="Disk" value={latestDisk.percent || 0} color="var(--accent-success)" icon={<LayoutGrid size={16} />} />
        </div>

        <div className="card">
          <h3 style={{ fontSize: '1.125rem', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Activity size={20} color="var(--accent-secondary)" /> Latest SIEM Logs
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {data.siem.slice(0, 8).map((event: any, i: number) => {
              const p = parseSiemRow(event);
              return (
                <div key={i} style={{ display: 'flex', gap: '16px', padding: '16px', borderRadius: 'var(--radius-md)', backgroundColor: 'rgba(255,255,255,0.015)', border: '1px solid var(--border-color)', borderLeft: '3px solid var(--accent-secondary)', flexWrap: 'wrap', transition: 'all 0.2s ease' }}
                  onMouseOver={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.03)'}
                  onMouseOut={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.015)'}
                >
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', width: '140px', flexShrink: 0 }}>{p.timestamp || event.timestamp}</div>
                  <div style={{ fontSize: '0.875rem' }}>
                    <span style={{ fontWeight: 700, color: 'var(--accent-secondary)', marginRight: '8px' }}>[{p.source || 'LOG'}]</span>
                    {p.message}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
        <div className="card">
          <h3 style={{ fontSize: '1.125rem', marginBottom: '20px' }}>Agent Metadata</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <DetailItem label="Operating System" value={data.info[0]?.os_info || 'Generic Linux'} />
            <DetailItem label="Hostname" value={data.info[0]?.hostname || data.info[0]?.agent_name || '-'} />
            <DetailItem label="Local IP Address" value={data.info[0]?.public_ip || '-'} />
            <DetailItem label="MAC Identifier" value={data.info[0]?.mac_address || '-'} />
          </div>
        </div>

        <div className="card">
          <h3 style={{ fontSize: '1.125rem', marginBottom: '20px' }}>Threat Summary</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <SummaryStat label="Critical Alerts" value={data.alerts.filter((a:any)=>parseSiemRow(a).severity==='CRITICAL').length} color="var(--accent-color)" />
            <SummaryStat label="Vulnerabilities" value={data.vulnerabilities.length} color="var(--accent-warning)" />
            <SummaryStat label="Open Ports" value={data.portscans.length} color="var(--accent-secondary)" />
          </div>
        </div>
      </div>
    </div>
  );
};

const ResourceMiniCard: React.FC<{ label: string, value: number, color: string, icon: React.ReactNode }> = ({ label, value, color, icon }) => (
  <div className="card" style={{ padding: '20px' }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>{label}</span>
      <div style={{ color }}>{icon}</div>
    </div>
    <div style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '8px' }}>{value}%</div>
    <div style={{ height: '4px', backgroundColor: 'var(--bg-color)', borderRadius: '2px', overflow: 'hidden' }}>
      <div style={{ width: `${value}%`, height: '100%', backgroundColor: color, transition: 'width 1s ease' }} />
    </div>
  </div>
);

const DetailItem: React.FC<{ label: string, value: string }> = ({ label, value }) => (
  <div style={{ borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '12px' }}>
    <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>{label}</p>
    <p style={{ fontSize: '0.875rem', fontWeight: 600 }}>{value}</p>
  </div>
);

const SummaryStat: React.FC<{ label: string, value: number, color: string }> = ({ label, value, color }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px', borderRadius: '8px', backgroundColor: 'rgba(255,255,255,0.02)' }}>
    <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>{label}</span>
    <span style={{ fontSize: '1.125rem', fontWeight: 700, color }}>{value}</span>
  </div>
);

const VulnsTab: React.FC<{ agentName: string, data: any[], onRefresh: () => void }> = ({ agentName, data, onRefresh }) => {
  const [scanning, setScanning] = useState(false);
  const [lastScan, setLastScan] = useState<{ packages: number, hits: number, inserted: number, ecosystem?: string, skipped_reason?: string } | null>(null);

  const handleScan = async () => {
    setScanning(true);
    try {
      const stat = await agentService.scanVulns(agentName);
      setLastScan({
        packages: stat.packages || 0,
        hits: stat.hits || 0,
        inserted: stat.inserted || 0,
        ecosystem: stat.ecosystem,
        skipped_reason: stat.skipped_reason,
      });
      await onRefresh();
    } catch (err: any) {
      console.error('Vuln scan failed:', err);
      setLastScan({ packages: 0, hits: 0, inserted: 0, skipped_reason: err?.response?.data?.error || 'scan_failed' });
    } finally {
      setScanning(false);
    }
  };

  const rows = data.map((r: any) => [r.package_name, r.package_version, r.vulnerability_id, r.summary]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div className="card" style={{ padding: '16px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontSize: '0.95rem', fontWeight: 700 }}>Server-Side Vulnerability Scan</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Reads installed packages from this agent and queries OSV. Runs automatically; click to trigger now.
          </div>
          {lastScan && (
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '8px' }}>
              Last scan: {lastScan.packages} packages
              {lastScan.ecosystem && ` · ${lastScan.ecosystem}`}
              {' · '}{lastScan.hits} OSV hits · {lastScan.inserted} new
              {lastScan.skipped_reason && ` · skipped: ${lastScan.skipped_reason}`}
            </div>
          )}
        </div>
        <button
          onClick={handleScan}
          disabled={scanning}
          style={{
            padding: '10px 20px',
            borderRadius: '10px',
            backgroundColor: scanning ? 'rgba(96,165,250,0.15)' : 'var(--accent-secondary)',
            color: 'white',
            border: 'none',
            cursor: scanning ? 'wait' : 'pointer',
            fontSize: '0.875rem',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <RefreshCw size={16} className={scanning ? 'animate-spin' : ''} />
          {scanning ? 'Scanning…' : 'Scan Now'}
        </button>
      </div>
      <TableTab
        title={`Vulnerabilities Report (${rows.length})`}
        columns={['Package', 'Version', 'CVE ID', 'Summary']}
        data={rows}
      />
    </div>
  );
};

type TableColConfig = {
  width?: string;
  minWidth?: string;
  nowrap?: boolean;
  align?: 'left' | 'center' | 'right';
};

const TableTab: React.FC<{
  title: string;
  columns: string[];
  data: any[];
  columnConfig?: TableColConfig[];
}> = ({ title, columns, data, columnConfig }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [searchMode, setSearchMode] = useState('fuzzy');
  const [visibleCount, setVisibleCount] = useState(50);

  const filteredData = React.useMemo(() => {
    if (!searchTerm) return data;
    
    // Convert array of arrays to array of objects for better fuse.js parsing or just map them into strings
    const searchItems = data.map((row) => ({
      original: row,
      text: row.join(' ')
    }));

    const fuse = new Fuse(searchItems, {
      keys: ['text'],
      threshold: 0.2, // Tighter threshold for better precision
      ignoreLocation: true,
      useExtendedSearch: true // Enable advanced search syntax (=exact, !exclude, ^prefix)
    });

    let query = searchTerm;
    if (searchMode === 'exact') query = `="${searchTerm}"`;
    else if (searchMode === 'exclude') query = `!${searchTerm}`;
    else if (searchMode === 'prefix') query = `^${searchTerm}`;

    return fuse.search(query).map(r => r.item.original);
  }, [data, searchTerm, searchMode]);

  const visibleData = filteredData.slice(0, visibleCount);

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const { scrollTop, scrollHeight, clientHeight } = e.currentTarget;
    if (scrollHeight - scrollTop - clientHeight < 50) {
      if (visibleCount < filteredData.length) {
        setVisibleCount(v => v + 50);
      }
    }
  };

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{ padding: '20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <h3 style={{ fontSize: '1.125rem' }}>{title} ({filteredData.length})</h3>
        </div>
        <div style={{ position: 'relative', display: 'flex', gap: '8px', alignItems: 'center' }}>
          <select
            value={searchMode}
            onChange={(e) => setSearchMode(e.target.value)}
            style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '6px 12px', fontSize: '0.75rem', color: 'white', cursor: 'pointer', outline: 'none' }}
          >
            <option value="fuzzy">Fuzzy</option>
            <option value="exact">Exact Match</option>
            <option value="exclude">Exclude</option>
            <option value="prefix">Starts With</option>
          </select>
          <div style={{ position: 'relative' }}>
            <FileSearch size={16} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
            <input 
              type="text" 
              placeholder="Search data..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '6px 12px 6px 32px', fontSize: '0.75rem', color: 'white', width: '250px' }} 
            />
          </div>
        </div>
      </div>
      <div className="table-container" onScroll={handleScroll} style={{ maxHeight: '600px', overflowY: 'auto', overflowX: 'auto' }}>
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            textAlign: 'left',
            fontSize: '0.875rem',
            tableLayout: 'auto',
          }}
        >
          <thead style={{ position: 'sticky', top: 0, backgroundColor: 'var(--sidebar-bg)', zIndex: 10 }}>
            <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
              {columns.map((col, i) => {
                const cfg = columnConfig?.[i];
                return (
                  <th
                    key={col}
                    style={{
                      padding: '14px 20px',
                      fontWeight: 700,
                      color: 'var(--text-secondary)',
                      textTransform: 'uppercase',
                      fontSize: '0.75rem',
                      whiteSpace: 'nowrap',
                      textAlign: cfg?.align || 'left',
                      minWidth: cfg?.minWidth,
                    }}
                  >
                    {col}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {visibleData.map((row, i) => (
              <tr key={i} style={{ borderBottom: '1px solid var(--border-color)', transition: 'background-color 0.2s ease' }} onMouseOver={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.01)'} onMouseOut={e => e.currentTarget.style.backgroundColor = 'transparent'}>
                {row.map((cell: any, j: number) => {
                  const cfg = columnConfig?.[j];
                  const nowrap = !!cfg?.nowrap;
                  const text = cell == null ? '' : cell.toString();
                  const isCritical = text.includes('CRITICAL');
                  return (
                    <td
                      key={j}
                      style={{
                        padding: '14px 20px',
                        wordBreak: 'break-word',
                        overflowWrap: 'anywhere',
                        whiteSpace: nowrap ? 'nowrap' : 'normal',
                        textAlign: cfg?.align || 'left',
                        verticalAlign: 'top',
                        minWidth: cfg?.minWidth,
                      }}
                    >
                      {isCritical ? <span style={{ color: 'var(--accent-color)', fontWeight: 700 }}>{cell}</span> : cell}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

type AlertRow = {
  timestamp: string;
  severity: string;
  event_type: string;
  source: string;
  message: string;
};

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, '': 0
};

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'var(--accent-color)',
  HIGH: '#f97316',
  MEDIUM: 'var(--accent-warning)',
  LOW: 'var(--accent-secondary)',
  INFO: 'var(--text-secondary)'
};

const AlertsTab: React.FC<{ rows: AlertRow[] }> = ({ rows }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [eventTypeFilter, setEventTypeFilter] = useState('ALL');
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [timeWindow, setTimeWindow] = useState('ALL');
  const [sortBy, setSortBy] = useState<'time' | 'severity'>('time');
  const [visibleCount, setVisibleCount] = useState(50);

  const eventTypes = React.useMemo(() => {
    const set = new Set<string>();
    rows.forEach(r => { if (r.event_type) set.add(r.event_type); });
    // localeCompare, not the default sort: the default orders by UTF-16 code
    // unit, which puts Turkish characters (ş, ç, ğ, İ) after Z in a filter
    // dropdown an operator is scanning by eye.
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [rows]);

  const sources = React.useMemo(() => {
    const set = new Set<string>();
    rows.forEach(r => { if (r.source) set.add(r.source); });
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [rows]);

  const severityCounts = React.useMemo(() => {
    const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    rows.forEach(r => { if (counts[r.severity] !== undefined) counts[r.severity]++; });
    return counts;
  }, [rows]);

  const parseTs = (ts: string): number => {
    if (!ts) return 0;
    const s = String(ts).trim();
    const isoLike = /[zZ]|[+-]\d{2}:?\d{2}$/.test(s) ? s : s.replace(' ', 'T') + 'Z';
    const d = new Date(isoLike);
    return isNaN(d.getTime()) ? 0 : d.getTime();
  };

  const filtered = React.useMemo(() => {
    const now = Date.now();
    const windowMs: Record<string, number> = {
      ALL: 0,
      '1h': 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000
    };
    const cutoff = windowMs[timeWindow] || 0;
    const term = searchTerm.toLowerCase().trim();

    let out = rows.filter(r => {
      if (severityFilter !== 'ALL' && r.severity !== severityFilter) return false;
      if (eventTypeFilter !== 'ALL' && r.event_type !== eventTypeFilter) return false;
      if (sourceFilter !== 'ALL' && r.source !== sourceFilter) return false;
      if (cutoff > 0) {
        const t = parseTs(r.timestamp);
        if (!t || (now - t) > cutoff) return false;
      }
      if (term) {
        const blob = `${r.timestamp} ${r.severity} ${r.event_type} ${r.source} ${r.message}`.toLowerCase();
        if (!blob.includes(term)) return false;
      }
      return true;
    });

    if (sortBy === 'severity') {
      out = [...out].sort((a, b) =>
        (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
        || parseTs(b.timestamp) - parseTs(a.timestamp)
      );
    } else {
      out = [...out].sort((a, b) => parseTs(b.timestamp) - parseTs(a.timestamp));
    }
    return out;
  }, [rows, severityFilter, eventTypeFilter, sourceFilter, timeWindow, searchTerm, sortBy]);

  const visible = filtered.slice(0, visibleCount);

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const { scrollTop, scrollHeight, clientHeight } = e.currentTarget;
    if (scrollHeight - scrollTop - clientHeight < 50 && visibleCount < filtered.length) {
      setVisibleCount(v => v + 50);
    }
  };

  const resetFilters = () => {
    setSearchTerm(''); setSeverityFilter('ALL'); setEventTypeFilter('ALL');
    setSourceFilter('ALL'); setTimeWindow('ALL'); setSortBy('time');
  };

  const selectStyle: React.CSSProperties = {
    backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)',
    borderRadius: '6px', padding: '8px 12px', fontSize: '0.8125rem',
    color: 'white', cursor: 'pointer', outline: 'none', minWidth: '130px'
  };

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{ padding: '20px', borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <h3 style={{ fontSize: '1.125rem' }}>Security Alerts ({filtered.length}/{rows.length})</h3>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {(['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as const).map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? 'ALL' : sev)}
                style={{
                  padding: '4px 10px', borderRadius: '12px', fontSize: '0.7rem', fontWeight: 700,
                  border: `1px solid ${SEVERITY_COLOR[sev]}`,
                  backgroundColor: severityFilter === sev ? SEVERITY_COLOR[sev] : 'transparent',
                  color: severityFilter === sev ? 'white' : SEVERITY_COLOR[sev],
                  cursor: 'pointer'
                }}
              >
                {sev} {severityCounts[sev] || 0}
              </button>
            ))}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} style={selectStyle}>
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
          <select value={eventTypeFilter} onChange={e => setEventTypeFilter(e.target.value)} style={selectStyle}>
            <option value="ALL">All Event Types</option>
            {eventTypes.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select value={sourceFilter} onChange={e => setSourceFilter(e.target.value)} style={selectStyle}>
            <option value="ALL">All Sources</option>
            {sources.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={timeWindow} onChange={e => setTimeWindow(e.target.value)} style={selectStyle}>
            <option value="ALL">Any Time</option>
            <option value="1h">Last 1h</option>
            <option value="24h">Last 24h</option>
            <option value="7d">Last 7d</option>
          </select>
          <select value={sortBy} onChange={e => setSortBy(e.target.value as 'time' | 'severity')} style={selectStyle}>
            <option value="time">Newest First</option>
            <option value="severity">By Severity</option>
          </select>
          <div style={{ position: 'relative', flex: 1, minWidth: '200px' }}>
            <FileSearch size={16} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
            <input
              type="text"
              placeholder="Search message, source..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              style={{ width: '100%', backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '8px 12px 8px 32px', fontSize: '0.8125rem', color: 'white' }}
            />
          </div>
          <button onClick={resetFilters} style={{ padding: '8px 14px', borderRadius: '6px', border: '1px solid var(--border-color)', fontSize: '0.75rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            Reset
          </button>
        </div>
      </div>

      <div className="table-container" onScroll={handleScroll} style={{ maxHeight: '600px', overflowY: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
          <thead style={{ position: 'sticky', top: 0, backgroundColor: 'var(--sidebar-bg)', zIndex: 10 }}>
            <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
              {['Timestamp', 'Severity', 'Event Type', 'Source', 'Message'].map(c => (
                <th key={c} style={{ padding: '14px 20px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '0.75rem' }}>{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>No alerts match the current filters.</td></tr>
            ) : visible.map((r, i) => (
              <tr key={i} style={{ borderBottom: '1px solid var(--border-color)' }}>
                <td style={{ padding: '14px 20px', whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>{r.timestamp}</td>
                <td style={{ padding: '14px 20px' }}>
                  <span style={{
                    padding: '3px 10px', borderRadius: '10px', fontSize: '0.7rem', fontWeight: 700,
                    backgroundColor: `${SEVERITY_COLOR[r.severity] || 'var(--text-secondary)'}1f`,
                    color: SEVERITY_COLOR[r.severity] || 'var(--text-secondary)'
                  }}>
                    {r.severity || 'N/A'}
                  </span>
                </td>
                <td style={{ padding: '14px 20px' }}>{r.event_type}</td>
                <td style={{ padding: '14px 20px', fontFamily: 'monospace', fontSize: '0.8125rem' }}>{r.source}</td>
                <td style={{ padding: '14px 20px', wordBreak: 'break-word', whiteSpace: 'pre-wrap' }}>{r.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export type ConfigIssue = { line: number | null; message: string; severity: 'error' | 'warning' };

const ConfigVerdict: React.FC<{ issues: ConfigIssue[] }> = ({ issues }) => {
  const errs = issues.filter(i => i.severity === 'error').length;
  const warns = issues.length - errs;
  const [color, bg, label] =
    errs > 0 ? ['#ef4444', 'rgba(239,68,68,0.10)', `${errs} error${errs > 1 ? 's' : ''}`]
      : warns > 0 ? ['#f59e0b', 'rgba(245,158,11,0.10)', `${warns} warning${warns > 1 ? 's' : ''}`]
        : ['#10b981', 'rgba(16,185,129,0.10)', 'Valid'];

  return (
    <span style={{
      padding: '4px 10px', borderRadius: '6px', fontSize: '0.7rem', fontWeight: 700,
      color, backgroundColor: bg, border: `1px solid ${color}33`,
      textTransform: 'uppercase', letterSpacing: '0.04em', whiteSpace: 'nowrap',
    }}>
      {label}
    </span>
  );
};

const ConfigIssueList: React.FC<{ issues: ConfigIssue[]; onJump: (line: number) => void }> = ({ issues, onJump }) => {
  if (!issues.length) return null;
  // Errors first: they are what blocks the save.
  const ordered = [...issues].sort((a, b) =>
    (a.severity === b.severity ? (a.line ?? 0) - (b.line ?? 0) : a.severity === 'error' ? -1 : 1));

  return (
    <div style={{
      marginBottom: '16px', border: '1px solid var(--border-color)', borderRadius: '8px',
      overflow: 'hidden', maxHeight: '200px', overflowY: 'auto',
    }} className="custom-scrollbar">
      {ordered.map((issue, i) => {
        const isError = issue.severity === 'error';
        return (
          <div
            key={i}
            onClick={() => issue.line && onJump(issue.line)}
            style={{
              display: 'flex', alignItems: 'flex-start', gap: '10px',
              padding: '8px 12px', fontSize: '0.8125rem',
              borderTop: i === 0 ? 'none' : '1px solid var(--border-color)',
              backgroundColor: isError ? 'rgba(239,68,68,0.05)' : 'rgba(245,158,11,0.04)',
              cursor: issue.line ? 'pointer' : 'default',
            }}
            title={issue.line ? 'Jump to this line' : undefined}
          >
            <span style={{
              fontFamily: 'monospace', fontSize: '0.75rem', fontWeight: 700, minWidth: '52px',
              color: isError ? '#ef4444' : '#f59e0b',
            }}>
              {issue.line ? `L${issue.line}` : '—'}
            </span>
            <span style={{ color: 'var(--text-primary)', lineHeight: 1.5 }}>{issue.message}</span>
          </div>
        );
      })}
    </div>
  );
};

// Robust extraction for critical_summary lines. Worker emits two shapes:
//   A) "[PREFIX] {json}"          → JSON sometimes malformed by the LLM
//   B) "[PREFIX] [SEV] conf=X.XX (indicator) summary -> ACTION  techniques=... | iocs=... | next=..."
// We regex each known field independently so a missing closing bracket in (A)
// doesn't drop the rest of the data.
type ParsedInsight = {
  tag: string;
  verdict: string;
  severity: string;
  confidence: number | null;
  indicator: string;
  summary: string;
  action: string;
  target: string;
  techniques: string[];
  iocs: string[];
  next_steps: string[];
  reason: string;
  auto_dispatched: boolean;
  intel_match: string;
  isJsonForm: boolean;
};

function parseInsight(raw: string): ParsedInsight {
  const r: ParsedInsight = {
    tag: '', verdict: '', severity: '', confidence: null, indicator: '',
    summary: '', action: '', target: '', techniques: [], iocs: [],
    next_steps: [], reason: '', auto_dispatched: false, intel_match: '',
    isJsonForm: false,
  };
  if (!raw) return r;

  let body = raw;
  const tagMatch = body.match(/^\[([^\]]+)\]\s*/);
  if (tagMatch) { r.tag = tagMatch[1]; body = body.slice(tagMatch[0].length); }

  if (raw.includes('AUTO-DISPATCHED')) r.auto_dispatched = true;
  const intelIdx = body.indexOf('GLOBAL THREAT INTEL MATCH:');
  if (intelIdx >= 0) {
    r.intel_match = body.slice(intelIdx + 'GLOBAL THREAT INTEL MATCH:'.length).split('\n')[0].trim();
    body = body.slice(0, intelIdx).replace(/\[!!\]\s*$/, '').trim();
  }

  // Form A — JSON
  if (body.trim().startsWith('{')) {
    r.isJsonForm = true;
    const getStr = (k: string) => {
      const m = body.match(new RegExp(`"${k}"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"`, 'i'));
      return m ? m[1].replace(/\\"/g, '"') : '';
    };
    const getNum = (k: string) => {
      const m = body.match(new RegExp(`"${k}"\\s*:\\s*([0-9]*\\.?[0-9]+)`));
      return m ? parseFloat(m[1]) : null;
    };
    const getArr = (k: string) => {
      const m = body.match(new RegExp(`"${k}"\\s*:\\s*\\[([^\\]]*)\\]?`));
      if (!m) return [];
      return m[1]
        .split(/\s*,\s*/)
        .map(x => x.trim().replace(/^"|"$/g, '').replace(/\\"/g, '"'))
        .filter(Boolean);
    };
    r.verdict = getStr('verdict');
    r.severity = getStr('severity');
    r.confidence = getNum('confidence');
    r.indicator = getStr('indicator') || getStr('kill_chain_stage');
    r.summary = getStr('summary');
    r.action = getStr('recommended_action') || getStr('action');
    r.target = getStr('target');
    r.reason = getStr('reason');
    r.techniques = getArr('techniques');
    r.iocs = getArr('iocs');
    r.next_steps = getArr('next_steps');
    return r;
  }

  // Form B — pre-formatted
  const sevMatch = body.match(/^\[([A-Z]+)\]\s*/);
  if (sevMatch) { r.severity = sevMatch[1]; body = body.slice(sevMatch[0].length); }

  const confMatch = body.match(/conf=([0-9.]+)\s*/);
  if (confMatch) { r.confidence = parseFloat(confMatch[1]); body = body.replace(confMatch[0], ''); }

  const indMatch = body.match(/^\(([^)]+)\)\s*/);
  if (indMatch) { r.indicator = indMatch[1]; body = body.slice(indMatch[0].length); }

  const actMatch = body.match(/->\s*([A-Z_]+)/);
  if (actMatch) { r.action = actMatch[1]; body = body.replace(actMatch[0], ''); }

  const targetMatch = body.match(/target=(\S+)/);
  if (targetMatch) { r.target = targetMatch[1]; body = body.replace(targetMatch[0], ''); }

  const techMatch = body.match(/techniques=([^|\n]+)/);
  if (techMatch) {
    r.techniques = techMatch[1].split(',').map(s => s.trim()).filter(Boolean);
    body = body.replace(techMatch[0], '');
  }
  const iocMatch = body.match(/iocs=([^|\n]+)/);
  if (iocMatch) {
    r.iocs = iocMatch[1].split(',').map(s => s.trim()).filter(Boolean);
    body = body.replace(iocMatch[0], '');
  }
  const nextMatch = body.match(/next=([^\n]+)/);
  if (nextMatch) {
    r.next_steps = nextMatch[1].split('|').map(s => s.trim()).filter(Boolean);
    body = body.replace(nextMatch[0], '');
  }

  // AUTO-DISPATCHED marker emitted by defensive worker on auto-action
  body = body.replace(/\|\s*AUTO-DISPATCHED\s+\S+/, '').replace(/\|\s*AUTO-DISPATCH FAILED/, '');

  // Worker appends "\nReason: <text>" when the model gave a narrative.
  // Pull it out as the primary summary so the operator actually sees it.
  const reasonLineMatch = body.match(/\n?\s*Reason:\s*([\s\S]+?)\s*$/i);
  if (reasonLineMatch) {
    r.reason = reasonLineMatch[1].trim();
    body = body.replace(reasonLineMatch[0], '');
  }

  let summary = body.replace(/^\s*\|+\s*/, '').replace(/\s*\|\s*$/, '').trim();
  // If the residual summary is just the verdict echo (MONITOR / ACT / ...)
  // and we have a real reason, promote reason to summary.
  const verdictWords = ['MONITOR', 'ACT', 'IGNORE', 'CRITICAL', 'SUSPICIOUS', 'NOT_CRITICAL', 'INSUFFICIENT_DATA'];
  if (r.reason && (!summary || verdictWords.includes(summary.toUpperCase()))) {
    if (summary && !r.verdict) r.verdict = summary;
    summary = r.reason;
  }
  r.summary = summary;
  return r;
}

/** Schema defaults that mean "absent" — they should not become chips. */
const isPlaceholder = (v?: string) =>
  !v || ['none', 'null', 'n/a', ''].includes(v.trim().toLowerCase());

/**
 * Fields for one insight, preferring the real columns over the rendered line.
 *
 * `verdict` / `severity` / `confidence` are columns now, and `payload` holds
 * the whole validated verdict. Reading those is both cheaper and correct:
 * parseInsight is reconstructing fields out of a string that was *derived*
 * from them, so anything the renderer dropped — a MONITOR action, a `none`
 * indicator — was unrecoverable, and a summary containing "conf=" or "-> "
 * could confuse the regexes outright.
 *
 * Rows written before those columns existed have nothing else to read, so
 * they keep the string path. That is why parseInsight stays.
 */
function insightFields(insight: any): ParsedInsight {
  const parsed = parseInsight(insight?.critical_summary || '');
  if (insight?.verdict == null) return parsed;

  let payload: any = {};
  try {
    if (insight.payload) {
      payload = typeof insight.payload === 'string'
        ? JSON.parse(insight.payload)
        : insight.payload;
    }
  } catch {
    payload = {};   // malformed payload falls back to the parsed line below
  }

  const pick = (fromPayload: any, fromString: string) =>
    isPlaceholder(fromPayload) ? fromString : String(fromPayload);

  return {
    ...parsed,
    verdict: insight.verdict || parsed.verdict,
    severity: insight.severity || parsed.severity,
    confidence: insight.confidence != null ? Number(insight.confidence) : parsed.confidence,
    indicator: pick(payload.indicator ?? payload.kill_chain_stage, parsed.indicator),
    summary: pick(payload.summary, '') || pick(payload.reason, parsed.summary),
    reason: pick(payload.reason, parsed.reason),
    action: pick(payload.recommended_action ?? payload.action, parsed.action),
    target: pick(payload.target, parsed.target),
    techniques: payload.techniques?.length ? payload.techniques : parsed.techniques,
    iocs: payload.iocs?.length ? payload.iocs : parsed.iocs,
    next_steps: payload.next_steps?.length ? payload.next_steps : parsed.next_steps,
    // Dispatch state is not in the verdict — the worker decides it after the
    // model has answered — so it still comes from source_file.
    auto_dispatched: insight.source_file === 'AI_DEFENSIVE_AUTO' || parsed.auto_dispatched,
  };
}

const SEVERITY_STYLE: Record<string, { color: string, bg: string }> = {
  CRITICAL: { color: '#ef4444', bg: 'rgba(239,68,68,0.10)' },
  HIGH:     { color: '#f97316', bg: 'rgba(249,115,22,0.10)' },
  MEDIUM:   { color: '#facc15', bg: 'rgba(250,204,21,0.10)' },
  LOW:      { color: '#34d399', bg: 'rgba(52,211,153,0.10)' },
  INFO:     { color: '#60a5fa', bg: 'rgba(96,165,250,0.10)' },
};

// User-friendly label for the AI insight source. source_file comes in raw as
// "Realtime_siem_events", "Manual_events_alert", "AI_DEFENSIVE_AUTO" etc;
// this maps it to a readable label used by both the dropdown and the chip.
const SOURCE_LABELS: Record<string, string> = {
  'Realtime_siem_events': 'Logs (Auto)',
  'Realtime_events_alert': 'Alerts (Auto)',
  'Realtime_soar_actions': 'SOAR History (Auto)',
  'Manual_siem_events': 'Logs (Manual)',
  'Manual_events_alert': 'Alerts (Manual)',
  'Manual_soar_actions': 'SOAR History (Manual)',
  'AI_DEFENSIVE_AUTO': 'AI Auto-Action',
  'AI_DEFENSIVE_ADVICE': 'AI Advisory',
  'SOAR_Recommender': 'AI Advisory',
};
const sourceLabel = (raw?: string): string => {
  if (!raw) return 'Unknown';
  if (SOURCE_LABELS[raw]) return SOURCE_LABELS[raw];
  // Unknown prefix fallback: "Realtime_xxx" → "xxx (Auto)".
  const m = /^(Realtime|Manual)_(.+)$/.exec(raw);
  if (m) return `${m[2].replace(/_/g, ' ')} (${m[1] === 'Realtime' ? 'Auto' : 'Manual'})`;
  return raw.replace(/_/g, ' ');
};

const Chip: React.FC<{ children: React.ReactNode, color?: string, bg?: string, mono?: boolean }> = ({ children, color = 'var(--text-secondary)', bg = 'rgba(255,255,255,0.05)', mono }) => (
  <span style={{
    padding: '3px 10px',
    borderRadius: '6px',
    fontSize: '0.7rem',
    fontWeight: 700,
    color,
    backgroundColor: bg,
    border: `1px solid ${color === 'var(--text-secondary)' ? 'rgba(255,255,255,0.06)' : color + '33'}`,
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    fontFamily: mono ? 'monospace' : 'inherit',
    whiteSpace: 'nowrap',
  }}>
    {children}
  </span>
);

export const InsightCard: React.FC<{ insight: any }> = ({ insight }) => {
  const [showRaw, setShowRaw] = useState(false);
  const [showSource, setShowSource] = useState(false);
  const [sourceText, setSourceText] = useState<string | null>(insight.source_data ?? null);
  const [sourceLoading, setSourceLoading] = useState(false);

  // Older rows still carry source_data inline; newer ones are fetched on
  // demand. Either way the modal gets what it needs.
  const openSource = async () => {
    setShowSource(true);
    if (sourceText != null || !insight.id || !insight.agent) return;
    setSourceLoading(true);
    try {
      const res = await agentService.getInsightSource(insight.agent, insight.id);
      setSourceText(res?.insight?.source_data ?? null);
    } catch {
      setSourceText(null);
    } finally {
      setSourceLoading(false);
    }
  };
  // Columns first, rendered line only as the fallback for pre-column rows.
  const p = insightFields(insight);
  const sevKey = (p.severity || '').toUpperCase();
  const sevStyle = SEVERITY_STYLE[sevKey] || SEVERITY_STYLE.INFO;
  const accent = p.auto_dispatched ? '#ef4444' : sevStyle.color;

  // Pick the card's narrative once, so the Reason block below can tell whether
  // it has already been shown. Suppressing a verdict echo used to `return
  // null`, which left cards rendering nothing but chips whenever the model
  // returned an empty `summary` or a summary that was just "NOT_CRITICAL".
  const VERDICT_WORDS = [
    'ACT', 'MONITOR', 'IGNORE', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW',
    'INFO', 'NOT_CRITICAL', 'SUSPICIOUS', 'INSUFFICIENT_DATA',
  ];
  const isVerdictEcho = (text: string) => {
    const u = (text || '').trim().toUpperCase();
    return !u
      || u === (p.verdict || '').toUpperCase()
      || u === (p.severity || '').toUpperCase()
      || VERDICT_WORDS.includes(u);
  };
  // First candidate carrying actual prose wins.
  const narrative = [p.summary, p.reason, p.indicator]
    .map(v => (v || '').trim())
    .find(v => v && !isVerdictEcho(v)) || '';
  const reasonAlreadyShown = !!narrative && narrative === (p.reason || '').trim();

  return (
    <div className="card" style={{ padding: '20px', borderLeft: `4px solid ${accent}` }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', gap: '12px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          {p.tag && <Chip color="#a78bfa" bg="rgba(167,139,250,0.10)">{p.tag}</Chip>}
          {p.auto_dispatched && <Chip color="#ef4444" bg="rgba(239,68,68,0.15)">Auto-Dispatched</Chip>}
          {insight.source_file && <Chip>{sourceLabel(insight.source_file)}</Chip>}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={openSource}
            title="View the raw log analyzed by AI"
            style={{
              fontSize: '0.7rem',
              fontWeight: 700,
              color: 'var(--accent-secondary)',
              backgroundColor: 'rgba(96,165,250,0.10)',
              border: '1px solid rgba(96,165,250,0.25)',
              borderRadius: '6px',
              padding: '4px 10px',
              cursor: 'pointer',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
            }}
          >
            View Source
          </button>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            {insight.timestamp || insight.created_at || ''}
          </span>
        </div>
      </div>

      {showSource && (
        <SourceLogModal
          // Fetched on open rather than shipped with every row. source_data
          // holds the full raw log, so including it in the feed made the AI
          // list response scale with the size of the events themselves.
          source={sourceText}
          loading={sourceLoading}
          sourceFile={insight.source_file}
          timestamp={insight.timestamp || insight.created_at}
          onClose={() => setShowSource(false)}
        />
      )}

      {/* Verdict row */}
      {(p.severity || p.confidence != null || p.indicator || p.verdict) && (
        <div style={{ display: 'flex', gap: '8px', marginBottom: '14px', flexWrap: 'wrap' }}>
          {p.verdict && p.verdict.toUpperCase() !== p.severity && (
            <Chip color={accent} bg={sevStyle.bg}>{p.verdict}</Chip>
          )}
          {p.severity && <Chip color={sevStyle.color} bg={sevStyle.bg}>{p.severity}</Chip>}
          {p.confidence != null && (
            <Chip color="var(--text-primary)" bg="rgba(255,255,255,0.05)" mono>
              conf {(p.confidence * 100).toFixed(0)}%
            </Chip>
          )}
          {p.indicator && <Chip color="#60a5fa" bg="rgba(96,165,250,0.10)" mono>{p.indicator}</Chip>}
          {p.action && <Chip color="#f97316" bg="rgba(249,115,22,0.10)">{p.action}</Chip>}
        </div>
      )}

      {/* Every card says something. A blank card reads as a rendering bug and
          gets scrolled past; "the model returned no narrative" is a fact about
          the model that an operator should actually see. */}
      {narrative ? (
        <p style={{ fontSize: '0.95rem', lineHeight: 1.6, color: 'var(--text-primary)', margin: 0, marginBottom: '14px' }}>
          {narrative}
        </p>
      ) : (
        <p style={{
          fontSize: '0.875rem', lineHeight: 1.6, color: 'var(--text-secondary)',
          fontStyle: 'italic', margin: 0, marginBottom: '14px',
        }}>
          {(p.verdict || p.summary || '').trim()
            ? `Model returned a ${(p.verdict || p.summary).trim().replace(/_/g, ' ').toLowerCase()} verdict with no written narrative.`
            : 'Model returned no narrative for this event. Use View Source to see the log it was given.'}
        </p>
      )}

      {/* Target */}
      {p.target && p.target !== 'none' && (
        <div style={{ marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Target</span>
          <code style={{ fontSize: '0.8125rem', padding: '4px 10px', borderRadius: '6px', backgroundColor: 'rgba(251,191,36,0.10)', border: '1px solid rgba(251,191,36,0.2)', color: '#fbbf24' }}>
            {p.target}
          </code>
        </div>
      )}

      {/* MITRE techniques */}
      {p.techniques.length > 0 && (
        <InsightSection label="MITRE Techniques">
          {p.techniques.map((t, i) => (
            <Chip key={i} color="#60a5fa" bg="rgba(96,165,250,0.10)" mono>{t}</Chip>
          ))}
        </InsightSection>
      )}

      {/* IOCs */}
      {p.iocs.length > 0 && (
        <InsightSection label="Indicators of Compromise">
          {p.iocs.map((t, i) => (
            <Chip key={i} color="#fbbf24" bg="rgba(251,191,36,0.10)" mono>{t}</Chip>
          ))}
        </InsightSection>
      )}

      {/* Next steps */}
      {p.next_steps.length > 0 && (
        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>Next Steps</div>
          <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '0.875rem', lineHeight: 1.6, color: 'var(--text-primary)' }}>
            {p.next_steps.map((s, i) => <li key={i}>{s}</li>)}
          </ul>
        </div>
      )}

      {/* Reason (defensive only). Skipped when the block above already used it
          as the narrative, which happens whenever `summary` was empty. */}
      {p.reason && !reasonAlreadyShown && (
        <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', fontStyle: 'italic', marginBottom: '12px' }}>
          Reason: {p.reason}
        </div>
      )}

      {/* Threat-intel hit */}
      {p.intel_match && (
        <div style={{ padding: '10px 12px', borderRadius: '8px', backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', fontSize: '0.8125rem', color: '#fca5a5', marginBottom: '12px' }}>
          <strong>Global Threat Intel Match:</strong> {p.intel_match}
        </div>
      )}

      {/* Raw toggle */}
      <button
        onClick={() => setShowRaw(v => !v)}
        style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', backgroundColor: 'transparent', border: 'none', cursor: 'pointer', padding: 0, marginTop: '4px', textDecoration: 'underline', textDecorationColor: 'rgba(255,255,255,0.15)', textUnderlineOffset: '3px' }}
      >
        {showRaw ? 'Hide raw' : 'Show raw'}
      </button>
      {showRaw && (
        <pre style={{ marginTop: '10px', fontSize: '0.75rem', backgroundColor: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px', whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: 'var(--text-secondary)', maxHeight: '240px', overflowY: 'auto' }} className="custom-scrollbar">
          {insight.critical_summary}
        </pre>
      )}
    </div>
  );
};

const SourceLogModal: React.FC<{ source?: string | null, loading?: boolean, sourceFile?: string, timestamp?: string, onClose: () => void }> = ({ source, loading, sourceFile, timestamp, onClose }) => {
  // Lock body scroll while the modal is open so the page underneath doesn't
  // scroll when the user wheels inside the modal.
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener('keydown', onKey);
    };
  }, [onClose]);

  let pretty = loading ? 'Loading the source log…' : '';
  if (source) {
    try {
      pretty = JSON.stringify(JSON.parse(source), null, 2);
    } catch {
      pretty = source;
    }
  }

  // Render to document.body via portal. The InsightCard host uses `.card`
  // which sets `backdrop-filter` — and any ancestor with backdrop-filter,
  // filter, transform or perspective becomes a new containing block for
  // `position: fixed`, which previously trapped the modal inside the card
  // (it looked half-cut / off-screen). Portaling outside the card fixes it.
  const modal = (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.85)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 9999, padding: '24px',
        overflowY: 'auto',
        backdropFilter: 'blur(4px)',
        WebkitBackdropFilter: 'blur(4px)',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: 'min(1100px, 96vw)',
          height: 'min(88vh, 800px)',
          display: 'flex',
          flexDirection: 'column',
          padding: 0,
          overflow: 'hidden',
          backgroundColor: 'var(--card-bg, #0f172a)',
          border: '1px solid var(--border-color, #334155)',
          borderRadius: '12px',
          boxShadow: '0 25px 60px rgba(0,0,0,0.6)',
        }}
      >
        <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px', flexShrink: 0 }}>
          <div>
            <div style={{ fontSize: '1rem', fontWeight: 700 }}>Source Log Analyzed by AI</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              {sourceLabel(sourceFile)} · {timestamp || '-'}
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', fontSize: '1.75rem', cursor: 'pointer', lineHeight: 1, padding: '4px 10px' }}
          >
            ×
          </button>
        </div>
        <div
          style={{
            padding: '20px 24px',
            overflowY: 'auto',
            overflowX: 'auto',
            flex: '1 1 auto',
            minHeight: 0,
          }}
          className="custom-scrollbar"
        >
          {pretty ? (
            <pre style={{ fontSize: '0.85rem', backgroundColor: 'rgba(0,0,0,0.35)', padding: '16px', borderRadius: '8px', whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: 'var(--text-primary)', margin: 0, lineHeight: 1.5 }}>
              {pretty}
            </pre>
          ) : (
            <div style={{ padding: '60px 12px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
              Raw log was not stored when this insight was saved. <br />
              <span style={{ fontSize: '0.75rem', opacity: 0.7 }}>(The "View Source" feature is active for new insights only.)</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  if (typeof document === 'undefined') return modal;
  return createPortal(modal, document.body);
};

const InsightSection: React.FC<{ label: string, children: React.ReactNode }> = ({ label, children }) => (
  <div style={{ marginBottom: '12px' }}>
    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>{label}</div>
    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>{children}</div>
  </div>
);

const AIAnalysisTab: React.FC<{ insights: any[], agentName: string }> = ({ insights, agentName }) => {
  const [filter, setFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('all');

  const sources = Array.from(new Set(insights.map(i => i.source_file).filter(Boolean)));

  const filtered = insights.filter(i => {
    const matchSource = sourceFilter === 'all' || i.source_file === sourceFilter;
    const haystack = `${i.critical_summary || ''} ${i.source_file || ''}`.toLowerCase();
    const matchText = !filter || haystack.includes(filter.toLowerCase());
    return matchSource && matchText;
  });

  const counts = {
    auto: insights.filter(i => (i.critical_summary || '').includes('AUTO-DISPATCHED')).length,
    crit: insights.filter(i => /CRITICAL/i.test(i.critical_summary || '')).length,
    advice: insights.filter(i => (i.critical_summary || '').includes('AI DEFENSIVE') || i.source_file === 'SOAR_Recommender').length,
    manual: insights.filter(i => /MANUAL/i.test(i.critical_summary || '')).length,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
        <StatPill label="Total" value={insights.length} color="var(--text-primary)" />
        <StatPill label="Auto-Actions" value={counts.auto} color="#ef4444" />
        <StatPill label="Critical" value={counts.crit} color="#f87171" />
        <StatPill label="Advisories" value={counts.advice} color="#60a5fa" />
        <StatPill label="Manual Scans" value={counts.manual} color="#a78bfa" />
      </div>

      <div className="card" style={{ padding: '16px', display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          type="text"
          placeholder={`Search insights for ${agentName}...`}
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={{ flex: 1, minWidth: '220px', backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '10px 14px', color: 'var(--text-primary)', fontSize: '0.875rem', outline: 'none' }}
        />
        <select
          value={sourceFilter}
          onChange={e => setSourceFilter(e.target.value)}
          style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '10px 14px', color: 'var(--text-primary)', fontSize: '0.875rem', outline: 'none' }}
        >
          <option value="all">All Sources</option>
          {sources.map(s => <option key={s} value={s}>{sourceLabel(s)}</option>)}
        </select>
      </div>

      {filtered.length === 0 ? (
        <div className="card" style={{ padding: '64px', textAlign: 'center' }}>
          <BrainCircuit size={48} style={{ opacity: 0.15, marginBottom: '16px' }} />
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '6px' }}>No AI insights for this agent yet</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>Insights appear after the worker triages this agent's logs.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {filtered.map((insight: any, i: number) => (
            <InsightCard key={insight.id ?? i} insight={insight} />
          ))}
        </div>
      )}
    </div>
  );
};

const StatPill: React.FC<{ label: string, value: number, color: string }> = ({ label, value, color }) => (
  <div className="card" style={{ padding: '12px 18px', display: 'flex', alignItems: 'center', gap: '12px', flex: '1 1 140px' }}>
    <div style={{ fontSize: '1.5rem', fontWeight: 800, color }}>{value}</div>
    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
  </div>
);

const SoarTab: React.FC<{ data: any, agentName: string, onRefresh: () => void }> = ({ data, agentName, onRefresh }) => (
  <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
    <div style={{ padding: '20px', borderBottom: '1px solid var(--border-color)' }}>
      <h3 style={{ fontSize: '1.125rem' }}>SOAR Execution History</h3>
    </div>
    <div className="table-container">
      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
        <thead>
          <tr style={{ backgroundColor: 'rgba(255,255,255,0.02)', borderBottom: '1px solid var(--border-color)' }}>
            <th style={{ padding: '14px 20px', fontWeight: 700, color: 'var(--text-secondary)' }}>Time</th>
            <th style={{ padding: '14px 20px', fontWeight: 700, color: 'var(--text-secondary)' }}>Action</th>
            <th style={{ padding: '14px 20px', fontWeight: 700, color: 'var(--text-secondary)' }}>Target</th>
            <th style={{ padding: '14px 20px', fontWeight: 700, color: 'var(--text-secondary)' }}>Status</th>
            <th style={{ padding: '14px 20px', fontWeight: 700, color: 'var(--text-secondary)', textAlign: 'right' }}>Ops</th>
          </tr>
        </thead>
        <tbody>
          {data.soar.map((row: any, i: number) => (
            <tr key={i} style={{ borderBottom: '1px solid var(--border-color)' }}>
              <td style={{ padding: '14px 20px' }}>{row.timestamp}</td>
              <td style={{ padding: '14px 20px', fontWeight: 600 }}>{row.action?.toUpperCase()}</td>
              <td style={{ padding: '14px 20px', fontFamily: 'monospace' }}>{row.target}</td>
              <td style={{ padding: '14px 20px' }}>
                <span style={{ padding: '4px 8px', borderRadius: '4px', fontSize: '0.7rem', fontWeight: 700, backgroundColor: row.status === 'SUCCESS' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)', color: row.status === 'SUCCESS' ? 'var(--accent-success)' : 'var(--accent-color)' }}>
                  {row.status}
                </span>
              </td>
              <td style={{ padding: '14px 20px', textAlign: 'right' }}>
                {!row.resolved_at && (
                  <button onClick={async () => {
                    const c = prompt("Resolution comment:");
                    if (c) {
                      await agentService.resolveSoarAction(agentName, row.id, c);
                      onRefresh();
                    }
                  }} style={{ fontSize: '0.75rem', color: 'var(--accent-secondary)', fontWeight: 600 }}>Resolve</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

const SystemTab: React.FC<{ data: any }> = ({ data }) => (
  <div style={{ display: 'grid', gridTemplateColumns: window.innerWidth > 768 ? '1fr 1fr' : '1fr', gap: '32px' }}>
    <div className="card">
      <h3 style={{ fontSize: '1.125rem', marginBottom: '24px' }}>Hardware Resources</h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
        <ResourceMeter label="CPU Usage" value={data.resources[0]?.cpu_percent || 0} />
        <ResourceMeter label="Memory Usage" value={data.resources[0]?.mem_percent || 0} />
      </div>
    </div>
    <div className="card">
      <h3 style={{ fontSize: '1.125rem', marginBottom: '24px' }}>Disk Inventory</h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {data.disks.map((disk: any, i: number) => (
          <div key={i} style={{ padding: '12px', borderRadius: '8px', backgroundColor: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>{disk.device} ({disk.mountpoint})</span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{disk.used_gb} / {disk.total_gb} GB</span>
            </div>
            <ResourceMeter label="" value={disk.percent || 0} />
          </div>
        ))}
      </div>
    </div>
    <div className="card">
      <h3 style={{ fontSize: '1.125rem', marginBottom: '24px' }}>Network Connectivity</h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <DetailItem label="Primary IP" value={data.info[0]?.public_ip || '-'} />
        <DetailItem label="MAC Identifier" value={data.info[0]?.mac_address || '-'} />
        <DetailItem label="Hostname" value={data.info[0]?.hostname || data.info[0]?.agent_name || '-'} />
      </div>
    </div>
  </div>
);

const ResourceMeter: React.FC<{ label: string, value: number }> = ({ label, value }) => (
  <div>
    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '0.875rem' }}>
      <span>{label}</span>
      <span style={{ fontWeight: 700 }}>{value}%</span>
    </div>
    <div style={{ height: '8px', backgroundColor: 'var(--bg-color)', borderRadius: '4px', overflow: 'hidden' }}>
      <div style={{ width: `${value}%`, height: '100%', backgroundColor: value > 80 ? 'var(--accent-color)' : value > 50 ? 'var(--accent-warning)' : 'var(--accent-secondary)', transition: 'width 1s ease' }} />
    </div>
  </div>
);

export default AgentDetail;
