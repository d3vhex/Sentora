import React, { useState, useEffect, useMemo } from 'react';
import { 
  Database, 
  Search, 
  Cpu, 
  Package, 
  Globe, 
  Server,
  RefreshCw,
  ChevronRight,
  Info
} from 'lucide-react';
import { agentService } from '../services/api';
import { Card } from '../components/ui';
import { CategoryBars } from '../components/ui/charts';

const chartNote: React.CSSProperties = {
  margin: '0 0 var(--space-3)', color: 'var(--text-muted)',
  fontSize: 'var(--text-xs)', maxWidth: '58ch',
};

/** A socket state is a state, so it takes a semantic colour. A listening
 *  socket is surface; an established one is a conversation already underway. */
const STATE_TONE: Record<string, string> = {
  LISTEN: 'var(--sev-medium)',
  ESTABLISHED: 'var(--sev-high)',
  CLOSE_WAIT: 'var(--sev-low)',
  TIME_WAIT: 'var(--sev-info)',
};

const Assets: React.FC = () => {
    const [agents, setAgents] = useState<any[]>([]);
    const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<'hardware' | 'software' | 'network'>('hardware');
    const [data, setData] = useState<any[]>([]);
    const [loading, setLoading] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        fetchAgents();
    }, []);

    useEffect(() => {
        if (selectedAgent) {
            fetchInventory();
        }
    }, [selectedAgent, activeTab]);

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

    const fetchInventory = async () => {
        if (!selectedAgent) return;
        setLoading(true);
        try {
            // Using the new endpoints
            const endpoint = `/api/agent/${selectedAgent}/inventory/${activeTab}`;
            const res = await agentService.getCustom(endpoint);
            setData(res || []);
        } catch (err) {
            console.error("Failed to fetch inventory", err);
            setData([]);
        } finally {
            setLoading(false);
        }
    };

    const filteredData = data.filter(item => {
        const searchStr = JSON.stringify(item).toLowerCase();
        return searchStr.includes(searchTerm.toLowerCase());
    });

    /* One chart per tab, because the three tabs answer three different
       questions - and all of them are asked of the rows already on screen,
       so the picture and the table can never disagree. */
    const breakdown = useMemo(() => {
        const field =
            activeTab === 'hardware' ? (i: any) => i.type
            : activeTab === 'software' ? (i: any) => i.vendor
            : (i: any) => i.state;

        const counts = new Map<string, number>();
        for (const item of filteredData) {
            const key = String(field(item) || 'unknown').trim() || 'unknown';
            counts.set(key, (counts.get(key) ?? 0) + 1);
        }
        return [...counts.entries()]
            .map(([name, value]) => ({
                name: name.length > 22 ? name.slice(0, 21) + '…' : name,
                value,
            }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 8);
    }, [filteredData, activeTab]);

    const breakdownCopy = activeTab === 'hardware'
        ? { title: 'Hardware by type',
            note: 'What the inventory is made of. A category that is missing entirely usually means the collector for it failed rather than the host has none.' }
        : activeTab === 'software'
        ? { title: 'Packages by vendor',
            note: 'Who wrote the software on this host. A long tail of one-off vendors is where unmanaged software lives.' }
        : { title: 'Connections by state',
            note: 'Listening sockets are attack surface; established ones are traffic already flowing. The mix is the shape of what this host is doing.' };

    return (
        <div style={{ padding: '32px', maxWidth: '1600px', margin: '0 auto', animation: 'fadeIn 0.5s ease-out' }}>
            {/* Header Section */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '32px' }}>
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                        <div style={{ background: 'linear-gradient(135deg, var(--accent-secondary), #3b82f6)', padding: '10px', borderRadius: '12px', display: 'flex' }}>
                            <Database size={24} color="white" />
                        </div>
                        <h1 style={{ fontSize: '2rem', fontWeight: 800, background: 'linear-gradient(to right, #fff, #a1a1aa)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Asset & Inventory</h1>
                    </div>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '1rem', fontWeight: 500 }}>Comprehensive hardware, software, and network monitoring.</p>
                </div>
                
                <div style={{ display: 'flex', gap: '12px' }}>
                    <div style={{ position: 'relative' }}>
                        <Search size={18} style={{ position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
                        <input 
                            type="text" 
                            placeholder="Search assets..." 
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
                        onClick={fetchInventory}
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
                                    backgroundColor: selectedAgent === agent.name ? 'rgba(59, 130, 246, 0.1)' : 'transparent',
                                    color: selectedAgent === agent.name ? 'white' : 'var(--text-secondary)',
                                    textAlign: 'left',
                                    transition: 'all 0.2s',
                                    cursor: 'pointer'
                                }}
                            >
                                <div style={{ 
                                    width: '32px', height: '32px', borderRadius: '8px', 
                                    backgroundColor: selectedAgent === agent.name ? 'var(--accent-secondary)' : 'rgba(255,255,255,0.05)',
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

                {/* Main Content */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                    {/* Tabs */}
                    <div style={{ display: 'flex', background: 'var(--card-bg)', padding: '6px', borderRadius: '14px', border: '1px solid var(--border-color)', width: 'fit-content' }}>
                        <TabButton active={activeTab === 'hardware'} onClick={() => setActiveTab('hardware')} icon={<Cpu size={16} />} label="Hardware" />
                        <TabButton active={activeTab === 'software'} onClick={() => setActiveTab('software')} icon={<Package size={16} />} label="Software" />
                        <TabButton active={activeTab === 'network'} onClick={() => setActiveTab('network')} icon={<Globe size={16} />} label="Network" />
                    </div>

                    <div style={{ marginBottom: '24px' }}>
                        <Card title={breakdownCopy.title}>
                            <p style={chartNote}>{breakdownCopy.note}</p>
                            <CategoryBars
                                data={breakdown}
                                height={200}
                                colorFor={activeTab === 'network'
                                    ? (row) => STATE_TONE[row.name.toUpperCase()] ?? 'var(--chart-1)'
                                    : undefined}
                            />
                        </Card>
                    </div>

                    {/* Table View */}
                    <div style={{ 
                        background: 'var(--card-bg)', 
                        borderRadius: '20px', 
                        border: '1px solid var(--border-color)', 
                        overflow: 'hidden',
                        boxShadow: '0 10px 40px rgba(0,0,0,0.2)'
                    }}>
                        <div style={{ overflowX: 'auto' }}>
                            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                                <thead>
                                    <tr style={{ borderBottom: '1px solid var(--border-color)', backgroundColor: 'rgba(255,255,255,0.02)' }}>
                                        {activeTab === 'hardware' && <>
                                            <Th>Type</Th>
                                            <Th>Item Name</Th>
                                            <Th>Specification / Path</Th>
                                            <Th>Status</Th>
                                            <Th>Last Scanned</Th>
                                        </>}
                                        {activeTab === 'software' && <>
                                            <Th>Package Name</Th>
                                            <Th>Version</Th>
                                            <Th>Vendor</Th>
                                            <Th>Installed Date</Th>
                                            <Th>Status</Th>
                                        </>}
                                        {/* The columns `network_connections`
                                            actually has. `Protocol` was here
                                            and the table has no such field,
                                            so it rendered as a blank badge on
                                            every row - while the remote
                                            address, which is the whole point
                                            of an established connection, was
                                            not shown at all. */}
                                        {activeTab === 'network' && <>
                                            <Th>Process</Th>
                                            <Th>PID</Th>
                                            <Th>Local</Th>
                                            <Th>Remote</Th>
                                            <Th>State</Th>
                                        </>}
                                    </tr>
                                </thead>
                                <tbody>
                                    {loading ? (
                                        <tr>
                                            <td colSpan={6} style={{ padding: '64px', textAlign: 'center' }}>
                                                <RefreshCw size={24} className="animate-spin" style={{ opacity: 0.5, marginBottom: '12px' }} />
                                                <p style={{ color: 'var(--text-secondary)' }}>Gathering intelligence...</p>
                                            </td>
                                        </tr>
                                    ) : filteredData.length === 0 ? (
                                        <tr>
                                            <td colSpan={6} style={{ padding: '64px', textAlign: 'center' }}>
                                                <Info size={32} style={{ opacity: 0.2, marginBottom: '12px' }} />
                                                <p style={{ color: 'var(--text-secondary)' }}>No assets found for the selected category.</p>
                                            </td>
                                        </tr>
                                    ) : filteredData.map((item, idx) => (
                                        <tr key={idx} style={{ 
                                            borderBottom: '1px solid rgba(255,255,255,0.03)',
                                            transition: 'background-color 0.2s'
                                        }} onMouseOver={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.01)'}
                                           onMouseOut={e => e.currentTarget.style.backgroundColor = 'transparent'}>
                                            {activeTab === 'hardware' && <>
                                                <Td><span style={{ textTransform: 'uppercase', fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-secondary)' }}>{item.type}</span></Td>
                                                <Td style={{ fontWeight: 600 }}>{item.name}</Td>
                                                <Td style={{ color: 'var(--text-secondary)' }}>{item.product_id}</Td>
                                                <Td><StatusBadge status={item.status} /></Td>
                                                <Td style={{ fontSize: '0.8rem', opacity: 0.6 }}>{item.timestamp}</Td>
                                            </>}
                                            {activeTab === 'software' && <>
                                                <Td style={{ fontWeight: 600 }}>{item.name}</Td>
                                                <Td style={{ color: 'var(--accent-secondary)', fontWeight: 500 }}>{item.version}</Td>
                                                <Td>{item.vendor}</Td>
                                                <Td style={{ opacity: 0.6 }}>{item.install_date}</Td>
                                                <Td><StatusBadge status="installed" /></Td>
                                            </>}
                                            {activeTab === 'network' && <>
                                                <Td style={{ fontWeight: 600 }}>{item.process_name}</Td>
                                                <Td style={{ opacity: 0.6 }}>{item.pid}</Td>
                                                <Td className="mono">{item.local_addr}:{item.local_port}</Td>
                                                <Td className="mono" style={{ color: 'var(--accent-secondary)' }}>
                                                    {item.remote_addr}:{item.remote_port}
                                                </Td>
                                                <Td><StatusBadge status={item.state} /></Td>
                                            </>}
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

const TabButton = ({ active, onClick, icon, label }: any) => (
    <button
        onClick={onClick}
        style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 20px',
            borderRadius: '10px',
            border: 'none',
            backgroundColor: active ? 'rgba(255,255,255,0.08)' : 'transparent',
            color: active ? 'white' : 'var(--text-secondary)',
            fontWeight: active ? 700 : 500,
            fontSize: '0.9rem',
            transition: 'all 0.2s',
            cursor: 'pointer'
        }}
    >
        {icon} {label}
    </button>
);

const Th = ({ children }: any) => (
    <th style={{ padding: '16px 20px', fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{children}</th>
);

const Td = ({ children, style, className }: any) => (
    <td className={className} style={{ padding: '16px 20px', fontSize: '0.9rem', ...style }}>{children}</td>
);

const StatusBadge = ({ status }: { status: string }) => {
    const isGood = ['active', 'connected', 'LISTEN', 'installed'].includes(status);
    return (
        <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 10px',
            borderRadius: '6px',
            backgroundColor: isGood ? 'rgba(34, 197, 94, 0.1)' : 'rgba(244, 114, 182, 0.1)',
            color: isGood ? '#4ade80' : '#f472b6',
            fontSize: '0.75rem',
            fontWeight: 700,
            textTransform: 'uppercase'
        }}>
            <div style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'currentColor' }}></div>
            {status}
        </div>
    );
};

export default Assets;
