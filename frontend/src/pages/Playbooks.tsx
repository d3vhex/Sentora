import React, { useEffect, useState } from 'react';
import { 
  PlaySquare, 
  Play, 
  Plus, 
  Trash2, 
  CheckCircle2,
  AlertCircle,
  Clock,
  Edit2,
  X,
  Save,
  RefreshCw,
  ArrowUp,
  ArrowDown,
  Server
} from 'lucide-react';
import api, { agentService } from '../services/api';
import {
  ACTIONS,
  CATEGORY_LABELS,
  getAction,
  validateStep,
  type ActionCategory,
  type ActionSpec,
} from '../lib/playbookActions';

interface PlaybookNode {
  id: string;
  type: string;
  data: {
    action: string;
    params: {
      target?: string;
      [key: string]: any;
    }
  }
}

/** One-line "3 steps · Block IP → Kill Process → …" for the list row. */
const summarisePlaybook = (pb: any): string => {
  const nodes: PlaybookNode[] = Array.isArray(pb?.nodes) ? pb.nodes : [];
  if (!nodes.length) return 'No steps defined';

  const labels = nodes.map(n => getAction(n?.data?.action)?.label || n?.data?.action || '?');
  const shown = labels.slice(0, 3).join(' → ');
  const rest = labels.length > 3 ? ` +${labels.length - 3} more` : '';
  const risky = nodes.filter(n => getAction(n?.data?.action)?.destructive).length;

  return `${nodes.length} step${nodes.length > 1 ? 's' : ''} · ${shown}${rest}`
    + (risky ? `  ⚠ ${risky} irreversible` : '');
};

const Playbooks: React.FC = () => {
  const [agents, setAgents] = useState<string[]>([]);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [runs, setRuns] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [runningId, setRunningId] = useState<number | null>(null);
  const [expandedRun, setExpandedRun] = useState<number | null>(null);
  const [runDetail, setRunDetail] = useState<any>(null);
  const [runDetailLoading, setRunDetailLoading] = useState(false);
  
  // Modal states
  const [showModal, setShowModal] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [formData, setFormData] = useState<{
    name: string;
    description: string;
    nodes: PlaybookNode[];
  }>({
    name: '',
    description: '',
    nodes: []
  });

  useEffect(() => {
    agentService.getAgents().then((list: any[]) => {
      const agentNames = list.map(item => typeof item === 'string' ? item : item.name);
      setAgents(agentNames);
      if (agentNames.length > 0) setSelectedAgent(agentNames[0]);
    });
  }, []);

  useEffect(() => {
    if (selectedAgent) {
      fetchData();
    }
  }, [selectedAgent]);

  const fetchData = async () => {
    if (!selectedAgent) return;
    setLoading(true);
    try {
      const [pbList, runList] = await Promise.all([
        agentService.getPlaybooks(selectedAgent),
        agentService.getPlaybookRuns(selectedAgent)
      ]);
      setPlaybooks(pbList);
      setRuns(runList);
    } finally {
      setLoading(false);
    }
  };

  const toggleRunDetail = async (runId: number) => {
    if (expandedRun === runId) {
      setExpandedRun(null);
      return;
    }
    setExpandedRun(runId);
    setRunDetail(null);
    setRunDetailLoading(true);
    try {
      setRunDetail(await agentService.getPlaybookRunDetail(selectedAgent, runId));
    } catch (err) {
      console.error('Failed to load run detail', err);
      setRunDetail(null);
    } finally {
      setRunDetailLoading(false);
    }
  };

  const handleRunPlaybook = async (pbId: number) => {
    if (!selectedAgent) return;
    setRunningId(pbId);
    try {
      await api.post(`/${selectedAgent}/playbooks/${pbId}/run`);
      await fetchData();
      setTimeout(fetchData, 2500);
    } catch (err) {
      console.error('Failed to run playbook:', err);
    } finally {
      setRunningId(null);
    }
  };

  const handleDeletePlaybook = async (pbId: number) => {
    if (!selectedAgent) return;
    if (window.confirm("Are you sure you want to delete this playbook?")) {
      try {
        await api.delete(`/${selectedAgent}/playbooks/${pbId}`);
        fetchData();
      } catch (err) {
        console.error('Failed to delete playbook:', err);
      }
    }
  };

  const handleOpenCreate = () => {
    setIsEditing(false);
    setEditingId(null);
    setFormData({
      name: '',
      description: 'A new security playbook',
      nodes: [
        { id: `node_${Date.now()}`, type: 'action', data: { action: 'block_ip', params: { target: '' } } }
      ]
    });
    setShowModal(true);
  };

  const handleOpenEdit = (pb: any) => {
    setIsEditing(true);
    setEditingId(pb.id);
    setFormData({
      name: pb.name,
      description: pb.description || '',
      nodes: pb.nodes || []
    });
    setShowModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAgent) return;
    try {
      // Auto-generate linear connections from top format
      const connections = [];
      for (let i = 0; i < formData.nodes.length - 1; i++) {
        connections.push({
          source: formData.nodes[i].id,
          target: formData.nodes[i+1].id
        });
      }

      const payload = {
        name: formData.name,
        description: formData.description,
        nodes: formData.nodes,
        connections: connections
      };

      if (isEditing && editingId) {
        await agentService.updatePlaybook(selectedAgent, editingId, payload);
      } else {
        await agentService.createPlaybook(selectedAgent, payload);
      }
      setShowModal(false);
      fetchData();
    } catch (err: any) {
      alert("Error saving playbook: " + (err.response?.data?.error || err.message));
    }
  };

  const handleAddNode = () => {
    const newNode: PlaybookNode = {
      id: `node_${Date.now()}`,
      type: 'action',
      data: { action: 'block_ip', params: { target: '' } }
    };
    setFormData({ ...formData, nodes: [...formData.nodes, newNode] });
  };

  const handleUpdateNode = (index: number, field: string, value: string) => {
    const updatedNodes = [...formData.nodes];
    if (field === 'action') {
      updatedNodes[index].data.action = value;
    } else {
      updatedNodes[index].data.params[field] = value;
    }
    setFormData({ ...formData, nodes: updatedNodes });
  };

  const handleRemoveNode = (index: number) => {
    const updatedNodes = [...formData.nodes];
    updatedNodes.splice(index, 1);
    setFormData({ ...formData, nodes: updatedNodes });
  };

  const handleMoveNode = (index: number, direction: 'up' | 'down') => {
    if (direction === 'up' && index === 0) return;
    if (direction === 'down' && index === formData.nodes.length - 1) return;
    
    const updatedNodes = [...formData.nodes];
    const targetIndex = direction === 'up' ? index - 1 : index + 1;
    [updatedNodes[index], updatedNodes[targetIndex]] = [updatedNodes[targetIndex], updatedNodes[index]];
    setFormData({ ...formData, nodes: updatedNodes });
  };

  // Per-step parameter errors, keyed by step index. Recomputed on every edit
  // so the Save button reflects the current state rather than the state at
  // the last submit attempt.
  const stepErrors = React.useMemo(() => {
    const out: Record<number, string> = {};
    formData.nodes.forEach((node, i) => {
      const err = validateStep(node.data.action, node.data.params.target || '');
      if (err) out[i] = err;
    });
    return out;
  }, [formData.nodes]);

  const hasStepErrors = Object.keys(stepErrors).length > 0;
  const destructiveSteps = formData.nodes
    .map(n => getAction(n.data.action))
    .filter((a): a is ActionSpec => !!a?.destructive);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h2 style={{ fontSize: '1.875rem', marginBottom: '8px' }}>Security Playbooks</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Automated incident response workflows and threat hunting scripts.</p>
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
            <Plus size={18} /> New Playbook
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '32px' }}>
        <div>
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '1.125rem' }}>Active Playbooks</h3>
              <button onClick={fetchData} style={{ color: 'var(--text-secondary)' }}><RefreshCw size={18} className={loading ? 'animate-spin' : ''} /></button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {playbooks.map((pb, i) => (
                <div key={pb.id || i} style={{ 
                  padding: '24px', 
                  borderBottom: i < playbooks.length - 1 ? '1px solid var(--border-color)' : 'none',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  transition: 'background-color 0.2s ease'
                }}
                onMouseOver={(e) => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.01)'}
                onMouseOut={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                >
                  <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
                    <div style={{ width: '40px', height: '40px', borderRadius: '10px', backgroundColor: 'rgba(59, 130, 246, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <PlaySquare color="var(--accent-secondary)" />
                    </div>
                    <div>
                      <h4 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '4px' }}>{pb.name || 'Unnamed Playbook'}</h4>
                      {/* The list showed only a name and a timestamp, so the
                          one thing you need before pressing Run — what it will
                          do — meant opening the editor first. */}
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                        {summarisePlaybook(pb)}
                      </p>
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <Clock size={12} /> Updated: {pb.updated_at}
                      </p>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '12px' }}>
                    <button 
                      onClick={() => handleRunPlaybook(pb.id)}
                      disabled={runningId === pb.id}
                      style={{ padding: '8px 16px', borderRadius: '6px', backgroundColor: 'rgba(16, 185, 129, 0.1)', color: 'var(--accent-success)', fontSize: '0.75rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '6px', cursor: runningId === pb.id ? 'not-allowed' : 'pointer', opacity: runningId === pb.id ? 0.5 : 1 }}
                    >
                      <Play size={14} /> {runningId === pb.id ? 'RUNNING...' : 'RUN'}
                    </button>
                    <button onClick={() => handleOpenEdit(pb)} style={{ padding: '8px', color: 'var(--text-secondary)' }}><Edit2 size={18} /></button>
                    <button onClick={() => handleDeletePlaybook(pb.id)} style={{ padding: '8px', color: 'var(--accent-color)', cursor: 'pointer' }}><Trash2 size={18} /></button>
                  </div>
                </div>
              ))}
              {playbooks.length === 0 && !loading && (
                <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                  <PlaySquare size={48} style={{ opacity: 0.1, marginBottom: '16px', margin: '0 auto' }} />
                  <p>No playbooks found for this agent.</p>
                </div>
              )}
            </div>
          </div>
        </div>

        <div>
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '20px', borderBottom: '1px solid var(--border-color)' }}>
              <h3 style={{ fontSize: '1.125rem' }}>Recent Executions</h3>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {runs.map((run, i) => {
                const failed = !(run.status === 'success' || run.status === 'completed');
                const reason = (run.last_error || run.error || run.failure_reason || '').toString().trim();
                const expanded = expandedRun === run.id;
                return (
                  <div
                    key={run.id || i}
                    onClick={() => toggleRunDetail(run.id)}
                    style={{
                      padding: '16px 20px',
                      borderBottom: i < runs.length - 1 ? '1px solid var(--border-color)' : 'none',
                      cursor: 'pointer',
                      backgroundColor: expanded ? 'rgba(255,255,255,0.02)' : 'transparent',
                    }}
                    title="Show the result of each step"
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                      <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>{run.playbook_name || `Run #${run.id}`}</span>
                      <span style={{
                        fontSize: '0.75rem',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        color: failed ? 'var(--accent-color)' : 'var(--accent-success)',
                        textTransform: 'uppercase',
                        fontWeight: 600
                      }}>
                        {failed ? <AlertCircle size={14} /> : <CheckCircle2 size={14} />}
                        {run.status || 'COMPLETED'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      <span>{run.started_at || 'Just now'}</span>
                      <span>#{run.id}</span>
                    </div>
                    {failed && reason && (
                      <div
                        title={reason}
                        style={{
                          marginTop: '8px',
                          padding: '8px 10px',
                          fontSize: '0.75rem',
                          color: 'var(--accent-color)',
                          backgroundColor: 'rgba(239, 68, 68, 0.08)',
                          border: '1px solid rgba(239, 68, 68, 0.2)',
                          borderRadius: '6px',
                          fontFamily: 'monospace',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis'
                        }}
                      >
                        {reason}
                      </div>
                    )}

                    {/* Per-step results. The run row only ever showed one
                        error line, so "which step failed, and what did the
                        endpoint say" was invisible — even though the server
                        already records it per node. */}
                    {expanded && (
                      <div style={{ marginTop: '12px', borderTop: '1px solid var(--border-color)', paddingTop: '12px' }}>
                        {runDetailLoading ? (
                          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Loading step results…</p>
                        ) : runDetail?.results?.length ? (
                          runDetail.results.map((step: any, si: number) => {
                            const stepOk = /success|ok|completed/i.test(String(step.status || ''));
                            const spec = getAction(step.action || step.type);
                            return (
                              <div key={si} style={{ display: 'flex', gap: '10px', alignItems: 'flex-start', padding: '6px 0', fontSize: '0.75rem' }}>
                                <span style={{ color: stepOk ? 'var(--accent-success)' : 'var(--accent-color)', marginTop: '2px', flexShrink: 0 }}>
                                  {stepOk ? <CheckCircle2 size={13} /> : <AlertCircle size={13} />}
                                </span>
                                <div style={{ minWidth: 0 }}>
                                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                                    {si + 1}. {spec?.label || step.action || step.type || 'step'}
                                    {step.target ? <span style={{ color: 'var(--text-secondary)', fontWeight: 400 }}> → {step.target}</span> : null}
                                  </div>
                                  {(step.output || step.error || step.message) && (
                                    <div style={{ color: 'var(--text-secondary)', fontFamily: 'monospace', marginTop: '2px', wordBreak: 'break-word' }}>
                                      {String(step.output || step.error || step.message).slice(0, 300)}
                                    </div>
                                  )}
                                </div>
                              </div>
                            );
                          })
                        ) : (
                          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                            No per-step results were recorded for this run.
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
              {runs.length === 0 && (
                <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                  <p style={{ fontSize: '0.875rem' }}>No recent executions.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Playbook Edit/Create Modal */}
      {showModal && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '40px', backdropFilter: 'blur(8px)' }}>
          <div style={{ backgroundColor: 'var(--card-bg)', backdropFilter: 'blur(24px)', width: '100%', maxWidth: '800px', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-neon)', display: 'flex', flexDirection: 'column', maxHeight: '90vh', boxShadow: '0 25px 60px rgba(0,0,0,0.6)' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '1.25rem' }}>{isEditing ? 'Edit Playbook' : 'Create New Playbook'}</h3>
              <button onClick={() => setShowModal(false)} style={{ color: 'var(--text-secondary)' }}><X size={24} /></button>
            </div>
            
            <form onSubmit={handleSubmit} style={{ padding: '32px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <label style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Playbook Name</label>
                  <input 
                    type="text" 
                    value={formData.name} 
                    onChange={e => setFormData({...formData, name: e.target.value})} 
                    required 
                    style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px', color: 'white' }} 
                  />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <label style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Description</label>
                  <input 
                    type="text" 
                    value={formData.description} 
                    onChange={e => setFormData({...formData, description: e.target.value})} 
                    style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', padding: '12px', borderRadius: '8px', color: 'white' }} 
                  />
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <label style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>Action Steps</label>
                  <button type="button" onClick={handleAddNode} style={{ fontSize: '0.875rem', display: 'flex', alignItems: 'center', gap: '6px', backgroundColor: 'rgba(59, 130, 246, 0.1)', color: 'var(--accent-secondary)', padding: '6px 12px', borderRadius: '6px', fontWeight: 600 }}>
                    <Plus size={14} /> Add Step
                  </button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', backgroundColor: 'rgba(0,0,0,0.1)', padding: '16px', borderRadius: '12px', border: '1px dashed var(--border-color)' }}>
                  {formData.nodes.map((node, index) => {
                    const actionInfo = getAction(node.data.action);
                    return (
                      <div key={node.id} style={{ display: 'flex', gap: '12px', backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '16px', alignItems: 'flex-start', position: 'relative' }}>
                        
                        {/* Ordering Controls */}
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <button type="button" onClick={() => handleMoveNode(index, 'up')} disabled={index === 0} style={{ color: index === 0 ? 'var(--bg-color)' : 'var(--text-secondary)' }}>
                            <ArrowUp size={16} />
                          </button>
                          <div style={{ width: '24px', height: '24px', borderRadius: '12px', backgroundColor: 'rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 700, margin: '4px 0' }}>
                            {index + 1}
                          </div>
                          <button type="button" onClick={() => handleMoveNode(index, 'down')} disabled={index === formData.nodes.length - 1} style={{ color: index === formData.nodes.length - 1 ? 'var(--bg-color)' : 'var(--text-secondary)' }}>
                            <ArrowDown size={16} />
                          </button>
                        </div>

                        {/* Action Configuration */}
                        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '10px' }}>
                          <div style={{ display: 'flex', gap: '12px' }}>
                            <div style={{ flex: 1 }}>
                              <select
                                value={node.data.action}
                                onChange={e => handleUpdateNode(index, 'action', e.target.value)}
                                style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', padding: '10px', borderRadius: '8px', color: 'white', width: '100%', fontSize: '0.875rem' }}
                              >
                                {/* Grouped, so seventeen actions read as five short
                                    lists instead of one long one. */}
                                {(Object.keys(CATEGORY_LABELS) as ActionCategory[])
                                  .filter(cat => ACTIONS.some(a => a.category === cat))
                                  .map(cat => (
                                    <optgroup key={cat} label={CATEGORY_LABELS[cat]}>
                                      {ACTIONS.filter(a => a.category === cat).map(a => (
                                        <option key={a.value} value={a.value}>
                                          {a.label}{a.destructive ? '  ⚠' : ''}
                                        </option>
                                      ))}
                                    </optgroup>
                                  ))}
                              </select>
                            </div>
                            <button type="button" onClick={() => handleRemoveNode(index)} style={{ padding: '8px', color: 'var(--accent-color)', backgroundColor: 'rgba(239, 68, 68, 0.1)', borderRadius: '8px' }}>
                              <Trash2 size={16} />
                            </button>
                          </div>

                          {/* What the step actually does, so the operator does
                              not have to already know the action name. */}
                          {actionInfo && (
                            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>
                              {actionInfo.description}
                            </p>
                          )}

                          {actionInfo?.destructive && (
                            <div style={{
                              display: 'flex', alignItems: 'center', gap: '8px',
                              fontSize: '0.75rem', color: '#f59e0b', fontWeight: 600,
                              backgroundColor: 'rgba(245,158,11,0.08)',
                              border: '1px solid rgba(245,158,11,0.25)',
                              borderRadius: '6px', padding: '8px 10px',
                            }}>
                              <AlertCircle size={14} /> Cannot be undone from the console.
                            </div>
                          )}

                          {/* Only rendered when the action takes one. The old
                              editor showed an empty box for parameterless
                              actions, which read as a field left unfilled. */}
                          {actionInfo?.param && (
                            <div>
                              <label style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                                {actionInfo.param.label}
                              </label>
                              <input
                                type="text"
                                value={node.data.params.target || ''}
                                onChange={e => handleUpdateNode(index, 'target', e.target.value)}
                                placeholder={actionInfo.param.placeholder}
                                style={{
                                  backgroundColor: 'rgba(0,0,0,0.2)',
                                  border: `1px solid ${stepErrors[index] ? 'rgba(239,68,68,0.5)' : 'var(--border-color)'}`,
                                  padding: '10px 12px', borderRadius: '8px', color: 'white',
                                  width: '100%', fontSize: '0.875rem',
                                }}
                              />
                              {stepErrors[index] && (
                                <p style={{ fontSize: '0.75rem', color: '#ef4444', margin: '6px 0 0 0' }}>
                                  {stepErrors[index]}
                                </p>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}

                  {formData.nodes.length === 0 && (
                    <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
                      <Server size={32} style={{ opacity: 0.1, margin: '0 auto 12px auto' }} />
                      No actions defined yet. Click "Add Step" to begin building your playbook.
                    </div>
                  )}
                </div>
              </div>

              {destructiveSteps.length > 0 && (
                <div style={{
                  padding: '12px 14px', borderRadius: '8px', fontSize: '0.8125rem',
                  backgroundColor: 'rgba(245,158,11,0.08)',
                  border: '1px solid rgba(245,158,11,0.25)', color: '#fbbf24',
                  display: 'flex', gap: '10px', alignItems: 'flex-start',
                }}>
                  <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
                  <span>
                    This playbook contains {destructiveSteps.length} irreversible step
                    {destructiveSteps.length > 1 ? 's' : ''} ({destructiveSteps.map(a => a.label).join(', ')}).
                    Running it cannot be undone from the console.
                  </span>
                </div>
              )}

              <div style={{ display: 'flex', gap: '12px', marginTop: '12px' }}>
                <button type="button" onClick={() => setShowModal(false)} style={{ flex: 1, padding: '14px', borderRadius: '8px', border: '1px solid var(--border-color)', color: 'white', fontWeight: 600 }}>Cancel</button>
                <button
                  type="submit"
                  disabled={hasStepErrors || formData.nodes.length === 0}
                  title={
                    formData.nodes.length === 0 ? 'Add at least one step'
                      : hasStepErrors ? 'Fix the highlighted steps first'
                        : undefined
                  }
                  style={{
                    flex: 1, padding: '14px', borderRadius: '8px',
                    backgroundColor: (hasStepErrors || formData.nodes.length === 0)
                      ? 'var(--border-color)' : 'var(--accent-secondary)',
                    color: 'white', fontWeight: 700, display: 'flex',
                    alignItems: 'center', justifyContent: 'center', gap: '8px',
                    cursor: (hasStepErrors || formData.nodes.length === 0) ? 'not-allowed' : 'pointer',
                  }}
                >
                  <Save size={18} /> {isEditing ? 'Update Playbook' : 'Create Playbook'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Playbooks;
