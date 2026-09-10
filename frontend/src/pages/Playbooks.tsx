/**
 * Ordered response actions, and what happened the last time they ran.
 *
 * Every request on this page failed silently. `fetchData` had a `try/finally`
 * and no `catch`; run and delete both ended at `console.error`. The run one is
 * the serious case: these playbooks contain steps the editor itself labels
 * "cannot be undone from the console", and pressing Run on a request that
 * never reached the server looked exactly like pressing Run on one that did.
 * The operator's next move - press it again - is the worst available.
 *
 * The step editor is unchanged. It already validated per step, described what
 * each action does, and refused to save a playbook with an invalid target;
 * that part was carefully built and only needed the shared shell around it.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  PlaySquare, Play, Plus, Trash2, CheckCircle2, AlertCircle, Clock,
  Edit2, Save, RefreshCw, ArrowUp, ArrowDown, Server,
} from 'lucide-react';
import api, { agentService } from '../services/api';
import {
  ACTIONS, CATEGORY_LABELS, getAction, validateStep,
  type ActionCategory, type ActionSpec,
} from '../lib/playbookActions';
import {
  PageHeader, Card, Badge, Field, EmptyState, ErrorState, LoadingState,
  Modal, DialogButton,
} from '../components/ui';

interface PlaybookNode {
  id: string;
  type: string;
  data: { action: string; params: { target?: string; [key: string]: any } };
}

/** One-line "3 steps · Block IP → Kill Process → …" for the list row. */
const summarisePlaybook = (pb: any): string => {
  const nodes: PlaybookNode[] = Array.isArray(pb?.nodes) ? pb.nodes : [];
  if (!nodes.length) return 'No steps defined';

  const labels = nodes.map((n) => getAction(n?.data?.action)?.label || n?.data?.action || '?');
  const shown = labels.slice(0, 3).join(' → ');
  const rest = labels.length > 3 ? ` +${labels.length - 3} more` : '';
  const risky = nodes.filter((n) => getAction(n?.data?.action)?.destructive).length;

  return `${nodes.length} step${nodes.length > 1 ? 's' : ''} · ${shown}${rest}`
    + (risky ? `  ·  ${risky} irreversible` : '');
};

const Playbooks: React.FC = () => {
  const [agents, setAgents] = useState<string[]>([]);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [runs, setRuns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [runningId, setRunningId] = useState<number | null>(null);
  const [expandedRun, setExpandedRun] = useState<number | null>(null);
  const [runDetail, setRunDetail] = useState<any>(null);
  const [runDetailLoading, setRunDetailLoading] = useState(false);

  const [showModal, setShowModal] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<any>(null);
  const [formData, setFormData] = useState<{
    name: string; description: string; nodes: PlaybookNode[];
  }>({ name: '', description: '', nodes: [] });

  const say = (err: any, fallback: string) =>
    err?.response?.data?.error || err?.response?.data?.message || err?.message || fallback;

  useEffect(() => {
    agentService.getAgents()
      .then((list: any[]) => {
        const names = list.map((item) => (typeof item === 'string' ? item : item.name));
        setAgents(names);
        setSelectedAgent((current) => current || names[0] || '');
        if (names.length === 0) setLoading(false);
      })
      .catch((err) => {
        setError(say(err, 'Could not list agents'));
        setLoading(false);
      });
  }, []);

  const fetchData = useCallback(async () => {
    if (!selectedAgent) return;
    setLoading(true);
    try {
      const [pbList, runList] = await Promise.all([
        agentService.getPlaybooks(selectedAgent),
        agentService.getPlaybookRuns(selectedAgent),
      ]);
      setPlaybooks(pbList);
      setRuns(runList);
      setError(null);
    } catch (err) {
      setError(say(err, `Could not read playbooks for ${selectedAgent}`));
    } finally {
      setLoading(false);
    }
  }, [selectedAgent]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const toggleRunDetail = async (runId: number) => {
    if (expandedRun === runId) { setExpandedRun(null); return; }
    setExpandedRun(runId);
    setRunDetail(null);
    setRunDetailLoading(true);
    try {
      setRunDetail(await agentService.getPlaybookRunDetail(selectedAgent, runId));
    } catch {
      setRunDetail({ failed_to_load: true });
    } finally {
      setRunDetailLoading(false);
    }
  };

  const handleRunPlaybook = async (pb: any) => {
    if (!selectedAgent) return;
    setRunningId(pb.id);
    setNotice(null);
    try {
      await api.post(`/${selectedAgent}/playbooks/${pb.id}/run`);
      // "Started", not "succeeded". The steps run on the host afterwards and
      // the execution list below is what reports their result.
      setNotice(`${pb.name || `Playbook #${pb.id}`} started on ${selectedAgent}. Watch the runs list for step results.`);
      await fetchData();
      setTimeout(fetchData, 2500);
    } catch (err) {
      // This used to be console.error. A playbook that never started and one
      // that started and failed looked identical, and the natural response to
      // the first - press it again - is the wrong response to the second.
      setError(say(err, `${pb.name || 'The playbook'} did not start. Nothing has run.`));
    } finally {
      setRunningId(null);
    }
  };

  const handleDeletePlaybook = async (pb: any) => {
    setConfirmDelete(null);
    if (!selectedAgent) return;
    try {
      await api.delete(`/${selectedAgent}/playbooks/${pb.id}`);
      fetchData();
    } catch (err) {
      setError(say(err, 'Failed to delete the playbook'));
    }
  };

  const openCreate = () => {
    setEditingId(null);
    setFormData({
      name: '',
      description: '',
      nodes: [{ id: `node_${Date.now()}`, type: 'action', data: { action: 'block_ip', params: { target: '' } } }],
    });
    setShowModal(true);
  };

  const openEdit = (pb: any) => {
    setEditingId(pb.id);
    setFormData({ name: pb.name, description: pb.description || '', nodes: pb.nodes || [] });
    setShowModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAgent) return;
    // The editor is a list; the server wants a graph. Linear connections are
    // generated from the order shown.
    const connections = formData.nodes.slice(0, -1).map((node, i) => ({
      source: node.id, target: formData.nodes[i + 1].id,
    }));
    const payload = { ...formData, connections };
    try {
      if (editingId) {
        await agentService.updatePlaybook(selectedAgent, editingId, payload);
      } else {
        await agentService.createPlaybook(selectedAgent, payload);
      }
      setShowModal(false);
      fetchData();
    } catch (err) {
      alert(say(err, 'Failed to save the playbook'));
    }
  };

  const addNode = () => setFormData((f) => ({
    ...f,
    nodes: [...f.nodes, {
      id: `node_${Date.now()}`, type: 'action',
      data: { action: 'block_ip', params: { target: '' } },
    }],
  }));

  const updateNode = (index: number, field: string, value: string) => {
    setFormData((f) => {
      const nodes = f.nodes.map((n, i) => {
        if (i !== index) return n;
        return field === 'action'
          ? { ...n, data: { ...n.data, action: value } }
          : { ...n, data: { ...n.data, params: { ...n.data.params, [field]: value } } };
      });
      return { ...f, nodes };
    });
  };

  const removeNode = (index: number) =>
    setFormData((f) => ({ ...f, nodes: f.nodes.filter((_, i) => i !== index) }));

  const moveNode = (index: number, direction: 'up' | 'down') => {
    const target = direction === 'up' ? index - 1 : index + 1;
    if (target < 0 || target >= formData.nodes.length) return;
    setFormData((f) => {
      const nodes = [...f.nodes];
      [nodes[index], nodes[target]] = [nodes[target], nodes[index]];
      return { ...f, nodes };
    });
  };

  // Per-step parameter errors, keyed by step index. Recomputed on every edit
  // so the Save button reflects the current state rather than the state at the
  // last submit attempt.
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
    .map((n) => getAction(n.data.action))
    .filter((a): a is ActionSpec => !!a?.destructive);

  const playbookList = () => {
    if (loading) return <LoadingState label="Reading playbooks…" />;
    if (agents.length === 0) {
      return <EmptyState title="No agents" detail="A playbook runs on a host. Enrol one first." />;
    }
    if (playbooks.length === 0) {
      return (
        <EmptyState
          title="No playbooks for this agent"
          detail="A playbook is an ordered list of response actions you can run in one press."
          icon={<PlaySquare size={18} style={{ color: 'var(--text-muted)' }} />}
        />
      );
    }
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
        {playbooks.map((pb) => (
          <div
            key={pb.id}
            style={{
              display: 'flex', justifyContent: 'space-between',
              alignItems: 'flex-start', gap: 'var(--space-4)',
              padding: 'var(--space-3)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
            }}
          >
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                {pb.name || 'Unnamed playbook'}
              </div>
              {/* The list showed only a name and a timestamp, so the one thing
                  you need before pressing Run — what it will do — meant
                  opening the editor first. */}
              <div
                style={{
                  marginTop: 'var(--space-1)', fontSize: 'var(--text-xs)',
                  color: 'var(--text-secondary)',
                }}
              >
                {summarisePlaybook(pb)}
              </div>
              <div
                style={{
                  display: 'flex', alignItems: 'center', gap: 'var(--space-1)',
                  marginTop: 'var(--space-1)', fontSize: 'var(--text-xs)',
                  color: 'var(--text-muted)',
                }}
              >
                <Clock size={11} /> {pb.updated_at}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 'var(--space-2)', flexShrink: 0 }}>
              <button
                className="btn-secondary"
                onClick={() => handleRunPlaybook(pb)}
                disabled={runningId === pb.id}
              >
                <Play size={14} /> {runningId === pb.id ? 'Starting…' : 'Run'}
              </button>
              <button className="icon-btn" title="Edit" onClick={() => openEdit(pb)}>
                <Edit2 size={15} />
              </button>
              <button
                className="icon-btn"
                title="Delete"
                onClick={() => setConfirmDelete(pb)}
                style={{ color: 'var(--accent-color)' }}
              >
                <Trash2 size={15} />
              </button>
            </div>
          </div>
        ))}
      </div>
    );
  };

  const runList = () => {
    if (loading) return <LoadingState label="Reading runs…" />;
    if (runs.length === 0) {
      return <EmptyState title="Nothing has run yet" detail="Executions and their per-step results appear here." />;
    }
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
        {runs.map((run) => {
          const ok = run.status === 'success' || run.status === 'completed';
          const reason = (run.last_error || run.error || run.failure_reason || '').toString().trim();
          const expanded = expandedRun === run.id;
          return (
            <div
              key={run.id}
              style={{
                padding: 'var(--space-3)',
                border: '1px solid var(--border-color)',
                borderRadius: 'var(--radius-md)',
              }}
            >
              <button
                onClick={() => toggleRunDetail(run.id)}
                title="Show the result of each step"
                style={{
                  display: 'flex', justifyContent: 'space-between', width: '100%',
                  gap: 'var(--space-3)', background: 'none', border: 'none',
                  padding: 0, cursor: 'pointer', textAlign: 'left',
                  color: 'inherit', font: 'inherit',
                }}
              >
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                  {run.playbook_name || `Run #${run.id}`}
                </span>
                <Badge tone={ok ? 'ok' : 'critical'}>{run.status || 'unknown'}</Badge>
              </button>
              <div
                style={{
                  display: 'flex', justifyContent: 'space-between',
                  marginTop: 'var(--space-1)', fontSize: 'var(--text-xs)',
                  color: 'var(--text-muted)',
                }}
              >
                <span>{run.started_at || 'just now'}</span>
                <span>#{run.id}</span>
              </div>

              {!ok && reason && (
                <div
                  className="mono"
                  title={reason}
                  style={{
                    marginTop: 'var(--space-2)', padding: 'var(--space-2)',
                    fontSize: 'var(--text-xs)', color: 'var(--accent-color)',
                    border: '1px solid var(--border-color)',
                    borderRadius: 'var(--radius-sm)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}
                >
                  {reason}
                </div>
              )}

              {/* Per-step results. The run row only ever showed one error line,
                  so "which step failed, and what did the endpoint say" was
                  invisible — even though the server records it per node. */}
              {expanded && (
                <div
                  style={{
                    marginTop: 'var(--space-3)', paddingTop: 'var(--space-3)',
                    borderTop: '1px solid var(--border-color)',
                  }}
                >
                  {runDetailLoading && <LoadingState label="Loading step results…" />}
                  {!runDetailLoading && runDetail?.failed_to_load && (
                    <ErrorState title="Could not load the step results" detail="The run itself is unaffected." />
                  )}
                  {!runDetailLoading && !runDetail?.failed_to_load && !runDetail?.results?.length && (
                    <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                      No per-step results were recorded for this run.
                    </p>
                  )}
                  {!runDetailLoading && runDetail?.results?.map((step: any, si: number) => {
                    const stepOk = /success|ok|completed/i.test(String(step.status || ''));
                    const spec = getAction(step.action || step.type);
                    return (
                      <div
                        key={`${run.id}-step-${si}`}
                        style={{
                          display: 'flex', gap: 'var(--space-2)', alignItems: 'flex-start',
                          padding: 'var(--space-1) 0', fontSize: 'var(--text-xs)',
                        }}
                      >
                        <span
                          style={{
                            color: stepOk ? 'var(--accent-success)' : 'var(--accent-color)',
                            flexShrink: 0, marginTop: 2,
                          }}
                        >
                          {stepOk ? <CheckCircle2 size={13} /> : <AlertCircle size={13} />}
                        </span>
                        <div style={{ minWidth: 0 }}>
                          <div style={{ color: 'var(--text-primary)' }}>
                            {si + 1}. {spec?.label || step.action || step.type || 'step'}
                            {step.target && (
                              <span style={{ color: 'var(--text-secondary)' }}> → {step.target}</span>
                            )}
                          </div>
                          {(step.output || step.error || step.message) && (
                            <div
                              className="mono"
                              style={{
                                marginTop: 2, color: 'var(--text-secondary)',
                                wordBreak: 'break-word',
                              }}
                            >
                              {String(step.output || step.error || step.message).slice(0, 300)}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div>
      <PageHeader
        title="Playbooks"
        subtitle="An ordered set of response actions, run on one host in one press — and what each step returned."
        icon={<PlaySquare size={22} />}
        actions={
          <>
            <select
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              disabled={agents.length === 0}
            >
              {agents.length === 0 && <option>No agents</option>}
              {agents.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
            <button className="btn-secondary" onClick={fetchData}>
              <RefreshCw size={15} className={loading ? 'animate-spin' : undefined} />
            </button>
            <button className="btn-primary" onClick={openCreate} disabled={!selectedAgent}>
              <Plus size={15} /> New playbook
            </button>
          </>
        }
      />

      {error && (
        <div style={{ marginBottom: 'var(--space-5)' }}>
          <ErrorState title="Request failed" detail={error} />
        </div>
      )}
      {notice && (
        <p
          style={{
            margin: '0 0 var(--space-5)', padding: 'var(--space-3)',
            border: '1px solid var(--border-color)',
            borderRadius: 'var(--radius-md)',
            fontSize: 'var(--text-sm)', color: 'var(--text-secondary)',
          }}
        >
          {notice}
        </p>
      )}

      <div
        style={{
          display: 'grid', gap: 'var(--space-5)', alignItems: 'start',
          gridTemplateColumns: 'minmax(0, 1.6fr) minmax(280px, 1fr)',
        }}
      >
        <Card title="Playbooks">{playbookList()}</Card>
        <Card title="Recent runs">{runList()}</Card>
      </div>

      {showModal && (
        <Modal
          title={editingId ? 'Edit playbook' : 'New playbook'}
          subtitle="Steps run top to bottom on the selected agent."
          onClose={() => setShowModal(false)}
          width={800}
        >
          <form
            onSubmit={handleSubmit}
            style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}
          >
            <div className="responsive-grid">
              <Field label="Name">
                <input
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  required
                  autoFocus
                />
              </Field>
              <Field label="Description" hint="What situation this is for.">
                <input
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                />
              </Field>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div
                style={{
                  display: 'flex', alignItems: 'center',
                  justifyContent: 'space-between', gap: 'var(--space-3)',
                }}
              >
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                  Steps
                </span>
                <button type="button" className="btn-secondary" onClick={addNode}>
                  <Plus size={14} /> Add step
                </button>
              </div>

              {formData.nodes.length === 0 ? (
                <EmptyState
                  title="No steps"
                  detail="A playbook with no steps does nothing when run."
                  icon={<Server size={18} style={{ color: 'var(--text-muted)' }} />}
                />
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                  {formData.nodes.map((node, index) => {
                    const actionInfo = getAction(node.data.action);
                    return (
                      <div
                        key={node.id}
                        style={{
                          display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-start',
                          padding: 'var(--space-3)',
                          border: '1px solid var(--border-color)',
                          borderRadius: 'var(--radius-md)',
                        }}
                      >
                        <div
                          style={{
                            display: 'flex', flexDirection: 'column',
                            alignItems: 'center', gap: 2,
                          }}
                        >
                          <button
                            type="button"
                            className="icon-btn"
                            onClick={() => moveNode(index, 'up')}
                            disabled={index === 0}
                            title="Move up"
                          >
                            <ArrowUp size={14} />
                          </button>
                          <span
                            style={{
                              fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
                            }}
                          >
                            {index + 1}
                          </span>
                          <button
                            type="button"
                            className="icon-btn"
                            onClick={() => moveNode(index, 'down')}
                            disabled={index === formData.nodes.length - 1}
                            title="Move down"
                          >
                            <ArrowDown size={14} />
                          </button>
                        </div>

                        <div
                          style={{
                            flex: 1, minWidth: 0, display: 'flex',
                            flexDirection: 'column', gap: 'var(--space-2)',
                          }}
                        >
                          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                            <select
                              value={node.data.action}
                              onChange={(e) => updateNode(index, 'action', e.target.value)}
                              style={{ flex: 1 }}
                            >
                              {/* Grouped, so seventeen actions read as five short
                                  lists instead of one long one. */}
                              {(Object.keys(CATEGORY_LABELS) as ActionCategory[])
                                .filter((cat) => ACTIONS.some((a) => a.category === cat))
                                .map((cat) => (
                                  <optgroup key={cat} label={CATEGORY_LABELS[cat]}>
                                    {ACTIONS.filter((a) => a.category === cat).map((a) => (
                                      <option key={a.value} value={a.value}>
                                        {a.label}{a.destructive ? '  ⚠' : ''}
                                      </option>
                                    ))}
                                  </optgroup>
                                ))}
                            </select>
                            <button
                              type="button"
                              className="icon-btn"
                              onClick={() => removeNode(index)}
                              title="Remove step"
                              style={{ color: 'var(--accent-color)' }}
                            >
                              <Trash2 size={15} />
                            </button>
                          </div>

                          {/* What the step actually does, so the operator does
                              not have to already know the action name. */}
                          {actionInfo && (
                            <p
                              style={{
                                margin: 0, fontSize: 'var(--text-xs)',
                                color: 'var(--text-secondary)', lineHeight: 1.5,
                              }}
                            >
                              {actionInfo.description}
                            </p>
                          )}

                          {actionInfo?.destructive && (
                            <Badge tone="medium">cannot be undone</Badge>
                          )}

                          {/* Only rendered when the action takes one. The old
                              editor showed an empty box for parameterless
                              actions, which read as a field left unfilled. */}
                          {actionInfo?.param && (
                            <Field label={actionInfo.param.label} hint={stepErrors[index]}>
                              <input
                                value={node.data.params.target || ''}
                                onChange={(e) => updateNode(index, 'target', e.target.value)}
                                placeholder={actionInfo.param.placeholder}
                                style={stepErrors[index]
                                  ? { borderColor: 'var(--accent-color)' }
                                  : undefined}
                              />
                            </Field>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {destructiveSteps.length > 0 && (
              <ErrorState
                title={`${destructiveSteps.length} irreversible step${destructiveSteps.length > 1 ? 's' : ''}`}
                detail={`${destructiveSteps.map((a) => a.label).join(', ')}. Running this cannot be undone from the console.`}
              />
            )}

            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <DialogButton onClick={() => setShowModal(false)}>Cancel</DialogButton>
              <button
                type="submit"
                className="btn-primary"
                disabled={hasStepErrors || formData.nodes.length === 0}
                title={formData.nodes.length === 0
                  ? 'Add at least one step'
                  : hasStepErrors ? 'Fix the highlighted steps first' : undefined}
                style={{ flex: 1 }}
              >
                <Save size={15} /> {editingId ? 'Update' : 'Create'}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {confirmDelete && (
        <Modal
          title={`Delete ${confirmDelete.name || 'this playbook'}?`}
          subtitle="The definition goes. Anything it has already run stays run."
          onClose={() => setConfirmDelete(null)}
          footer={
            <>
              <DialogButton onClick={() => setConfirmDelete(null)}>Cancel</DialogButton>
              <DialogButton
                variant="solid"
                tone="critical"
                onClick={() => handleDeletePlaybook(confirmDelete)}
              >
                Delete
              </DialogButton>
            </>
          }
        >
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            {summarisePlaybook(confirmDelete)}
          </p>
        </Modal>
      )}
    </div>
  );
};

export default Playbooks;
