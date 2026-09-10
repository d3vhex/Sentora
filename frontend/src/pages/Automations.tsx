/**
 * Response actions: what was run on a host, and what happened.
 *
 * Both loaders here had no failure branch - `getAgents()` and
 * `getAutomations()` were `.then(setState)` with nothing after them. A request
 * that failed left the agent dropdown empty, which disables the New button,
 * which is indistinguishable from an estate with no agents in it.
 *
 * `StatusBadge` was a fourth private copy of the severity-to-colour mapping,
 * with its own greens and reds. It is the shared `Badge` now, so `failed` here
 * is the same red as `critical` everywhere else.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  Zap, Clock, Terminal, Plus, Edit2, Trash2, Save, RefreshCw,
} from 'lucide-react';
import { agentService } from '../services/api';
import {
  PageHeader, Card, Badge, DataTable, Row, Cell, Tone,
  EmptyState, ErrorState, LoadingState, Modal, Field, DialogButton,
} from '../components/ui';

const ACTIONS = [
  ['block_ip', 'Block IP address'],
  ['unblock_ip', 'Unblock IP address'],
  ['disable_user', 'Disable user account'],
  ['enable_user', 'Enable user account'],
  ['quarantine_file', 'Quarantine file'],
  ['delete_file', 'Delete file'],
  ['kill_process', 'Kill process'],
  ['suspend_process', 'Suspend process'],
  ['delete_registry_key', 'Delete registry key'],
  ['protect_shadows', 'Protect volume shadows'],
  ['restart_service', 'Restart service'],
  ['isolate_host', 'Isolate host'],
  ['lock_machine', 'Lock machine'],
  ['tail_log', 'Tail log file'],
  ['run_cmd', 'Run custom command'],
] as const;

/** One mapping, shared with every other page through `Badge`. */
const STATUS_TONE: Record<string, Tone> = {
  completed: 'ok', success: 'ok',
  failed: 'critical',
  active: 'medium', pending: 'medium',
  cancelled: 'neutral', paused: 'neutral',
};

const FILTERS = [
  ['all', 'All'],
  ['active', 'Running'],
  ['completed', 'Done'],
  ['failed', 'Failed'],
] as const;

/** The target arrives as a JSON array for some actions and a bare string for
 *  others, and rendering the raw `["1.2.3.4"]` was leaking that detail. */
function targetText(raw: unknown): string {
  if (Array.isArray(raw)) return raw.join(' ');
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      try {
        const arr = JSON.parse(trimmed);
        if (Array.isArray(arr)) return arr.join(' ');
      } catch {
        /* not JSON after all; show it as written */
      }
    }
    return raw;
  }
  return String(raw ?? '');
}

const Automations: React.FC = () => {
  const [agents, setAgents] = useState<string[]>([]);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [automations, setAutomations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>('all');

  const [showModal, setShowModal] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
  const [formData, setFormData] = useState({
    action: 'block_ip', target: '', comment: '', event_id: '',
  });

  const say = (err: any, fallback: string) =>
    err?.response?.data?.error || err?.response?.data?.message || err?.message || fallback;

  useEffect(() => {
    agentService.getAgents()
      .then((list: any[]) => {
        const names = list.map((a) => (typeof a === 'string' ? a : a.name));
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
      setAutomations(await agentService.getAutomations(selectedAgent));
      setError(null);
    } catch (err) {
      setError(say(err, `Could not read automations for ${selectedAgent}`));
    } finally {
      setLoading(false);
    }
  }, [selectedAgent]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const openCreate = () => {
    setEditingId(null);
    setFormData({ action: 'block_ip', target: '', comment: 'Manual SOAR trigger', event_id: '' });
    setShowModal(true);
  };

  const openEdit = (auto: any) => {
    setEditingId(auto.id);
    setFormData({
      action: auto.action,
      target: targetText(auto.target),
      comment: auto.comment || '',
      event_id: auto.event_id?.toString() || '',
    });
    setShowModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAgent) return;
    const payload = {
      ...formData,
      event_id: formData.event_id ? parseInt(formData.event_id, 10) : null,
    };
    try {
      if (editingId) {
        await agentService.updateAutomation(selectedAgent, editingId, payload);
      } else {
        await agentService.createAutomation(selectedAgent, payload);
      }
      setShowModal(false);
      fetchData();
    } catch (err) {
      alert(say(err, 'Failed to save automation'));
    }
  };

  const handleDelete = async (id: number) => {
    setConfirmDelete(null);
    if (!selectedAgent) return;
    try {
      await agentService.deleteAutomation(selectedAgent, id);
      fetchData();
    } catch (err) {
      alert(say(err, 'Failed to delete automation'));
    }
  };

  const visible = automations.filter((a) => {
    const status = (a.status || '').toLowerCase();
    if (filter === 'active') return status === 'active' || status === 'pending';
    if (filter === 'completed') return status === 'completed' || status === 'success';
    if (filter === 'failed') return status === 'failed';
    return true;
  });

  const body = () => {
    if (loading) return <LoadingState label="Reading response history…" />;
    if (agents.length === 0) {
      return (
        <EmptyState
          title="No agents"
          detail="Response actions run on a host. Enrol one first."
        />
      );
    }
    if (visible.length === 0) {
      return (
        <EmptyState
          title={filter === 'all' ? 'Nothing has been run on this host' : `No ${filter} actions`}
          detail={filter === 'all'
            ? 'Response actions appear here whether a playbook or a person started them.'
            : 'Try the All filter.'}
          icon={<Zap size={18} style={{ color: 'var(--text-muted)' }} />}
        />
      );
    }
    return (
      <DataTable columns={['When', 'Action', 'Target', 'Status', 'Reason', '']}>
        {visible.map((auto) => {
          const status = (auto.status || 'pending').toLowerCase();
          const failed = status === 'failed';
          const reason = (auto.last_error || auto.error || auto.comment || '').toString().trim();
          return (
            <Row key={auto.id}>
              <Cell>
                <div>#{auto.id}</div>
                <div
                  style={{
                    display: 'flex', alignItems: 'center', gap: 'var(--space-1)',
                    marginTop: 'var(--space-1)', color: 'var(--text-muted)',
                    fontSize: 'var(--text-xs)',
                  }}
                >
                  <Clock size={11} /> {auto.timestamp}
                </div>
              </Cell>
              <Cell>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <Terminal size={14} style={{ color: 'var(--text-muted)' }} />
                  {auto.action}
                </span>
              </Cell>
              <Cell mono>
                <span style={{ wordBreak: 'break-word', overflowWrap: 'anywhere' }}>
                  {targetText(auto.target)}
                </span>
              </Cell>
              <Cell>
                <Badge tone={STATUS_TONE[status] ?? 'neutral'}>{status}</Badge>
              </Cell>
              <Cell>
                <span
                  style={{
                    color: failed ? 'var(--accent-color)' : 'var(--text-secondary)',
                    wordBreak: 'break-word', overflowWrap: 'anywhere',
                  }}
                >
                  {reason || '—'}
                </span>
              </Cell>
              <Cell align="right">
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)' }}>
                  <button className="icon-btn" title="Edit" onClick={() => openEdit(auto)}>
                    <Edit2 size={15} />
                  </button>
                  <button
                    className="icon-btn"
                    title="Delete"
                    onClick={() => setConfirmDelete(auto.id)}
                    style={{ color: 'var(--accent-color)' }}
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              </Cell>
            </Row>
          );
        })}
      </DataTable>
    );
  };

  return (
    <div>
      <PageHeader
        title="Response Actions"
        subtitle="What has been run on a host to contain something, and whether it worked."
        icon={<Zap size={22} />}
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
            <button className="btn-primary" onClick={openCreate} disabled={!selectedAgent}>
              <Plus size={15} /> New action
            </button>
          </>
        }
      />

      {error && (
        <div style={{ marginBottom: 'var(--space-5)' }}>
          <ErrorState title="Request failed" detail={error} />
        </div>
      )}

      <Card
        actions={
          <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
            {FILTERS.map(([key, label]) => (
              <button
                key={key}
                className={filter === key ? 'btn-primary' : 'btn-secondary'}
                onClick={() => setFilter(key)}
              >
                {label}
              </button>
            ))}
            <button className="icon-btn" title="Refresh" onClick={fetchData}>
              <RefreshCw size={15} className={loading ? 'animate-spin' : undefined} />
            </button>
          </div>
        }
      >
        {body()}
      </Card>

      {showModal && (
        <Modal
          title={editingId ? 'Edit action' : 'New response action'}
          subtitle={editingId
            ? undefined
            : `This runs on ${selectedAgent} as soon as you submit it.`}
          onClose={() => setShowModal(false)}
          width={500}
        >
          <form
            onSubmit={handleSubmit}
            style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}
          >
            <Field label="Action">
              <select
                value={formData.action}
                onChange={(e) => setFormData({ ...formData, action: e.target.value })}
              >
                {ACTIONS.map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
            </Field>
            <Field label="Target" hint="An address, a path, a PID or a service name, depending on the action.">
              <input
                value={formData.target}
                onChange={(e) => setFormData({ ...formData, target: e.target.value })}
                required
                placeholder="192.168.1.100"
                autoFocus
              />
            </Field>
            <Field label="Reason" hint="Why this was run. It is the only record once the action has finished.">
              <input
                value={formData.comment}
                onChange={(e) => setFormData({ ...formData, comment: e.target.value })}
              />
            </Field>
            <Field label="Linked event" hint="Optional. The SIEM event this responds to.">
              <input
                type="number"
                value={formData.event_id}
                onChange={(e) => setFormData({ ...formData, event_id: e.target.value })}
                placeholder="Event id"
              />
            </Field>
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <DialogButton onClick={() => setShowModal(false)}>Cancel</DialogButton>
              <DialogButton type="submit" variant="solid">
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <Save size={15} /> {editingId ? 'Update' : 'Run now'}
                </span>
              </DialogButton>
            </div>
          </form>
        </Modal>
      )}

      {confirmDelete !== null && (
        <Modal
          title="Delete this record?"
          subtitle="It removes the history, not the effect. An action that already ran stays run."
          onClose={() => setConfirmDelete(null)}
          footer={
            <>
              <DialogButton onClick={() => setConfirmDelete(null)}>Cancel</DialogButton>
              <DialogButton
                variant="solid"
                tone="critical"
                onClick={() => handleDelete(confirmDelete)}
              >
                Delete
              </DialogButton>
            </>
          }
        >
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            If you meant to reverse it, run the opposite action instead — unblock, enable,
            or restart.
          </p>
        </Modal>
      )}
    </div>
  );
};

export default Automations;
