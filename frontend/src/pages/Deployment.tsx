/**
 * Enrolling an endpoint: a one-time token, and the command that consumes it.
 *
 * Two things here were quietly wrong.
 *
 * `loadEnrollments` checked `if (r.ok && data.status === 'success')` and had
 * no else. A 401, a 500 and an empty estate all rendered "No enrollment tokens
 * yet." - so a token you had just issued could appear not to exist, and the
 * natural response is to issue another.
 *
 * And the copy button called `navigator.clipboard.writeText` without checking
 * whether it worked. That API only exists in a secure context, so on a
 * deployment reached over plain http it is `undefined` - the copy did nothing
 * and the button still said "Copied". On this page in particular that loses
 * the token: the panel says, correctly, that the raw value is shown once and
 * never again. It now reports the failure and leaves the text selectable.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  ShieldCheck, Info, CheckCircle2, Copy, Check, KeyRound, Trash2, RefreshCw,
} from 'lucide-react';
import {
  PageHeader, Card, Badge, DataTable, Row, Cell, Field,
  EmptyState, ErrorState, LoadingState, Modal, DialogButton,
} from '../components/ui';

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  (import.meta.env.DEV ? 'http://127.0.0.1:8000' : window.location.origin);

type Enrollment = {
  id: number;
  token_preview: string;
  created_by_username: string | null;
  hostname_hint: string | null;
  note: string | null;
  created_at: string;
  expires_at: string;
  used_at: string | null;
  used_by_agent: string | null;
  used_from_ip: string | null;
};

type EnrollResponse = {
  status: string;
  token: string;
  expires_at: string;
  server_url: string;
  install: { linux: string; windows: string };
};

const Deployment: React.FC = () => {
  const [copied, setCopied] = useState<string | null>(null);
  const [copyFailed, setCopyFailed] = useState<string | null>(null);

  const [hostnameHint, setHostnameHint] = useState('');
  const [note, setNote] = useState('');
  const [ttlHours, setTtlHours] = useState<number>(24);
  const [generating, setGenerating] = useState(false);
  const [lastToken, setLastToken] = useState<EnrollResponse | null>(null);

  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [loadingList, setLoadingList] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<Enrollment | null>(null);

  const authHeaders = (): Record<string, string> => ({
    'X-User-ID': localStorage.getItem('userId') || '0',
    'Content-Type': 'application/json',
  });

  // These calls use raw fetch rather than the shared axios client, so they
  // need the session cookie opted in explicitly. Without it the requests are
  // anonymous and the server 401s them.
  const authFetch = (url: string, init: RequestInit = {}) =>
    fetch(url, { ...init, credentials: 'include', headers: authHeaders() });

  const loadEnrollments = useCallback(async () => {
    setLoadingList(true);
    try {
      const r = await authFetch(`${API_BASE_URL}/api/agents/enrollments`);
      const data = await r.json().catch(() => ({}));
      if (!r.ok || data.status !== 'success') {
        // Previously this branch did not exist, so a rejected request left the
        // list empty and the page said there were no tokens.
        setError(data.message || `The server answered ${r.status} — the list below is unknown, not empty.`);
        return;
      }
      setEnrollments(data.enrollments || []);
      setError(null);
    } catch (e: any) {
      setError(e?.message || 'Could not reach the server');
    } finally {
      setLoadingList(false);
    }
  }, []);

  useEffect(() => { loadEnrollments(); }, [loadEnrollments]);

  const generateToken = async () => {
    setGenerating(true);
    setLastToken(null);
    try {
      const r = await authFetch(`${API_BASE_URL}/api/agents/enroll`, {
        method: 'POST',
        body: JSON.stringify({
          hostname_hint: hostnameHint || undefined,
          note: note || undefined,
          ttl_hours: ttlHours,
        }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok || data.status !== 'success') {
        setError(data.message || `Could not create a token (${r.status})`);
        return;
      }
      setLastToken(data);
      setHostnameHint('');
      setNote('');
      setError(null);
      loadEnrollments();
    } catch (e: any) {
      setError(e?.message || 'Could not create a token');
    } finally {
      setGenerating(false);
    }
  };

  const revokeToken = async (row: Enrollment) => {
    setConfirmRevoke(null);
    try {
      const r = await authFetch(`${API_BASE_URL}/api/agents/enrollments/${row.id}`, {
        method: 'DELETE',
      });
      if (r.ok) { loadEnrollments(); return; }
      const data = await r.json().catch(() => ({}));
      setError(data.message || `Could not revoke token ${row.token_preview}`);
    } catch (e: any) {
      setError(e?.message || 'Could not revoke the token');
    }
  };

  /** Reports failure instead of claiming success.
   *
   * `navigator.clipboard` is only defined in a secure context. Over plain http
   * — which is how a first deployment is usually reached — the old code threw
   * inside an unawaited promise and the button still said "Copied". */
  const copyToClipboard = async (text: string, id: string) => {
    setCopyFailed(null);
    try {
      if (!navigator.clipboard) throw new Error('no clipboard in this context');
      await navigator.clipboard.writeText(text);
      setCopied(id);
      setTimeout(() => setCopied(null), 2000);
    } catch {
      setCopyFailed(id);
    }
  };

  const statusOf = (e: Enrollment) => {
    if (e.used_at) return { tone: 'ok' as const, label: `used → ${e.used_by_agent}` };
    if (e.expires_at && new Date(e.expires_at) < new Date()) {
      return { tone: 'medium' as const, label: 'expired' };
    }
    return { tone: 'info' as const, label: 'pending' };
  };

  const list = () => {
    if (loadingList && enrollments.length === 0) return <LoadingState label="Reading tokens…" />;
    if (enrollments.length === 0) {
      return (
        <EmptyState
          title="No enrolment tokens"
          detail="Generate one above, then run the command it produces on the endpoint."
        />
      );
    }
    return (
      <DataTable columns={['Token', 'Hint', 'Created', 'Expires', 'Status', '']}>
        {enrollments.map((e) => {
          const status = statusOf(e);
          return (
            <Row key={e.id}>
              <Cell mono>{e.token_preview}</Cell>
              <Cell>{e.hostname_hint || '—'}</Cell>
              <Cell mono>{e.created_at}</Cell>
              <Cell mono>{e.expires_at}</Cell>
              <Cell><Badge tone={status.tone}>{status.label}</Badge></Cell>
              <Cell align="right">
                {!e.used_at && (
                  <button
                    className="icon-btn"
                    title="Revoke"
                    onClick={() => setConfirmRevoke(e)}
                    style={{ color: 'var(--accent-color)' }}
                  >
                    <Trash2 size={15} />
                  </button>
                )}
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
        title="Enrol an Endpoint"
        subtitle="A single-use token that the installer exchanges for this host's own key. Revoking one agent leaves the rest alone."
        icon={<KeyRound size={22} />}
        actions={
          <button className="btn-secondary" onClick={loadEnrollments} disabled={loadingList}>
            <RefreshCw size={15} className={loadingList ? 'animate-spin' : undefined} /> Refresh
          </button>
        }
      />

      {error && (
        <div style={{ marginBottom: 'var(--space-5)' }}>
          <ErrorState title="Enrolment request failed" detail={error} />
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
        <Card title="New token">
          <div
            style={{
              display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-start',
              marginBottom: 'var(--space-4)',
            }}
          >
            <Info size={16} style={{ color: 'var(--text-muted)', flexShrink: 0, marginTop: 2 }} />
            <p
              style={{
                margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)',
                lineHeight: 1.6, maxWidth: '78ch',
              }}
            >
              The token burns on first use and expires on its own. On first boot the installer
              trades it for a unique <code>agent_key</code>, writes an identity config and
              registers the service. Every issuance and registration is written to{' '}
              <code>audit_logs</code>.
            </p>
          </div>

          <div className="responsive-grid" style={{ alignItems: 'end' }}>
            <Field label="Hostname hint" hint="Optional. Which machine you mean this for.">
              <input value={hostnameHint} onChange={(e) => setHostnameHint(e.target.value)} />
            </Field>
            <Field label="Note" hint="Optional. Why it was issued.">
              <input value={note} onChange={(e) => setNote(e.target.value)} />
            </Field>
            <Field label="Valid for (hours)">
              <input
                type="number"
                min={1}
                max={720}
                value={ttlHours}
                onChange={(e) => setTtlHours(parseInt(e.target.value || '24', 10))}
              />
            </Field>
            <button className="btn-primary" onClick={generateToken} disabled={generating}>
              <KeyRound size={15} /> {generating ? 'Generating…' : 'Generate token'}
            </button>
          </div>

          {lastToken && (
            <div
              style={{
                marginTop: 'var(--space-5)', paddingTop: 'var(--space-4)',
                borderTop: '1px solid var(--border-color)',
              }}
            >
              <div
                style={{
                  display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                  marginBottom: 'var(--space-3)', fontSize: 'var(--text-sm)',
                }}
              >
                <CheckCircle2 size={16} style={{ color: 'var(--accent-success)' }} />
                Token ready — expires {lastToken.expires_at}
              </div>

              {(['linux', 'windows'] as const).map((os) => (
                <div key={os} style={{ marginBottom: 'var(--space-4)' }}>
                  <div
                    style={{
                      display: 'flex', justifyContent: 'space-between',
                      alignItems: 'center', marginBottom: 'var(--space-2)',
                    }}
                  >
                    <span
                      style={{
                        fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
                        textTransform: 'uppercase', letterSpacing: '0.04em',
                      }}
                    >
                      {os === 'linux' ? 'Linux (bash)' : 'Windows (PowerShell)'}
                    </span>
                    <button
                      className="btn-secondary"
                      onClick={() => copyToClipboard(lastToken.install[os], os)}
                    >
                      {copied === os ? <Check size={14} /> : <Copy size={14} />}
                      {copied === os ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <code
                    className="mono"
                    style={{
                      display: 'block', padding: 'var(--space-3)',
                      background: 'var(--bg-color)',
                      border: '1px solid var(--border-color)',
                      borderRadius: 'var(--radius-md)',
                      fontSize: 'var(--text-xs)',
                      overflowX: 'auto', whiteSpace: 'pre',
                      userSelect: 'all',
                    }}
                  >
                    {lastToken.install[os]}
                  </code>
                  {copyFailed === os && (
                    <p style={{ margin: 'var(--space-2) 0 0', fontSize: 'var(--text-xs)', color: 'var(--accent-color)' }}>
                      The browser refused clipboard access — that API needs https or localhost.
                      Select the command above and copy it by hand; it is not shown again.
                    </p>
                  )}
                </div>
              ))}

              <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                The raw token appears here once. Leaving this page discards it and you will need
                a new one.
              </p>
            </div>
          )}
        </Card>

        <Card title="Tokens issued">{list()}</Card>
      </div>

      {confirmRevoke && (
        <Modal
          title="Revoke this token?"
          subtitle={`${confirmRevoke.token_preview} can no longer be used to enrol.`}
          onClose={() => setConfirmRevoke(null)}
          footer={
            <>
              <DialogButton onClick={() => setConfirmRevoke(null)}>Cancel</DialogButton>
              <DialogButton
                variant="solid"
                tone="critical"
                onClick={() => revokeToken(confirmRevoke)}
              >
                Revoke
              </DialogButton>
            </>
          }
        >
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            <ShieldCheck size={14} style={{ verticalAlign: 'text-bottom' }} /> Agents already
            enrolled keep working — they hold their own keys, not this token.
          </p>
        </Modal>
      )}
    </div>
  );
};

export default Deployment;
