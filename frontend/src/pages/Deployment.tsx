import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  Info,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  KeyRound,
  Trash2,
  RefreshCw
} from 'lucide-react';

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

  const [hostnameHint, setHostnameHint] = useState('');
  const [note, setNote] = useState('');
  const [ttlHours, setTtlHours] = useState<number>(24);
  const [generating, setGenerating] = useState(false);
  const [lastToken, setLastToken] = useState<EnrollResponse | null>(null);

  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [loadingList, setLoadingList] = useState(false);

  const authHeaders = (): Record<string, string> => {
    const userId = localStorage.getItem('userId') || '0';
    return { 'X-User-ID': userId, 'Content-Type': 'application/json' };
  };

  // These calls use raw fetch rather than the shared axios client, so they
  // need the session cookie opted in explicitly. Without it the requests are
  // anonymous and the server 401s them.
  const authFetch = (url: string, init: RequestInit = {}) =>
    fetch(url, { ...init, credentials: 'include', headers: authHeaders() });

  const loadEnrollments = async () => {
    setLoadingList(true);
    try {
      const r = await authFetch(`${API_BASE_URL}/api/agents/enrollments`);
      const data = await r.json();
      if (r.ok && data.status === 'success') {
        setEnrollments(data.enrollments || []);
      }
    } catch (e) {
      console.error('Failed to load enrollments', e);
    } finally {
      setLoadingList(false);
    }
  };

  useEffect(() => {
    loadEnrollments();
  }, []);

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
      const data = await r.json();
      if (!r.ok || data.status !== 'success') {
        alert(data.message || 'Failed to create enrollment token');
        return;
      }
      setLastToken(data);
      setHostnameHint('');
      setNote('');
      loadEnrollments();
    } catch (e: any) {
      alert(`Error: ${e.message || e}`);
    } finally {
      setGenerating(false);
    }
  };

  const revokeToken = async (id: number) => {
    if (!confirm('Revoke this enrollment token?')) return;
    try {
      const r = await authFetch(`${API_BASE_URL}/api/agents/enrollments/${id}`, {
        method: 'DELETE',
      });
      if (r.ok) loadEnrollments();
      else {
        const data = await r.json().catch(() => ({}));
        alert(data.message || 'Failed to revoke');
      }
    } catch (e: any) {
      alert(`Error: ${e.message || e}`);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div style={{ maxWidth: '1100px', margin: '0 auto', padding: '20px' }}>
      {/* Header */}
      <div
        style={{
          backgroundColor: 'var(--card-bg)',
          borderRadius: '16px',
          padding: '32px',
          border: '1px solid var(--border-color)',
          marginBottom: '24px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '24px' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-secondary)',
            }}
          >
            <KeyRound size={24} />
          </div>
          <div>
            <h2 style={{ fontSize: '1.5rem', marginBottom: '4px' }}>Enroll New Agent</h2>
            <p style={{ color: 'var(--text-secondary)' }}>
              Generate a one-time enrollment token; each endpoint gets its own per-agent key.
            </p>
          </div>
        </div>

        <div
          style={{
            backgroundColor: 'rgba(59, 130, 246, 0.05)',
            border: '1px solid rgba(59, 130, 246, 0.2)',
            borderRadius: '12px',
            padding: '16px',
            display: 'flex',
            gap: '12px',
            marginBottom: '24px',
          }}
        >
          <Info size={20} color="#3b82f6" style={{ flexShrink: 0, marginTop: '2px' }} />
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            Tokens are <strong>single-use</strong> and expire. On first boot the installer exchanges the
            token for a unique <code>agent_key</code>, writes an identity config, and registers the
            service. Revoke an agent by deleting its key from the list below.
          </p>
        </div>

        {/* Token generation form */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '12px',
            marginBottom: '16px',
          }}
        >
          <input
            type="text"
            placeholder="Hostname hint (optional)"
            value={hostnameHint}
            onChange={(e) => setHostnameHint(e.target.value)}
            style={inputStyle}
          />
          <input
            type="text"
            placeholder="Note (optional)"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            style={inputStyle}
          />
          <input
            type="number"
            min={1}
            max={720}
            value={ttlHours}
            onChange={(e) => setTtlHours(parseInt(e.target.value || '24', 10))}
            placeholder="TTL (hours)"
            style={inputStyle}
          />
          <button
            onClick={generateToken}
            disabled={generating}
            style={{
              backgroundColor: 'var(--accent-secondary)',
              color: 'white',
              padding: '10px 16px',
              borderRadius: '8px',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              opacity: generating ? 0.6 : 1,
              cursor: generating ? 'not-allowed' : 'pointer',
            }}
          >
            <KeyRound size={16} /> {generating ? 'Generating…' : 'Generate Enrollment Token'}
          </button>
        </div>

        {/* Last generated token panel */}
        {lastToken && (
          <div
            style={{
              backgroundColor: 'var(--bg-color)',
              borderRadius: '12px',
              border: '1px solid rgba(16, 185, 129, 0.35)',
              padding: '20px',
              marginTop: '8px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <CheckCircle2 size={18} color="#10b981" />
              <strong>Token ready · expires {lastToken.expires_at}</strong>
            </div>
            <OneLinerBlock
              label="Linux (Bash)"
              color="#10b981"
              id="linux-new"
              text={lastToken.install.linux}
              copied={copied}
              onCopy={copyToClipboard}
            />
            <div style={{ height: 12 }} />
            <OneLinerBlock
              label="Windows (PowerShell)"
              color="#00a4ef"
              id="win-new"
              text={lastToken.install.windows}
              copied={copied}
              onCopy={copyToClipboard}
            />
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '10px' }}>
              The raw token is only visible here — copy the command now, it will not be shown again.
            </p>
          </div>
        )}
      </div>

      {/* Enrollments list */}
      <div
        style={{
          backgroundColor: 'var(--card-bg)',
          borderRadius: '16px',
          padding: '24px',
          border: '1px solid var(--border-color)',
          marginBottom: '24px',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '16px',
          }}
        >
          <h3 style={{ fontSize: '1.125rem', fontWeight: 700 }}>Recent Enrollments</h3>
          <button
            onClick={loadEnrollments}
            disabled={loadingList}
            style={{
              color: 'var(--accent-secondary)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.8125rem',
              fontWeight: 600,
              background: 'rgba(96, 165, 250, 0.1)',
              padding: '6px 12px',
              borderRadius: '6px',
            }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
        {enrollments.length === 0 ? (
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            No enrollment tokens yet.
          </p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', fontSize: '0.875rem', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ textAlign: 'left', color: 'var(--text-secondary)' }}>
                  <th style={thStyle}>Token</th>
                  <th style={thStyle}>Hint</th>
                  <th style={thStyle}>Created</th>
                  <th style={thStyle}>Expires</th>
                  <th style={thStyle}>Status</th>
                  <th style={thStyle}></th>
                </tr>
              </thead>
              <tbody>
                {enrollments.map((e) => {
                  const used = !!e.used_at;
                  const expired =
                    !used && e.expires_at && new Date(e.expires_at) < new Date();
                  return (
                    <tr key={e.id} style={{ borderTop: '1px solid var(--border-color)' }}>
                      <td style={tdStyle}>
                        <code style={{ fontSize: '0.8em' }}>{e.token_preview}</code>
                      </td>
                      <td style={tdStyle}>{e.hostname_hint || '—'}</td>
                      <td style={tdStyle}>{e.created_at}</td>
                      <td style={tdStyle}>{e.expires_at}</td>
                      <td style={tdStyle}>
                        {used ? (
                          <span style={{ color: '#10b981' }}>
                            Used → {e.used_by_agent}
                          </span>
                        ) : expired ? (
                          <span style={{ color: '#f59e0b' }}>Expired</span>
                        ) : (
                          <span style={{ color: 'var(--accent-secondary)' }}>Pending</span>
                        )}
                      </td>
                      <td style={tdStyle}>
                        {!used && (
                          <button
                            onClick={() => revokeToken(e.id)}
                            title="Revoke"
                            style={{
                              color: '#ef4444',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                              fontSize: '0.8125rem',
                              background: 'rgba(239, 68, 68, 0.1)',
                              padding: '4px 10px',
                              borderRadius: '6px',
                            }}
                          >
                            <Trash2 size={14} /> Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
          gap: '16px',
        }}
      >
        <FeatureCard
          icon={<ShieldCheck size={20} color="var(--accent-secondary)" />}
          title="Per-Agent Keys"
          text="Each endpoint enrolls with a unique key — revoke a single agent without affecting others."
        />
        <FeatureCard
          icon={<KeyRound size={20} color="var(--accent-secondary)" />}
          title="One-Time Tokens"
          text="Enrollment tokens burn on first use and expire automatically."
        />
        <FeatureCard
          icon={<AlertCircle size={20} color="var(--accent-secondary)" />}
          title="Audit Trail"
          text="Every token issuance and agent registration is logged to audit_logs."
        />
      </div>
    </div>
  );
};

const OneLinerBlock: React.FC<{
  label: string;
  color: string;
  id: string;
  text: string;
  copied: string | null;
  onCopy: (text: string, id: string) => void;
}> = ({ label, color, id, text, copied, onCopy }) => (
  <div>
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '8px',
      }}
    >
      <span
        style={{
          fontSize: '0.75rem',
          fontWeight: 700,
          color: 'var(--text-secondary)',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
        }}
      >
        {label}
      </span>
      <button
        onClick={() => onCopy(text, id)}
        style={{
          color: 'var(--accent-secondary)',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: '0.75rem',
          fontWeight: 700,
          background: 'rgba(96, 165, 250, 0.1)',
          padding: '4px 10px',
          borderRadius: '6px',
        }}
      >
        {copied === id ? <Check size={14} /> : <Copy size={14} />}
        {copied === id ? 'Copied' : 'Copy'}
      </button>
    </div>
    <code
      style={{
        display: 'block',
        backgroundColor: '#000',
        color,
        padding: '14px',
        borderRadius: '8px',
        fontSize: '0.8125rem',
        overflowX: 'auto',
        whiteSpace: 'pre',
        fontFamily: 'Fira Code, monospace',
      }}
    >
      {text}
    </code>
  </div>
);

const FeatureCard: React.FC<{ icon: React.ReactNode; title: string; text: string }> = ({
  icon,
  title,
  text,
}) => (
  <div
    style={{
      backgroundColor: 'var(--card-bg)',
      padding: '20px',
      borderRadius: '12px',
      border: '1px solid var(--border-color)',
      display: 'flex',
      flexDirection: 'column',
      gap: '10px',
    }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
      {icon}
      <h4 style={{ fontSize: '1rem', fontWeight: 600 }}>{title}</h4>
    </div>
    <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{text}</p>
  </div>
);

const inputStyle: React.CSSProperties = {
  padding: '10px 12px',
  borderRadius: '8px',
  border: '1px solid var(--border-color)',
  backgroundColor: 'var(--bg-color)',
  color: 'var(--text-primary)',
  fontSize: '0.875rem',
};

const thStyle: React.CSSProperties = {
  padding: '8px 10px',
  fontSize: '0.75rem',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  fontWeight: 700,
};

const tdStyle: React.CSSProperties = {
  padding: '10px',
  verticalAlign: 'middle',
};

export default Deployment;
