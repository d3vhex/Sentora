import React, { useState, useEffect, useMemo } from 'react';
import { User, Activity, Globe, Search, Eye } from 'lucide-react';
import { adminService, agentService } from '../services/api';
import { Card, Badge } from '../components/ui';

/** Platform events carry a severity, and a severity is a claim - so it takes
 *  the semantic colours rather than a series palette. */
const SEVERITY_TONE: Record<string, any> = {
  CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'neutral',
};
import { CategoryBars } from '../components/ui/charts';

const chartNote: React.CSSProperties = {
  margin: '0 0 var(--space-3)', color: 'var(--text-muted)',
  fontSize: 'var(--text-xs)', maxWidth: '58ch',
};

const formatTs = (raw: any): string => {
  if (!raw) return '-';
  // OpenSearch indexes use @timestamp; MySQL direct returns `timestamp`.
  // Both can be a string ISO/SQL datetime, occasionally a unix epoch.
  let v = raw;
  if (typeof v === 'number') {
    if (v < 1e12) v = v * 1000; // seconds → ms
    return new Date(v).toLocaleString();
  }
  const d = new Date(typeof v === 'string' ? v.replace(' ', 'T') : v);
  return isNaN(d.getTime()) ? String(raw) : d.toLocaleString();
};

const AuditLogs: React.FC = () => {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selected, setSelected] = useState<any | null>(null);
  /* Attacks on this platform. Separate state from the audit log because it
     answers a different question: that one records what operators did, this
     records what was attempted against them. */
  const [platform, setPlatform] = useState<any[] | null>(null);
  const [decryption, setDecryption] = useState<any | null>(null);

  useEffect(() => {
    fetchLogs();
    adminService.getPlatformEvents(24)
      .then((r) => { setPlatform(r.events || []); setDecryption(r.decryption || null); })
      // A role with manage_users but not manage_system gets 403 here. That is
      // not an error worth showing - the section simply does not apply to
      // them - so it stays hidden rather than rendering a failure.
      .catch(() => setPlatform(null));
  }, []);

  const fetchLogs = (q: string = '*') => {
    setLoading(true);
    agentService.searchLogs({ table: 'audit_logs', q, limit: 100 })
      .then(res => setLogs(res.hits || []))
      .catch(err => {
        console.error(err);
        adminService.getAuditLogs().then(setLogs);
      })
      .finally(() => setLoading(false));
  };

  /* Both derived from the rows already fetched - a chart with its own query
     is a chart that can disagree with the table under it. */
  const _top = (pick: (l: any) => any) => {
    const counts = new Map<string, number>();
    for (const l of logs) {
      const key = String(pick(l) || 'unknown').trim() || 'unknown';
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([name, value]) => ({
        name: name.length > 22 ? name.slice(0, 21) + '…' : name,
        value,
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 6);
  };
  const byAction = useMemo(() => _top((l) => l.action), [logs]);
  const byUser = useMemo(() => _top((l) => l.username), [logs]);

  const handleSearch = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      fetchLogs(searchTerm || '*');
    }
  };

  return (
    <div>
      <div style={{ marginBottom: '32px' }}>
        <h2 style={{ fontSize: '1.875rem', marginBottom: '8px' }}>Action Audit Logs</h2>
        <p style={{ color: 'var(--text-secondary)' }}>Comprehensive history of all administrative actions, resource modifications, and system changes.</p>
      </div>

      {/* The platform watches every host in the fleet, and until recently
          nothing watched the platform. A lockout went to a container log, a
          rejected agent key went to a container log - so the one machine an
          attacker has to get through was the one with no view of its own.

          Shown even when empty, which is a correction of the first version.
          Hiding it read well as an argument - a permanently empty panel is
          furniture people learn to skip - and it recreated the exact failure
          the rest of this work spent its time removing: an operator who never
          sees the panel cannot tell "nothing has attacked us" from "this
          platform does not watch itself". On a security view, a quiet
          twenty-four hours is a finding.

          `null` is the third state and stays hidden: the role cannot read
          this, so it is not an empty result, it is not their question. */}
      {platform !== null && (
        <Card title="Attempts against this platform (24h)">
          <p style={chartNote}>
            Failed logins past the lockout threshold, agent keys this server
            does not recognise, and operators reaching past their role.
            Repeats are folded: one attack is one row whose count climbs, not
            four hundred rows that bury it.
          </p>
          {/* Not an attack, and it belongs on this panel anyway: history
              nobody can decrypt is a fact about the platform. It was counted
              and never shown - one log line per field name, so a table where
              86% of the messages were unreadable produced the same output as
              one bad row. */}
          {!!decryption && decryption.undecryptable > 0 && (
            <p style={{ margin: '0 0 var(--space-3)', padding: 'var(--space-3)',
                        borderRadius: 'var(--radius-md)',
                        border: '1px solid var(--sev-medium)',
                        color: 'var(--text-secondary)', fontSize: 'var(--text-xs)' }}>
              <strong style={{ color: 'var(--sev-medium)' }}>
                {decryption.unreadable_percent}% of encrypted values read since
                this server started could not be decrypted
              </strong>{' '}
              ({decryption.undecryptable} of{' '}
              {decryption.undecryptable + decryption.decrypted}). {decryption.detail}
            </p>
          )}

          {platform.length === 0 ? (
            <p style={{ margin: 0, padding: 'var(--space-4) 0',
                        color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
              Nothing in the last 24 hours. This panel is live — an empty one
              means no attempts were detected, not that nothing is watching.
            </p>
          ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
              <thead>
                <tr style={{ textAlign: 'left', color: 'var(--text-secondary)' }}>
                  <th style={{ padding: '8px 12px' }}>What</th>
                  <th style={{ padding: '8px 12px' }}>Subject</th>
                  <th style={{ padding: '8px 12px' }}>From</th>
                  <th style={{ padding: '8px 12px', textAlign: 'right' }}>Count</th>
                  <th style={{ padding: '8px 12px' }}>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {platform.map((e, i) => (
                  <tr key={i} style={{ borderTop: '1px solid var(--border-color)' }}>
                    <td style={{ padding: '10px 12px' }}>
                      <Badge tone={SEVERITY_TONE[e.severity] ?? 'neutral'}>{e.kind}</Badge>
                      <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)',
                                    marginTop: '4px', maxWidth: '52ch' }}>
                        {e.explanation}
                      </div>
                    </td>
                    <td style={{ padding: '10px 12px' }}>{e.subject || '—'}</td>
                    <td style={{ padding: '10px 12px' }} className="mono">{e.source_ip || '—'}</td>
                    <td style={{ padding: '10px 12px', textAlign: 'right', fontWeight: 700 }}>
                      {e.occurrences}
                    </td>
                    <td style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>
                      {formatTs(e.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          )}
        </Card>
      )}

      {/* An audit log is read after something went wrong, and by then the
          question is never "what happened" but "who was doing what". A
          hundred rows in reverse-chronological order answers the first and
          hides the second. */}
      <div className="responsive-grid" style={{ marginBottom: '24px' }}>
        <Card title="Actions performed">
          <p style={chartNote}>
            What this window is mostly made of. A destructive action appearing
            at all is worth more attention than a common one appearing often.
          </p>
          <CategoryBars data={byAction} height={200} />
        </Card>
        <Card title="Busiest operators">
          <p style={chartNote}>
            Who is making the changes. An account here that nobody is sitting
            at is the finding.
          </p>
          <CategoryBars data={byUser} height={200} />
        </Card>
      </div>

      <div style={{ backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', overflow: 'hidden' }}>
        <div style={{ padding: '20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ fontSize: '1.125rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={20} color="var(--accent-secondary)" />
            Activity History
          </h3>
          <div style={{ position: 'relative' }}>
            <Search size={16} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
            <input
              type="text"
              placeholder="Filter by user, action, or resource..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onKeyDown={handleSearch}
              style={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '6px 12px 6px 32px', fontSize: '0.75rem', color: 'var(--text-primary)', width: '300px' }}
            />
          </div>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ backgroundColor: 'rgba(255,255,255,0.02)', borderBottom: '1px solid var(--border-color)' }}>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>Timestamp</th>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>User</th>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>Action</th>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>Resource</th>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>IP Address</th>
                <th style={{ padding: '12px 20px', fontWeight: 600, color: 'var(--text-secondary)' }}>Details</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log, i) => {
                const ts = formatTs(log.timestamp ?? log['@timestamp']);
                const resource = String(log.resource ?? '-');
                const details = String(log.details ?? '');
                return (
                  <tr key={log.id || i} style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <td style={{ padding: '14px 20px', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>{ts}</td>
                    <td style={{ padding: '14px 20px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <div style={{ width: '24px', height: '24px', borderRadius: '50%', backgroundColor: 'rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <User size={12} />
                        </div>
                        <span style={{ fontWeight: 600 }}>{log.username || '-'}</span>
                      </div>
                    </td>
                    <td style={{ padding: '14px 20px' }}>
                      <span style={{
                        padding: '4px 8px',
                        borderRadius: '6px',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        color: '#60a5fa',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        whiteSpace: 'nowrap',
                      }}>{log.action || '-'}</span>
                    </td>
                    <td
                      style={{ padding: '14px 20px', fontWeight: 500, fontFamily: 'monospace', cursor: 'pointer', color: resource !== '-' ? 'var(--text-primary)' : 'var(--text-secondary)' }}
                      title={resource}
                      onClick={() => setSelected(log)}
                    >
                      {resource.length > 32 ? resource.slice(0, 32) + '…' : resource}
                    </td>
                    <td style={{ padding: '14px 20px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <Globe size={14} style={{ opacity: 0.5 }} />
                        {log.ip_address || '-'}
                      </div>
                    </td>
                    <td style={{ padding: '14px 20px' }}>
                      <button
                        onClick={() => setSelected(log)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px',
                          padding: '6px 10px',
                          borderRadius: '6px',
                          backgroundColor: 'rgba(255,255,255,0.04)',
                          border: '1px solid var(--border-color)',
                          color: 'var(--text-secondary)',
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          maxWidth: '260px',
                        }}
                        title={details || 'View full record'}
                      >
                        <Eye size={12} style={{ flexShrink: 0 }} />
                        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {details ? (details.length > 40 ? details.slice(0, 40) + '…' : details) : 'View'}
                        </span>
                      </button>
                    </td>
                  </tr>
                );
              })}
              {logs.length === 0 && !loading && (
                <tr><td colSpan={6} style={{ padding: '60px', textAlign: 'center', color: 'var(--text-secondary)' }}>No activity logs found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (
        <AuditDetailModal log={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
};

const AuditDetailModal: React.FC<{ log: any, onClose: () => void }> = ({ log, onClose }) => {
  const ts = formatTs(log.timestamp ?? log['@timestamp']);
  const fields: Array<[string, any]> = [
    ['Timestamp', ts],
    ['User', log.username ?? '-'],
    ['User ID', log.user_id ?? '-'],
    ['Action', log.action ?? '-'],
    ['Resource', log.resource ?? '-'],
    ['IP Address', log.ip_address ?? '-'],
    ['Details', log.details ?? ''],
  ];
  // Surface any extra columns (e.g. fields added later) without losing them.
  const known = new Set(['id', 'timestamp', '@timestamp', 'username', 'user_id', 'action', 'resource', 'ip_address', 'details']);
  const extras = Object.entries(log).filter(([k]) => !known.has(k));

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.7)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 9999, padding: '24px',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: 'min(720px, 100%)', maxHeight: '80vh',
          display: 'flex', flexDirection: 'column',
          backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', overflow: 'hidden',
        }}
      >
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '0.95rem', fontWeight: 700 }}>Audit Log Detail</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{ts}</div>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', fontSize: '1.5rem', cursor: 'pointer', lineHeight: 1 }}>×</button>
        </div>
        <div style={{ padding: '16px 20px', overflowY: 'auto', flex: 1 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
            <tbody>
              {fields.map(([label, value]) => (
                <tr key={label} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '10px 0', color: 'var(--text-secondary)', fontWeight: 600, width: '140px', verticalAlign: 'top' }}>{label}</td>
                  <td style={{ padding: '10px 0', fontFamily: label === 'Resource' ? 'monospace' : 'inherit', wordBreak: 'break-all' }}>
                    {value === '' || value == null ? <span style={{ color: 'var(--text-secondary)' }}>—</span> : String(value)}
                  </td>
                </tr>
              ))}
              {extras.length > 0 && (
                <tr>
                  <td colSpan={2} style={{ padding: '14px 0 6px', fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700 }}>Other</td>
                </tr>
              )}
              {extras.map(([k, v]) => (
                <tr key={k} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '10px 0', color: 'var(--text-secondary)', fontWeight: 600, width: '140px', verticalAlign: 'top' }}>{k}</td>
                  <td style={{ padding: '10px 0', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    {typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default AuditLogs;
