import React, { useEffect, useState } from 'react';
import { ShieldCheck, ShieldOff, KeyRound, Copy, Check, AlertTriangle } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { authService } from '../services/api';
import { Card, PageHeader } from '../components/ui';

/** Every operator can reach this, whatever their role.
 *
 *  Two-factor protects the account, not the tenancy - a role that can do
 *  nothing else must still be able to secure its own login. That is why the
 *  four endpoints behind this page are session-only rather than
 *  permission-gated.
 */
const note: React.CSSProperties = {
  margin: '0 0 var(--space-3)', color: 'var(--text-secondary)',
  fontSize: 'var(--text-sm)', maxWidth: '62ch', lineHeight: 1.5,
};

const mono: React.CSSProperties = {
  fontFamily: 'monospace', fontSize: 'var(--text-sm)',
  background: 'var(--surface-2)', border: '1px solid var(--border-color)',
  borderRadius: 'var(--radius-md)', padding: 'var(--space-3)',
  wordBreak: 'break-all', color: 'var(--text-primary)',
};

const AccountSecurity: React.FC = () => {
  const [status, setStatus] = useState<any | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // Enrolment, which is three states rather than a boolean: nothing yet, a
  // secret waiting to be proved, and the codes shown exactly once afterwards.
  const [enrolling, setEnrolling] = useState<any | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [copied, setCopied] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);

  const [password, setPassword] = useState('');

  const refresh = () => authService.twoFactorStatus().then(setStatus).catch(() => setStatus(null));
  useEffect(() => { refresh(); }, []);

  const begin = async () => {
    setError(''); setBusy(true);
    try { setEnrolling(await authService.twoFactorEnrol()); }
    catch (e: any) { setError(e?.response?.data?.message || 'Could not start enrolment.'); }
    finally { setBusy(false); }
  };

  const confirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(''); setBusy(true);
    try {
      const res = await authService.twoFactorConfirm(code);
      setRecoveryCodes(res.recovery_codes);
      setEnrolling(null);
      setCode('');
      refresh();
    } catch (e: any) {
      setError(e?.response?.data?.message || 'That code is not valid.');
    } finally { setBusy(false); }
  };

  const disable = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(''); setBusy(true);
    try {
      await authService.twoFactorDisable(password);
      setPassword('');
      setRecoveryCodes(null);
      refresh();
    } catch (e: any) {
      setError(e?.response?.data?.message || 'Could not turn off two-factor.');
    } finally { setBusy(false); }
  };

  const enabled = !!status?.enabled;

  return (
    <div>
      <PageHeader
        title="Account security"
        subtitle="A second factor for this account. It protects your login only — every operator manages their own."
      />

      {!!error && (
        <div style={{
          display: 'flex', gap: 'var(--space-2)', alignItems: 'center',
          padding: 'var(--space-3)', marginBottom: 'var(--space-4)',
          border: '1px solid var(--sev-high)', borderRadius: 'var(--radius-md)',
          color: 'var(--sev-high)', fontSize: 'var(--text-sm)',
        }}>
          <AlertTriangle size={16} /> {error}
        </div>
      )}

      {/* Shown once, and the page says so, because the server genuinely cannot
          show them again - they are stored as hashes, which is the property
          that makes storing them safe at all. */}
      {!!recoveryCodes && (
        <Card title="Save these recovery codes now">
          <p style={note}>
            Each one signs you in once if you lose your authenticator. They are
            stored as hashes, so this page cannot show them again — if you
            leave without copying them, the only way back is to turn two-factor
            off with your password and enrol again.
          </p>
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: 'var(--space-2)', marginBottom: 'var(--space-3)',
          }}>
            {recoveryCodes.map((c) => <div key={c} style={mono}>{c}</div>)}
          </div>
          <button
            onClick={() => {
              navigator.clipboard?.writeText(recoveryCodes.join('\n'));
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            }}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)',
              padding: 'var(--space-2) var(--space-4)', borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-color)', background: 'var(--surface-2)',
              color: 'var(--text-primary)', cursor: 'pointer', fontSize: 'var(--text-sm)',
            }}
          >
            {copied ? <><Check size={15} /> Copied</> : <><Copy size={15} /> Copy all</>}
          </button>
        </Card>
      )}

      <Card title={enabled ? 'Two-factor is on' : 'Two-factor is off'}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
          marginBottom: 'var(--space-4)',
        }}>
          {enabled
            ? <ShieldCheck size={22} color="var(--accent-success)" />
            : <ShieldOff size={22} color="var(--sev-medium)" />}
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            {enabled
              ? `Signing in needs a code from your authenticator. ${status?.recovery_codes_remaining ?? 0} recovery code(s) left.`
              : 'Signing in needs only your password.'}
          </div>
        </div>

        {!enabled && !enrolling && (
          <>
            <p style={note}>
              A password alone protects this console against guessing and
              nothing else. It can isolate a host, run a command as SYSTEM on
              every endpoint, and read every log the fleet has produced — a
              password that has been reused or phished is enough for all of it.
            </p>
            <button onClick={begin} disabled={busy} style={{
              display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)',
              padding: 'var(--space-3) var(--space-5)', borderRadius: 'var(--radius-md)',
              background: 'var(--accent-secondary)', color: 'white', border: 'none',
              cursor: busy ? 'wait' : 'pointer', fontWeight: 600,
            }}>
              <KeyRound size={16} /> Turn on two-factor
            </button>
          </>
        )}

        {!!enrolling && (
          <>
            <p style={note}>
              Scan this with your authenticator, then prove it with a code.
              Nothing changes about your login until you do — a secret that is
              scanned and never confirmed would lock you out.
            </p>

            <div style={{
              display: 'flex', gap: 'var(--space-5)', flexWrap: 'wrap',
              alignItems: 'flex-start', marginBottom: 'var(--space-4)',
            }}>
              {/* On a white plate, always, in both themes.
                  A scanner needs dark modules on a light ground, and a code
                  drawn in theme colours on a dark card is a code that reads
                  perfectly to a human and not at all to a phone. */}
              <div style={{
                background: '#ffffff', padding: '12px',
                borderRadius: 'var(--radius-md)', lineHeight: 0,
              }}>
                <QRCodeSVG
                  value={enrolling.uri}
                  size={168}
                  level="M"
                  marginSize={0}
                />
              </div>

              <div style={{ flex: '1 1 260px', minWidth: 0 }}>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 'var(--space-1)' }}>
                  CAN'T SCAN? TYPE THIS KEY INSTEAD
                </div>
                <div style={{ ...mono, letterSpacing: '0.08em', marginBottom: 'var(--space-2)' }}>
                  {enrolling.secret}
                </div>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard?.writeText(enrolling.secret);
                    setCopiedSecret(true);
                    setTimeout(() => setCopiedSecret(false), 2000);
                  }}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)',
                    padding: 'var(--space-2) var(--space-3)', borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--border-color)', background: 'var(--surface-2)',
                    color: 'var(--text-primary)', cursor: 'pointer', fontSize: 'var(--text-xs)',
                  }}
                >
                  {copiedSecret ? <><Check size={14} /> Copied</> : <><Copy size={14} /> Copy key</>}
                </button>
              </div>
            </div>

            <form onSubmit={confirm} style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="123456"
                inputMode="numeric"
                autoComplete="one-time-code"
                style={{
                  padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-color)', border: '1px solid var(--border-color)',
                  color: 'var(--text-primary)', fontFamily: 'monospace',
                  letterSpacing: '0.25em', width: '160px',
                }}
              />
              <button type="submit" disabled={busy || !code} style={{
                padding: 'var(--space-3) var(--space-5)', borderRadius: 'var(--radius-md)',
                background: 'var(--accent-secondary)', color: 'white', border: 'none',
                cursor: busy || !code ? 'not-allowed' : 'pointer', fontWeight: 600,
                opacity: busy || !code ? 0.6 : 1,
              }}>
                Confirm
              </button>
              <button type="button" onClick={() => { setEnrolling(null); setCode(''); }} style={{
                background: 'none', border: 'none', color: 'var(--text-secondary)',
                cursor: 'pointer', fontSize: 'var(--text-sm)',
              }}>
                Cancel
              </button>
            </form>
          </>
        )}

        {enabled && (
          <>
            <p style={note}>
              Turning it off needs your password. A session that has been taken
              over must not be able to remove the control that would have
              stopped it.
            </p>
            <form onSubmit={disable} style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Your password"
                style={{
                  padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-color)', border: '1px solid var(--border-color)',
                  color: 'var(--text-primary)', width: '220px',
                }}
              />
              <button type="submit" disabled={busy || !password} style={{
                padding: 'var(--space-3) var(--space-5)', borderRadius: 'var(--radius-md)',
                background: 'transparent', color: 'var(--sev-high)',
                border: '1px solid var(--sev-high)',
                cursor: busy || !password ? 'not-allowed' : 'pointer',
                opacity: busy || !password ? 0.6 : 1, fontWeight: 600,
              }}>
                Turn off
              </button>
            </form>
          </>
        )}
      </Card>
    </div>
  );
};

export default AccountSecurity;
