/**
 * The only page outside the console shell, so it keeps its own layout - there
 * is no sidebar and no `PageHeader` here to hang it from.
 *
 * What it does share is the vocabulary. Every measurement was a literal:
 * `borderRadius: '4px'` five times, three copies of the same overlaid-icon
 * input, and `onFocus`/`onBlur` handlers setting `borderColor` by hand - which
 * is what the `input:focus` rule in index.css already does, so the two were
 * fighting. The hover on the submit button was a hardcoded `#d4d4d4` applied
 * through `onMouseOver`, meaning the one button in the product whose hover
 * lived in JavaScript.
 *
 * The two-step flow is unchanged. The second factor replaces the password form
 * rather than appearing beside it, and an expired pending token sends the
 * operator back to the start instead of leaving them typing codes at something
 * that will never accept one.
 */
import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ShieldAlert, Lock, User, AlertCircle, Loader2, KeyRound, Usb } from 'lucide-react';
import { authService } from '../services/api';
import * as webauthn from '../lib/webauthn';

/** Label, leading icon, input. Three copies of this were written out inline. */
const IconField: React.FC<{
  label: string;
  icon: React.ReactNode;
  hint?: string;
  children: React.ReactNode;
}> = ({ label, icon, hint, children }) => (
  <label style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
    <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
      {label}
    </span>
    <span style={{ position: 'relative', display: 'block' }}>
      <span
        style={{
          position: 'absolute', left: 14, top: '50%',
          transform: 'translateY(-50%)', color: 'var(--text-muted)',
          lineHeight: 0, pointerEvents: 'none',
        }}
      >
        {icon}
      </span>
      {children}
    </span>
    {hint && (
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {hint}
      </span>
    )}
  </label>
);

const inputWithIcon: React.CSSProperties = { width: '100%', paddingLeft: 40 };

const Login: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  /* The half-authenticated state. Held in a component, never in storage: it
     is a credential with a five-minute life, and putting it anywhere
     persistent would outlive the tab it was meant for. */
  const [pendingToken, setPendingToken] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [keyBusy, setKeyBusy] = useState(false);

  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from?.pathname || '/';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const result = await authService.login({ username, password });
      if (result?.status === 'second_factor_required') {
        setPendingToken(result.token);
        return;
      }
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.message || 'Login failed. Check the username and password.');
    } finally {
      setLoading(false);
    }
  };

  /* The key path, offered beside the code rather than instead of it.
   *
   * Not attempted automatically on arrival. Calling `navigator.credentials.get`
   * unprompted throws a browser dialog at an operator who was reaching for
   * their phone, and cancelling it counts as a failed attempt against the
   * pending token - so it is a button, pressed by somebody who has the key in
   * hand.
   *
   * The button is always shown. Whether a key exists for this account *at this
   * origin* is a question only the server can answer, and asking it up front
   * would mean an unauthenticated endpoint that reports whether an account has
   * a key, from a token anyone with the password holds. The answer arrives as
   * the error on a press instead. */
  const handleSecurityKey = async () => {
    setError('');
    setKeyBusy(true);
    try {
      const options = await authService.webauthnLoginBegin(pendingToken as string);
      const assertion = await webauthn.getAssertion(options);
      await authService.webauthnLoginFinish(pendingToken as string, assertion);
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err?.response?.data?.message || err?.message || webauthn.explain(err));
      if (/expired/i.test(err?.message || '')) {
        setPendingToken(null);
        setPassword('');
      }
    } finally {
      setKeyBusy(false);
    }
  };

  const handleSecondFactor = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await authService.completeSecondFactor(pendingToken as string, code);
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.message || 'That code is not valid.');
      setCode('');
      /* An expired or spent token cannot be retried, and the server answers
         every such case identically on purpose. Sending the operator back to
         the password rather than leaving them typing codes at something that
         will never accept one. */
      if (/expired/i.test(err.message || '')) {
        setPendingToken(null);
        setPassword('');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh', width: '100%',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'var(--bg-color)', padding: 'var(--space-5)',
      }}
    >
      <div
        className="card"
        style={{
          width: '100%', maxWidth: 420,
          padding: 'var(--space-7) var(--space-6)',
          animation: 'fadeIn 0.4s ease-out',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: 'var(--space-6)' }}>
          <div
            style={{
              display: 'inline-flex', padding: 'var(--space-3)',
              background: 'var(--bg-color)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
              marginBottom: 'var(--space-4)',
            }}
          >
            <ShieldAlert size={36} style={{ color: 'var(--text-primary)' }} />
          </div>
          <h1
            style={{
              margin: 0, fontSize: 'var(--text-xl)', fontWeight: 500,
              color: 'var(--text-primary)',
            }}
          >
            Sentora
          </h1>
          <p
            className="mono"
            style={{
              margin: 'var(--space-2) 0 0', color: 'var(--text-muted)',
              fontSize: 'var(--text-xs)', textTransform: 'uppercase',
              letterSpacing: '0.08em',
            }}
          >
            Console authentication
          </p>
        </div>

        {error && (
          <div
            style={{
              display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
              padding: 'var(--space-3)',
              border: '1px solid var(--accent-color)',
              borderRadius: 'var(--radius-md)',
              color: 'var(--accent-color)',
              fontSize: 'var(--text-sm)',
              marginBottom: 'var(--space-5)',
              animation: 'fadeIn 0.3s ease',
            }}
          >
            <AlertCircle size={16} style={{ flexShrink: 0 }} />
            <span style={{ lineHeight: 1.4 }}>{error}</span>
          </div>
        )}

        {pendingToken ? (
          /* The second step replaces the first rather than appearing beside
             it. Two forms on screen at once invites typing a code into a
             password field, and the password has already been accepted - it
             has nothing left to do here. */
          <form
            onSubmit={handleSecondFactor}
            style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}
          >
            <IconField
              label="Authentication code"
              icon={<KeyRound size={16} />}
              hint="From your authenticator app, or one of your recovery codes."
            >
              <input
                type="text"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="123456"
                autoFocus
                autoComplete="one-time-code"
                inputMode="numeric"
                className="mono"
                style={{ ...inputWithIcon, letterSpacing: '0.25em' }}
              />
            </IconField>

            <button type="submit" className="btn-primary" disabled={loading || !code}>
              {loading
                ? <><Loader2 size={15} className="animate-spin" /> Verifying…</>
                : 'Verify'}
            </button>

            {webauthn.supported() && (
              <>
                <div
                  style={{
                    display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
                    color: 'var(--text-muted)', fontSize: 'var(--text-xs)',
                  }}
                >
                  <span style={{ flex: 1, height: 1, background: 'var(--border-color)' }} />
                  or
                  <span style={{ flex: 1, height: 1, background: 'var(--border-color)' }} />
                </div>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={handleSecurityKey}
                  disabled={keyBusy || loading}
                >
                  {keyBusy
                    ? <><Loader2 size={15} className="animate-spin" /> Waiting for the key…</>
                    : <><Usb size={15} /> Use a security key</>}
                </button>
              </>
            )}

            <button
              type="button"
              onClick={() => { setPendingToken(null); setCode(''); setError(''); setPassword(''); }}
              style={{
                background: 'none', border: 'none', padding: 0,
                color: 'var(--text-muted)', fontSize: 'var(--text-xs)',
                cursor: 'pointer',
              }}
            >
              Start again
            </button>
          </form>
        ) : (
          <form
            onSubmit={handleSubmit}
            style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}
          >
            <IconField label="Username" icon={<User size={16} />}>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                placeholder="admin"
                autoComplete="username"
                style={inputWithIcon}
              />
            </IconField>

            <IconField label="Password" icon={<Lock size={16} />}>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                placeholder="••••••••"
                autoComplete="current-password"
                style={inputWithIcon}
              />
            </IconField>

            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? <Loader2 size={16} className="animate-spin" /> : 'Sign in'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};

export default Login;
