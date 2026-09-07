import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ShieldAlert, Lock, User, AlertCircle, Loader2, KeyRound } from 'lucide-react';
import { authService } from '../services/api';

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
  
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from?.pathname || "/";

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
      setError(err.message || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
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
    <div style={{
      height: '100vh',
      width: '100vw',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: 'var(--bg-color)',
      position: 'relative',
      overflow: 'hidden'
    }}>

      <div className="card" style={{
        width: '100%',
        maxWidth: '420px',
        padding: '48px 40px',
        borderRadius: '4px',
        zIndex: 1,
        animation: 'fadeIn 0.4s ease-out'
      }}>
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <div style={{ 
            display: 'inline-flex', 
            padding: '12px', 
            borderRadius: '4px', 
            background: 'var(--bg-color)',
            border: '1px solid var(--border-color)',
            marginBottom: '20px' 
          }}>
            <ShieldAlert size={40} color="var(--text-primary)" />
          </div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 600, letterSpacing: '-0.01em', marginBottom: '8px', color: 'var(--text-primary)' }}>Sentora Platform</h1>
          <p className="mono" style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>SECURE CONSOLE AUTHENTICATION</p>
        </div>

        {error && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '14px 16px',
            backgroundColor: 'var(--bg-color)',
            border: '1px solid var(--accent-color)',
            borderRadius: '4px',
            color: 'var(--accent-color)',
            fontSize: '0.875rem',
            marginBottom: '24px',
            animation: 'fadeIn 0.3s ease'
          }}>
            <AlertCircle size={18} style={{ flexShrink: 0 }} />
            <span style={{ fontWeight: 500, lineHeight: 1.4 }}>{error}</span>
          </div>
        )}

        {pendingToken ? (
          /* The second step replaces the first rather than appearing beside
             it. Two forms on screen at once invites typing a code into a
             password field, and the password has already been accepted - it
             has nothing left to do here. */
          <form onSubmit={handleSecondFactor} style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-secondary)' }}>
                Authentication code
              </label>
              <div style={{ position: 'relative' }}>
                <KeyRound size={18} style={{ position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
                <input
                  type="text"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  placeholder="123456"
                  autoFocus
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  style={{
                    width: '100%', padding: '14px 16px 14px 48px',
                    backgroundColor: 'var(--bg-color)',
                    border: '1px solid var(--border-color)', borderRadius: '4px',
                    color: 'var(--text-primary)', fontSize: '1.1rem',
                    letterSpacing: '0.25em', fontFamily: 'monospace',
                    outline: 'none',
                  }}
                />
              </div>
              <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                From your authenticator app, or one of your recovery codes.
              </p>
            </div>

            <button
              type="submit"
              disabled={loading || !code}
              style={{
                width: '100%', padding: '14px', borderRadius: '4px',
                backgroundColor: 'var(--accent-secondary)', color: 'white',
                border: 'none', fontSize: '0.9rem', fontWeight: 600,
                cursor: loading || !code ? 'not-allowed' : 'pointer',
                opacity: loading || !code ? 0.6 : 1,
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
              }}
            >
              {loading ? <><Loader2 size={16} className="animate-spin" /> Verifying...</> : 'Verify'}
            </button>

            <button
              type="button"
              onClick={() => { setPendingToken(null); setCode(''); setError(''); setPassword(''); }}
              style={{
                background: 'none', border: 'none', color: 'var(--text-secondary)',
                fontSize: '0.8rem', cursor: 'pointer', padding: 0,
              }}
            >
              Start again
            </button>
          </form>
        ) : (
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <label style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-secondary)' }}>Username</label>
            <div style={{ position: 'relative' }}>
              <User size={18} style={{ position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                placeholder="admin"
                style={{
                  width: '100%',
                  backgroundColor: 'var(--bg-color)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '4px',
                  padding: '14px 16px 14px 44px',
                  color: 'var(--text-primary)',
                  fontSize: '0.95rem',
                  outline: 'none',
                  transition: 'border-color 0.2s',
                  boxShadow: 'none'
                }}
                onFocus={(e) => { e.target.style.borderColor = 'var(--text-primary)'; }}
                onBlur={(e) => { e.target.style.borderColor = 'var(--border-color)'; }}
              />
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <label style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-secondary)' }}>Password</label>
            <div style={{ position: 'relative' }}>
              <Lock size={18} style={{ position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                placeholder="••••••••"
                style={{
                  width: '100%',
                  backgroundColor: 'var(--bg-color)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '4px',
                  padding: '14px 16px 14px 44px',
                  color: 'var(--text-primary)',
                  fontSize: '0.95rem',
                  outline: 'none',
                  transition: 'border-color 0.2s',
                  boxShadow: 'none'
                }}
                onFocus={(e) => { e.target.style.borderColor = 'var(--text-primary)'; }}
                onBlur={(e) => { e.target.style.borderColor = 'var(--border-color)'; }}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              marginTop: '12px',
              background: 'var(--text-primary)',
              color: 'var(--bg-color)',
              padding: '14px',
              borderRadius: '4px',
              fontWeight: 600,
              fontSize: '0.95rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '10px',
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'background 0.2s',
              border: 'none'
            }}
            onMouseOver={e => { if(!loading) { e.currentTarget.style.background = '#d4d4d4'; } }}
            onMouseOut={e => { if(!loading) { e.currentTarget.style.background = 'var(--text-primary)'; } }}
          >
            {loading ? <Loader2 className="animate-spin" size={20} /> : 'AUTHENTICATE'}
          </button>
        </form>
        )}

        <p style={{ 
          marginTop: '40px', 
          textAlign: 'center', 
          fontSize: '0.75rem', 
          color: 'var(--text-secondary)',
          opacity: 0.7
        }}>
          Sentora Enterprise Security Platform
        </p>
      </div>
    </div>
  );
};

export default Login;
