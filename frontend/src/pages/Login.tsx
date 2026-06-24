import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ShieldAlert, Lock, User, AlertCircle, Loader2 } from 'lucide-react';
import { authService } from '../services/api';

const Login: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from?.pathname || "/";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await authService.login({ username, password });
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.message || 'Login failed. Please check your credentials.');
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
