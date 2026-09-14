import React, { useState } from 'react';
import { NavLink, Link } from 'react-router-dom';
import { Activity, BrainCircuit, ChevronRight, ClipboardList, Database, Download, Grid3x3, Key, LayoutDashboard, LogOut, Monitor, PlaySquare, Radar, Search, Settings, ShieldAlert, ShieldCheck, Users, Zap } from 'lucide-react';
import { authService } from '../services/api';
import { Modal, Field, DialogButton } from './ui';

interface SidebarProps {
  isOpen: boolean;
  /** Passed down rather than measured here.
   *
   * These styles used to call `window.innerWidth` directly, which is read once
   * while React renders - so the sidebar only changed shape when something
   * else happened to re-render it. It worked by accident, because `Layout`
   * owns the resize listener and re-renders this on every change; the moment
   * that stopped being true the sidebar would have been fixed-positioned on a
   * desktop with nothing to explain it. Layout already knows, so it says. */
  isMobile: boolean;
}

const SidebarLink: React.FC<{ to: string, icon: React.ReactNode, label: string }> = ({ to, icon, label }) => {
  return (
    <NavLink 
      to={to}
      className={({ isActive }) => isActive ? 'active-nav-link' : 'nav-link'}
      style={({ isActive }) => ({
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '10px 12px',
        borderRadius: '6px',
        fontSize: '0.875rem',
        fontWeight: 500,
        color: isActive ? 'var(--accent-secondary)' : 'var(--text-secondary)',
        backgroundColor: isActive ? 'rgba(37, 99, 235, 0.08)' : 'transparent',
        borderLeft: isActive ? '3px solid var(--accent-secondary)' : '3px solid transparent',
        transition: 'all 0.15s ease-in-out',
        marginBottom: '2px'
      })}
    >
      {icon}
      <span style={{ flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{label}</span>
      <ChevronRight size={14} style={{ opacity: 0.5 }} />
    </NavLink>
  );
};

const Sidebar: React.FC<SidebarProps> = ({ isOpen, isMobile }) => {
  const user = authService.getUser();
  const [showPasswordModal, setShowPasswordModal] = useState(false);

  // The server refuses every route except the password change while the
  // account still carries the credential published in db/init_userdb.sql.
  // Without this the console renders empty and says nothing: the pages load,
  // every request 403s, and the cause is invisible.
  const [mustChange, setMustChange] = useState(
    () => localStorage.getItem('mustChangePassword') === '1'
  );
  React.useEffect(() => {
    const onForced = () => setMustChange(true);
    window.addEventListener('sentora:must-change-password', onForced);
    return () => window.removeEventListener('sentora:must-change-password', onForced);
  }, []);
  const [passwordData, setPasswordData] = useState({ current_password: '', new_password: '', confirm_password: '' });

  const handleLogout = async () => {
    // logout() now revokes the session server-side before redirecting, so it
    // has to be awaited — and it performs the redirect itself.
    await authService.logout();
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (passwordData.new_password !== passwordData.confirm_password) {
      alert("New passwords do not match!");
      return;
    }
    try {
      await authService.changePassword({
        username: user?.username,
        current_password: passwordData.current_password,
        new_password: passwordData.new_password
      });
      setShowPasswordModal(false);
      setMustChange(false);
      localStorage.removeItem('mustChangePassword');
      setPasswordData({ current_password: '', new_password: '', confirm_password: '' });
      // The server revokes every session issued against the old password,
      // this browser's included, so staying on the page would just 401.
      alert("Password changed. Please sign in again.");
      localStorage.clear();
      window.location.href = '/login';
    } catch (err: any) {
      alert(err.response?.data?.message || "Failed to change password");
    }
  };

  return (
    <>
    <aside style={{
      width: isOpen ? '260px' : '0',
      backgroundColor: 'var(--sidebar-bg)',
      borderRight: isOpen ? '1px solid var(--border-color)' : 'none',
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      position: isMobile ? 'fixed' : 'sticky',
      top: 0,
      left: 0,
      flexShrink: 0,
      transition: 'all 0.4s cubic-bezier(0.16, 1, 0.3, 1)',
      overflow: 'hidden',
      zIndex: 999,
      boxShadow: isOpen ? '4px 0 24px rgba(0,0,0,0.2)' : 'none',
      visibility: isOpen || !isMobile ? 'visible' : 'hidden'
    }}>
      <div style={{ 
        padding: '24px', 
        borderBottom: '1px solid var(--border-color)', 
        minWidth: '260px',
        opacity: isOpen ? 1 : 0,
        transition: 'opacity 0.3s ease'
      }}>
        <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '12px', textDecoration: 'none', transition: 'all 0.2s', padding: '4px' }}
          onMouseOver={e => e.currentTarget.style.opacity = '0.8'}
          onMouseOut={e => e.currentTarget.style.opacity = '1'}
        >
          <div style={{ padding: '8px', background: 'var(--accent-secondary)', borderRadius: '6px', display: 'flex' }}>
            <ShieldAlert size={24} color="#FFFFFF" />
          </div>
          <h1 style={{ fontSize: '1.25rem', letterSpacing: '-0.5px', fontWeight: 600, color: 'var(--text-primary)' }}>Sentora</h1>
        </Link>
      </div>

      <nav style={{ 
        padding: '20px 16px', 
        flex: 1, 
        overflowY: 'auto', 
        minWidth: '260px',
        opacity: isOpen ? 1 : 0,
        transition: 'opacity 0.3s ease'
      }}>
        <div style={{ marginBottom: '28px' }}>
          <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '12px', paddingLeft: '12px', opacity: 0.8 }}>Global Control</p>
          {authService.hasPermission('read_telemetry') && <SidebarLink to="/" icon={<LayoutDashboard size={18} />} label="Dashboard" />}
          {authService.hasPermission('read_telemetry') && <SidebarLink to="/agents" icon={<Monitor size={18} />} label="Security Agents" />}
          {authService.hasPermission('read_telemetry') && <SidebarLink to="/all-alerts" icon={<Activity size={18} />} label="Global Alerts" />}
          {authService.hasPermission('read_telemetry') && <SidebarLink to="/assets" icon={<Database size={18} />} label="Asset Inventory" />}
          {authService.hasPermission('read_telemetry') && <SidebarLink to="/fim" icon={<ShieldAlert size={18} />} label="File Integrity" />}
          {authService.hasPermission('read_telemetry') && <SidebarLink to="/search" icon={<Search size={18} />} label="Search" />}
          {authService.hasPermission('read_telemetry') && <SidebarLink to="/threat-intel" icon={<Radar size={18} />} label="Threat Intelligence" />}
          {authService.hasPermission('read_telemetry') && <SidebarLink to="/attack-coverage" icon={<Grid3x3 size={18} />} label="ATT&CK Coverage" />}
          {authService.hasPermission('manage_agent') && <SidebarLink to="/deployment" icon={<Download size={18} />} label="Deploy Agent" />}
          {authService.hasPermission('analyze_logs') && <SidebarLink to="/ai-analysis" icon={<BrainCircuit size={18} />} label="AI Analysis" />}
        </div>

        <div style={{ marginBottom: '28px' }}>
          <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '12px', paddingLeft: '12px', opacity: 0.8 }}>Automation Response</p>
          {authService.hasPermission('read_telemetry') && <SidebarLink to="/soar-hub" icon={<Zap size={18} />} label="Defensive Actions (SOAR)" />}
          {authService.hasPermission('manage_soar') && <SidebarLink to="/playbooks" icon={<PlaySquare size={18} />} label="Playbooks" />}
          {authService.hasPermission('manage_soar') && <SidebarLink to="/automations" icon={<Zap size={18} />} label="Automation Rules" />}
        </div>

        <div style={{ marginBottom: '24px' }}>
          <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '12px', paddingLeft: '12px', opacity: 0.8 }}>Administration</p>
          {authService.hasPermission('manage_users') && <SidebarLink to="/admin/users" icon={<Users size={18} />} label="Users & Roles" />}
          {authService.hasPermission('manage_system') && <SidebarLink to="/admin/config" icon={<Settings size={18} />} label="System Config" />}
          {authService.hasPermission('manage_db') && <SidebarLink to="/admin/databases" icon={<Database size={18} />} label="Databases" />}
          {authService.hasPermission('read_telemetry') && <SidebarLink to="/admin/login-logs" icon={<Key size={18} />} label="Access Logs" />}
          {authService.hasPermission('read_telemetry') && <SidebarLink to="/admin/audit" icon={<ClipboardList size={18} />} label="Activity Logs" />}
          {/* Ungated on purpose - see the route. A link only some roles can
              see would leave the rest unable to secure their own account. */}
          <SidebarLink to="/account/security" icon={<ShieldCheck size={18} />} label="My Security" />
        </div>
      </nav>

      <div style={{ 
        padding: '20px 16px', 
        borderTop: '1px solid var(--border-color)', 
        backgroundColor: 'var(--bg-color)', 
        minWidth: '260px',
        opacity: isOpen ? 1 : 0,
        transition: 'opacity 0.3s ease'
      }}>
        {mustChange && (
          <button
            onClick={() => setShowPasswordModal(true)}
            style={{
              width: '100%',
              textAlign: 'left',
              marginBottom: '14px',
              padding: '12px 14px',
              borderRadius: '10px',
              border: '1px solid rgba(248, 113, 113, 0.45)',
              backgroundColor: 'rgba(248, 113, 113, 0.12)',
              color: '#fca5a5',
              cursor: 'pointer',
              lineHeight: 1.45,
            }}
          >
            <strong style={{ display: 'block', marginBottom: '4px' }}>
              Set a password to continue
            </strong>
            <span style={{ fontSize: '0.8rem', opacity: 0.9 }}>
              This account still uses the default from the repository, so the
              console is showing nothing. Click here to change it.
            </span>
          </button>
        )}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '16px' }}>
          <div style={{ 
            width: '36px', 
            height: '36px', 
            borderRadius: '10px', 
            backgroundColor: 'rgba(96, 165, 250, 0.15)', 
            color: 'var(--accent-secondary)',
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center', 
            fontSize: '0.85rem', 
            fontWeight: 800,
            textTransform: 'uppercase'
          }}>
            {user?.username?.substring(0, 2) || 'AD'}
          </div>
          <div style={{ flex: 1, overflow: 'hidden' }}>
            <p style={{ fontSize: '0.875rem', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#fff' }}>{user?.username || 'Admin User'}</p>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'capitalize', fontWeight: 500 }}>{user?.role || 'Analyst'}</p>
          </div>
          <button 
            onClick={() => setShowPasswordModal(true)}
            style={{ color: 'var(--text-secondary)', padding: '6px', borderRadius: '6px', transition: 'all 0.2s', backgroundColor: 'transparent' }}
            onMouseOver={e => { e.currentTarget.style.color = 'var(--text-primary)'; e.currentTarget.style.backgroundColor = 'var(--bg-color)'; }}
            onMouseOut={e => { e.currentTarget.style.color = 'var(--text-secondary)'; e.currentTarget.style.backgroundColor = 'transparent'; }}
            title="Change Password"
          >
            <Key size={16} />
          </button>
        </div>
        <button 
          onClick={handleLogout}
          style={{ 
            width: '100%', 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center',
            gap: '8px', 
            padding: '8px', 
            borderRadius: '6px', 
            color: 'var(--text-secondary)', 
            backgroundColor: 'transparent',
            border: '1px solid var(--border-color)',
            fontSize: '0.875rem',
            fontWeight: 500,
            transition: 'all 0.2s ease',
            cursor: 'pointer'
          }}
          onMouseOver={(e) => { e.currentTarget.style.backgroundColor = 'var(--card-bg)'; e.currentTarget.style.color = 'var(--text-primary)'; }}
          onMouseOut={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.color = 'var(--text-secondary)'; }}
        >
          <LogOut size={16} /> Sign Out
        </button>
      </div>
    </aside>

    {showPasswordModal && (
      <Modal
        title="Change password"
        onClose={() => setShowPasswordModal(false)}
      >
        <form
          onSubmit={handleChangePassword}
          style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}
        >
          <Field label="Current password">
            <input
              type="password"
              autoComplete="current-password"
              value={passwordData.current_password}
              onChange={e => setPasswordData({ ...passwordData, current_password: e.target.value })}
              required
              autoFocus
            />
          </Field>
          <Field label="New password">
            <input
              type="password"
              autoComplete="new-password"
              value={passwordData.new_password}
              onChange={e => setPasswordData({ ...passwordData, new_password: e.target.value })}
              required
            />
          </Field>
          <Field label="Confirm new password">
            <input
              type="password"
              autoComplete="new-password"
              value={passwordData.confirm_password}
              onChange={e => setPasswordData({ ...passwordData, confirm_password: e.target.value })}
              required
            />
          </Field>
          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
            <DialogButton onClick={() => setShowPasswordModal(false)}>Cancel</DialogButton>
            <DialogButton type="submit" variant="solid">Update</DialogButton>
          </div>
        </form>
      </Modal>
    )}
    </>
  );
};

export default Sidebar;
