import React, { useState, useEffect } from 'react';
import { Mail, BrainCircuit, Save, ShieldCheck, Share2, Globe, RefreshCw } from 'lucide-react';
import { adminService } from '../services/api';

const AdminConfig: React.FC = () => {
  const [emailConfig, setEmailConfig] = useState<any>({
    smtp_server: '',
    smtp_port: 587,
    smtp_user: '',
    smtp_password: '',
    smtp_use_tls: true,
    email_from: '',
    email_to: '',
    enabled: false
  });
  const [aiConfig, setAiConfig] = useState<any>({
    model_name: 'llama3.2:3b',
    api_key: 'ollama',
    endpoint: 'http://ollama:11434/api'
  });
  const [ldapConfig, setLdapConfig] = useState<any>({
    ldap_host: '',
    ldap_port: 389,
    users_base: '',
    group_base: '',
    bind_dn: '',
    bind_password: '',
    login_filter: '(uid=%s)'
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchConfigs();
  }, []);

  const fetchConfigs = async () => {
    setLoading(true);
    try {
      const [email, ai, ldap] = await Promise.all([
        adminService.getEmailConfig(),
        adminService.getAiConfig('server'),
        adminService.getLdapConfig()
      ]);
      
      if (email) {
        setEmailConfig({
          ...email,
          email_from: email.email_from || email.from_addr || '',
          email_to: email.email_to || email.to_addr || ''
        });
      }
      if (ai) setAiConfig(ai);
      if (ldap && ldap.config) setLdapConfig(ldap.config);
    } catch (err) {
      console.error("Failed to fetch configs", err);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveEmail = async () => {
    try {
      // Backend expects email_from, email_to
      const payload = {
        ...emailConfig,
        email_from: emailConfig.email_from,
        email_to: emailConfig.email_to
      };
      await adminService.saveEmailConfig(payload);
      alert("Email configuration saved!");
      fetchConfigs();
    } catch (err: any) {
      alert("Failed to save email configuration: " + (err.response?.data?.message || err.message));
    }
  };

  const handleSaveAi = async () => {
    try {
      await adminService.updateAiConfig('server', aiConfig);
      alert("AI configuration saved!");
      fetchConfigs();
    } catch (err: any) {
      alert("Failed to save AI configuration: " + (err.response?.data?.error || err.message));
    }
  };

  const handleSaveLdap = async () => {
    try {
      await adminService.saveLdapConfig(ldapConfig);
      alert("LDAP configuration saved!");
      fetchConfigs();
    } catch (err) {
      alert("Failed to save LDAP configuration");
    }
  };

  const handleTestLdap = async () => {
    try {
      const res = await adminService.testLdap(ldapConfig);
      alert(res.message || "LDAP connection successful!");
    } catch (err: any) {
      alert(err.response?.data?.message || "LDAP connection failed");
    }
  };

  if (loading && !emailConfig.smtp_server) {
    return (
      <div style={{ height: '80vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <RefreshCw size={48} className="animate-spin" color="var(--accent-secondary)" />
      </div>
    );
  }

  return (
    <div>
      <div style={{ marginBottom: '32px' }}>
        <h2 style={{ fontSize: '1.875rem', marginBottom: '8px' }}>System Configuration</h2>
        <p style={{ color: 'var(--text-secondary)' }}>Manage global settings, AI integration, and notification channels.</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '32px' }}>
        {/* Email Config */}
        <div style={{ backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '32px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
            <Mail color="var(--accent-secondary)" />
            <h3 style={{ fontSize: '1.25rem' }}>Email Notifications</h3>
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <InputGroup label="SMTP Server" value={emailConfig.smtp_server} onChange={val => setEmailConfig({...emailConfig, smtp_server: val})} placeholder="smtp.gmail.com" />
            <InputGroup label="SMTP Port" value={emailConfig.smtp_port?.toString()} onChange={val => setEmailConfig({...emailConfig, smtp_port: parseInt(val) || 587})} placeholder="587" />
            <InputGroup label="SMTP User" value={emailConfig.smtp_user} onChange={val => setEmailConfig({...emailConfig, smtp_user: val})} placeholder="user@gmail.com" />
            <InputGroup label="SMTP Password" value={emailConfig.smtp_password} type="password" onChange={val => setEmailConfig({...emailConfig, smtp_password: val})} placeholder="••••••••" />
            <InputGroup label="Sender Email" value={emailConfig.email_from} onChange={val => setEmailConfig({...emailConfig, email_from: val})} placeholder="alerts@sentora.com" />
            <InputGroup label="Recipient Email" value={emailConfig.email_to} onChange={val => setEmailConfig({...emailConfig, email_to: val})} placeholder="admin@company.com" />
            
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '8px' }}>
              <input type="checkbox" checked={emailConfig.enabled} onChange={e => setEmailConfig({...emailConfig, enabled: e.target.checked})} id="email-enabled" />
              <label htmlFor="email-enabled" style={{ fontSize: '0.875rem' }}>Enable Email Alerts</label>
            </div>

            <button onClick={handleSaveEmail} style={{ marginTop: '12px', backgroundColor: 'var(--accent-secondary)', color: 'white', padding: '12px', borderRadius: '8px', fontWeight: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
              <Save size={18} /> Save Email Config
            </button>
          </div>
        </div>

        {/* AI Config */}
        <div style={{ backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '32px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
            <BrainCircuit color="var(--accent-warning)" />
            <h3 style={{ fontSize: '1.25rem' }}>AI Engine (Ollama / Local LLM)</h3>
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <InputGroup label="Model Name" value={aiConfig.model_name} onChange={val => setAiConfig({...aiConfig, model_name: val})} />
            <InputGroup label="API Endpoint" value={aiConfig.endpoint} onChange={val => setAiConfig({...aiConfig, endpoint: val})} placeholder="Enter endpoint" />
            <InputGroup label="API Key" value={aiConfig.api_key} type="password" onChange={val => setAiConfig({...aiConfig, api_key: val})} placeholder={aiConfig.has_api_key ? "•••••••• (Key set)" : "Enter API key"} />
            
            <div style={{ padding: '16px', backgroundColor: 'rgba(245, 158, 11, 0.05)', border: '1px solid rgba(245, 158, 11, 0.2)', borderRadius: '8px', marginTop: '8px' }}>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                <strong>Note:</strong> AI analysis is powered by <strong>Ollama</strong> for automated SIEM log triage and vulnerability summaries. 
              </p>
            </div>

            <button onClick={handleSaveAi} style={{ marginTop: '12px', backgroundColor: 'var(--accent-warning)', color: 'var(--bg-color)', padding: '12px', borderRadius: '8px', fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
              <ShieldCheck size={18} /> Update AI Settings
            </button>
          </div>
        </div>

        {/* LDAP Config */}
        <div style={{ backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '32px', gridColumn: 'span 2' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
            <Globe color="var(--accent-secondary)" />
            <h3 style={{ fontSize: '1.25rem' }}>LDAP / Active Directory Integration</h3>
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '32px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <InputGroup label="LDAP Host" value={ldapConfig.ldap_host} onChange={val => setLdapConfig({...ldapConfig, ldap_host: val})} placeholder="ldap://company.local" />
              <InputGroup label="LDAP Port" value={ldapConfig.ldap_port?.toString()} onChange={val => setLdapConfig({...ldapConfig, ldap_port: parseInt(val) || 389})} placeholder="389" />
              <InputGroup label="Search Base (Users)" value={ldapConfig.users_base} onChange={val => setLdapConfig({...ldapConfig, users_base: val})} placeholder="ou=Users,dc=company,dc=local" />
              <InputGroup label="Search Base (Groups)" value={ldapConfig.group_base} onChange={val => setLdapConfig({...ldapConfig, group_base: val})} placeholder="ou=Groups,dc=company,dc=local" />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <InputGroup label="Bind DN" value={ldapConfig.bind_dn} onChange={val => setLdapConfig({...ldapConfig, bind_dn: val})} placeholder="cn=admin,dc=company,dc=local" />
              <InputGroup label="Bind Password" value={ldapConfig.bind_password} type="password" onChange={val => setLdapConfig({...ldapConfig, bind_password: val})} placeholder="••••••••" />
              <InputGroup label="Login Filter" value={ldapConfig.login_filter} onChange={val => setLdapConfig({...ldapConfig, login_filter: val})} placeholder="(uid=%s)" />
              
              <div style={{ display: 'flex', gap: '12px', marginTop: '12px' }}>
                <button onClick={handleTestLdap} style={{ flex: 1, backgroundColor: 'rgba(255,255,255,0.05)', color: 'var(--text-primary)', padding: '12px', borderRadius: '8px', fontWeight: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', border: '1px solid var(--border-color)' }}>
                  <Share2 size={18} /> Test Connection
                </button>
                <button onClick={handleSaveLdap} style={{ flex: 1, backgroundColor: 'var(--accent-secondary)', color: 'white', padding: '12px', borderRadius: '8px', fontWeight: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                  <Save size={18} /> Save LDAP Config
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const InputGroup: React.FC<{ label: string, value?: string, placeholder?: string, type?: string, disabled?: boolean, onChange?: (val: string) => void }> = ({ label, value, placeholder, type = "text", disabled, onChange }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
    <label style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-secondary)' }}>{label}</label>
    <input 
      type={type} 
      value={value || ''} 
      onChange={e => onChange?.(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      style={{ 
        backgroundColor: 'var(--bg-color)', 
        border: '1px solid var(--border-color)', 
        borderRadius: '8px', 
        padding: '10px 14px', 
        color: disabled ? 'var(--text-secondary)' : 'var(--text-primary)',
        fontSize: '0.875rem',
        outline: 'none',
        transition: 'border-color 0.2s ease'
      }}
      onFocus={e => e.target.style.borderColor = 'var(--accent-secondary)'}
      onBlur={e => e.target.style.borderColor = 'var(--border-color)'}
    />
  </div>
);

export default AdminConfig;
