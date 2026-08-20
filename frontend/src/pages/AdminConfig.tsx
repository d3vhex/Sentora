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

  type EmailTemplate = {
    id?: number;
    template_name: string;
    subject_template: string;
    body_template: string;
  };
  const [templates, setTemplates] = useState<EmailTemplate[]>([]);
  const [editingTemplate, setEditingTemplate] = useState<EmailTemplate | null>(null);
  const [templateDefaultName, setTemplateDefaultName] = useState('Critical Alerts (default)');

  useEffect(() => {
    fetchConfigs();
  }, []);

  const handleSaveTemplate = async () => {
    if (!editingTemplate) return;
    try {
      const res = await adminService.saveEmailTemplate(editingTemplate);
      alert(res.message || 'Template saved.');
      setEditingTemplate(null);
      fetchConfigs();
    } catch (err: any) {
      alert(err?.response?.data?.message || 'Failed to save template.');
    }
  };

  const handleDeleteTemplate = async (t: EmailTemplate) => {
    if (!t.id) return;
    if (!window.confirm(`Delete template "${t.template_name}"?`)) return;
    try {
      const res = await adminService.deleteEmailTemplate(t.id);
      alert(res.message || 'Template deleted.');
      fetchConfigs();
    } catch (err: any) {
      alert(err?.response?.data?.message || 'Failed to delete template.');
    }
  };

  const fetchConfigs = async () => {
    setLoading(true);
    try {
      const [email, ai, ldap, tmpl] = await Promise.all([
        adminService.getEmailConfig(),
        adminService.getAiConfig('server'),
        adminService.getLdapConfig(),
        adminService.getEmailTemplates().catch(() => null),
      ]);
      if (tmpl?.status === 'success') {
        setTemplates(tmpl.templates || []);
        if (tmpl.default_name) setTemplateDefaultName(tmpl.default_name);
      }
      
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

        {/* Email Templates — the bodies the alert mails actually use. There
            was no way to see or edit these outside the database, so the
            per-agent override the dispatcher looks for was unusable. */}
        <div style={{ backgroundColor: 'var(--card-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '32px', gridColumn: 'span 2' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px', flexWrap: 'wrap', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <Mail color="var(--accent-secondary)" />
              <h3 style={{ fontSize: '1.25rem' }}>Alert Mail Templates</h3>
            </div>
            <button
              onClick={() => setEditingTemplate({ template_name: '', subject_template: '', body_template: '' })}
              style={{ backgroundColor: 'rgba(59,130,246,0.1)', color: 'var(--accent-secondary)', padding: '8px 14px', borderRadius: '8px', fontWeight: 600, fontSize: '0.8125rem' }}
            >
              + New Template
            </button>
          </div>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '20px', lineHeight: 1.6 }}>
            Critical-alert mail looks for a template named <code>Critical Alerts - Agent: &lt;name&gt;</code> and
            falls back to <code>{templateDefaultName}</code> when the agent has none of its own.
            Placeholders <code>{'{{agent}}'}</code> and <code>{'{{body}}'}</code> are substituted at send time.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {templates.map(t => (
              <div key={t.id} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '16px',
                padding: '14px 16px', borderRadius: '8px', border: '1px solid var(--border-color)',
                backgroundColor: 'rgba(0,0,0,0.15)',
              }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: '0.9375rem', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    {t.template_name}
                    {t.template_name === templateDefaultName && (
                      <span style={{ fontSize: '0.65rem', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', backgroundColor: 'rgba(16,185,129,0.12)', color: 'var(--accent-success)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                        Fallback
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {t.subject_template}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '8px', flexShrink: 0 }}>
                  <button onClick={() => setEditingTemplate({ ...t })} style={{ padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-color)', color: 'var(--text-primary)', fontSize: '0.75rem', fontWeight: 600 }}>
                    Edit
                  </button>
                  <button
                    onClick={() => handleDeleteTemplate(t)}
                    disabled={t.template_name === templateDefaultName}
                    title={t.template_name === templateDefaultName
                      ? 'This is the fallback every agent without its own template uses'
                      : 'Delete this template'}
                    style={{
                      padding: '6px 12px', borderRadius: '6px', fontSize: '0.75rem', fontWeight: 600,
                      color: t.template_name === templateDefaultName ? 'var(--text-secondary)' : 'var(--accent-color)',
                      backgroundColor: t.template_name === templateDefaultName ? 'transparent' : 'rgba(239,68,68,0.1)',
                      cursor: t.template_name === templateDefaultName ? 'not-allowed' : 'pointer',
                    }}
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
            {templates.length === 0 && (
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', padding: '20px', textAlign: 'center' }}>
                No templates yet. Alert mail cannot be sent without one.
              </p>
            )}
          </div>

          {editingTemplate && (
            <div style={{ marginTop: '20px', padding: '20px', borderRadius: '10px', border: '1px solid var(--border-neon)', backgroundColor: 'var(--bg-color)' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <InputGroup
                  label="Template Name"
                  value={editingTemplate.template_name}
                  onChange={val => setEditingTemplate({ ...editingTemplate, template_name: val })}
                  placeholder="Critical Alerts - Agent: WIN-01"
                />
                <InputGroup
                  label="Subject"
                  value={editingTemplate.subject_template}
                  onChange={val => setEditingTemplate({ ...editingTemplate, subject_template: val })}
                  placeholder="[Sentora] Critical alerts on {{agent}}"
                />
                <div>
                  <label style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-secondary)', display: 'block', marginBottom: '8px' }}>
                    Body
                  </label>
                  <textarea
                    value={editingTemplate.body_template}
                    onChange={e => setEditingTemplate({ ...editingTemplate, body_template: e.target.value })}
                    spellCheck={false}
                    placeholder={'Agent: {{agent}}\n\n{{body}}'}
                    style={{
                      width: '100%', height: '160px', backgroundColor: 'rgba(0,0,0,0.3)',
                      border: '1px solid var(--border-color)', borderRadius: '8px', padding: '14px',
                      color: 'white', fontFamily: 'monospace', fontSize: '0.8125rem',
                      lineHeight: 1.6, outline: 'none', resize: 'vertical',
                    }}
                  />
                </div>
                <div style={{ display: 'flex', gap: '12px' }}>
                  <button onClick={() => setEditingTemplate(null)} style={{ flex: 1, padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)', color: 'white', fontWeight: 600 }}>
                    Cancel
                  </button>
                  <button
                    onClick={handleSaveTemplate}
                    disabled={!editingTemplate.template_name.trim() || !editingTemplate.subject_template.trim() || !editingTemplate.body_template.trim()}
                    style={{
                      flex: 1, padding: '12px', borderRadius: '8px', color: 'white', fontWeight: 700,
                      display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                      backgroundColor: (!editingTemplate.template_name.trim() || !editingTemplate.subject_template.trim() || !editingTemplate.body_template.trim())
                        ? 'var(--border-color)' : 'var(--accent-secondary)',
                    }}
                  >
                    <Save size={16} /> Save Template
                  </button>
                </div>
              </div>
            </div>
          )}
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
