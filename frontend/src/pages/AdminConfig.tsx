/**
 * The settings the platform runs on: mail, the model, and the directory.
 *
 * `fetchConfigs` logged its failure to the browser console and returned, so a
 * load that failed left every field at its blank default. On this page that is
 * not merely confusing - the forms are editable and they save. An operator who
 * reads blank fields as "nothing is configured", fills them in and presses
 * Save has just overwritten a working SMTP or LDAP configuration with whatever
 * they guessed. The page now says it could not read the settings and does not
 * pretend they are empty.
 *
 * `InputGroup` was this page's own copy of a label-above-a-control, complete
 * with hand-rolled focus and blur handlers that duplicated the `input:focus`
 * rule in index.css. It is the shared `Field` now.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { Mail, BrainCircuit, Save, ShieldCheck, Share2, Globe, Trash2 } from 'lucide-react';
import { adminService } from '../services/api';
import {
  PageHeader, Card, Badge, Field, ErrorState, LoadingState, EmptyState,
} from '../components/ui';

type EmailTemplate = {
  id?: number;
  template_name: string;
  subject_template: string;
  body_template: string;
};

const AdminConfig: React.FC = () => {
  const [emailConfig, setEmailConfig] = useState<any>({
    smtp_server: '', smtp_port: 587, smtp_user: '', smtp_password: '',
    smtp_use_tls: true, email_from: '', email_to: '', enabled: false,
  });
  const [aiConfig, setAiConfig] = useState<any>({
    model_name: 'llama3.2:3b', api_key: 'ollama', endpoint: 'http://ollama:11434/api',
  });
  const [ldapConfig, setLdapConfig] = useState<any>({
    ldap_host: '', ldap_port: 389, users_base: '', group_base: '',
    bind_dn: '', bind_password: '', login_filter: '(uid=%s)',
  });
  const [templates, setTemplates] = useState<EmailTemplate[]>([]);
  const [editingTemplate, setEditingTemplate] = useState<EmailTemplate | null>(null);
  const [templateDefaultName, setTemplateDefaultName] = useState('Critical Alerts (default)');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const say = (err: any, fallback: string) =>
    err?.response?.data?.message || err?.response?.data?.error || err?.message || fallback;

  const fetchConfigs = useCallback(async () => {
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
          email_to: email.email_to || email.to_addr || '',
        });
      }
      if (ai) setAiConfig(ai);
      if (ldap?.config) setLdapConfig(ldap.config);
      setError(null);
    } catch (err) {
      setError(say(err, 'Could not read the current configuration'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchConfigs(); }, [fetchConfigs]);

  const handleSaveEmail = async () => {
    try {
      await adminService.saveEmailConfig(emailConfig);
      alert('Email configuration saved.');
      fetchConfigs();
    } catch (err) {
      alert(say(err, 'Failed to save email configuration'));
    }
  };

  const handleSaveAi = async () => {
    try {
      await adminService.updateAiConfig('server', aiConfig);
      alert('AI configuration saved.');
      fetchConfigs();
    } catch (err) {
      alert(say(err, 'Failed to save AI configuration'));
    }
  };

  const handleSaveLdap = async () => {
    try {
      await adminService.saveLdapConfig(ldapConfig);
      alert('LDAP configuration saved.');
      fetchConfigs();
    } catch (err) {
      alert(say(err, 'Failed to save LDAP configuration'));
    }
  };

  const handleTestLdap = async () => {
    try {
      const res = await adminService.testLdap(ldapConfig);
      alert(res.message || 'LDAP connection succeeded.');
    } catch (err) {
      alert(say(err, 'LDAP connection failed'));
    }
  };

  const handleSaveTemplate = async () => {
    if (!editingTemplate) return;
    try {
      const res = await adminService.saveEmailTemplate(editingTemplate);
      alert(res.message || 'Template saved.');
      setEditingTemplate(null);
      fetchConfigs();
    } catch (err) {
      alert(say(err, 'Failed to save template'));
    }
  };

  const handleDeleteTemplate = async (t: EmailTemplate) => {
    if (!t.id) return;
    if (!window.confirm(`Delete template "${t.template_name}"?`)) return;
    try {
      const res = await adminService.deleteEmailTemplate(t.id);
      alert(res.message || 'Template deleted.');
      fetchConfigs();
    } catch (err) {
      alert(say(err, 'Failed to delete template'));
    }
  };

  const templateIncomplete = !editingTemplate?.template_name.trim()
    || !editingTemplate?.subject_template.trim()
    || !editingTemplate?.body_template.trim();

  if (loading) {
    return (
      <div>
        <PageHeader title="System Configuration" icon={<ShieldCheck size={22} />} />
        <LoadingState label="Reading current settings…" />
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="System Configuration"
        subtitle="Mail, the analysis model, and the directory the platform authenticates against."
        icon={<ShieldCheck size={22} />}
      />

      {error && (
        <div style={{ marginBottom: 'var(--space-5)' }}>
          <ErrorState
            title="Could not read the current configuration"
            detail={`${error}. The fields below are blank because nothing was loaded, not because nothing is set — saving now would overwrite whatever is live.`}
          />
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
        <div className="responsive-grid">
          <Card title={<><Mail size={16} /> Email notifications</>}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <Field label="SMTP server">
                <input
                  value={emailConfig.smtp_server || ''}
                  onChange={(e) => setEmailConfig({ ...emailConfig, smtp_server: e.target.value })}
                  placeholder="smtp.example.com"
                />
              </Field>
              <Field label="SMTP port">
                <input
                  value={emailConfig.smtp_port ?? ''}
                  onChange={(e) => setEmailConfig({ ...emailConfig, smtp_port: parseInt(e.target.value, 10) || 587 })}
                  placeholder="587"
                />
              </Field>
              <Field label="SMTP user">
                <input
                  value={emailConfig.smtp_user || ''}
                  onChange={(e) => setEmailConfig({ ...emailConfig, smtp_user: e.target.value })}
                  placeholder="alerts@example.com"
                />
              </Field>
              <Field label="SMTP password">
                <input
                  type="password"
                  value={emailConfig.smtp_password || ''}
                  onChange={(e) => setEmailConfig({ ...emailConfig, smtp_password: e.target.value })}
                  placeholder="••••••••"
                />
              </Field>
              <Field label="Sender">
                <input
                  value={emailConfig.email_from || ''}
                  onChange={(e) => setEmailConfig({ ...emailConfig, email_from: e.target.value })}
                  placeholder="alerts@example.com"
                />
              </Field>
              <Field label="Recipient" hint="Where critical-alert mail is delivered.">
                <input
                  value={emailConfig.email_to || ''}
                  onChange={(e) => setEmailConfig({ ...emailConfig, email_to: e.target.value })}
                  placeholder="soc@example.com"
                />
              </Field>
              <label
                style={{
                  display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                  fontSize: 'var(--text-sm)', cursor: 'pointer',
                }}
              >
                <input
                  type="checkbox"
                  checked={!!emailConfig.enabled}
                  onChange={(e) => setEmailConfig({ ...emailConfig, enabled: e.target.checked })}
                  style={{ width: 'auto', padding: 0 }}
                />
                Send alert mail
              </label>
              <button className="btn-primary" onClick={handleSaveEmail}>
                <Save size={15} /> Save email settings
              </button>
            </div>
          </Card>

          <Card title={<><BrainCircuit size={16} /> Analysis model</>}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <Field label="Model">
                <input
                  value={aiConfig.model_name || ''}
                  onChange={(e) => setAiConfig({ ...aiConfig, model_name: e.target.value })}
                />
              </Field>
              <Field label="Endpoint">
                <input
                  value={aiConfig.endpoint || ''}
                  onChange={(e) => setAiConfig({ ...aiConfig, endpoint: e.target.value })}
                  placeholder="http://ollama:11434/api"
                />
              </Field>
              <Field label="API key" hint={aiConfig.has_api_key ? 'A key is already stored; leave blank to keep it.' : undefined}>
                <input
                  type="password"
                  value={aiConfig.api_key || ''}
                  onChange={(e) => setAiConfig({ ...aiConfig, api_key: e.target.value })}
                  placeholder={aiConfig.has_api_key ? '•••••••• (set)' : 'Enter API key'}
                />
              </Field>
              <p
                style={{
                  margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
                  lineHeight: 1.6,
                }}
              >
                The model proposes; the criteria in <code>ai/criteria.py</code> decide. A
                verdict whose stated criterion is not in the log is refused regardless of
                which model produced it.
              </p>
              <button className="btn-primary" onClick={handleSaveAi}>
                <ShieldCheck size={15} /> Save model settings
              </button>
            </div>
          </Card>
        </div>

        <Card
          title={<><Mail size={16} /> Alert mail templates</>}
          actions={
            <button
              className="btn-secondary"
              onClick={() => setEditingTemplate({ template_name: '', subject_template: '', body_template: '' })}
            >
              New template
            </button>
          }
        >
          <p
            style={{
              margin: '0 0 var(--space-4)', fontSize: 'var(--text-sm)',
              color: 'var(--text-secondary)', lineHeight: 1.6, maxWidth: '78ch',
            }}
          >
            Critical-alert mail looks for <code>Critical Alerts - Agent: &lt;name&gt;</code> and
            falls back to <code>{templateDefaultName}</code> when the agent has none of its
            own. <code>{'{{agent}}'}</code> and <code>{'{{body}}'}</code> are substituted at
            send time.
          </p>

          {templates.length === 0 ? (
            <EmptyState
              title="No templates"
              detail="Alert mail cannot be sent without one, so nothing is being delivered."
            />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {templates.map((t) => {
                const isFallback = t.template_name === templateDefaultName;
                return (
                  <div
                    key={t.id ?? t.template_name}
                    style={{
                      display: 'flex', alignItems: 'center',
                      justifyContent: 'space-between', gap: 'var(--space-4)',
                      padding: 'var(--space-3)',
                      border: '1px solid var(--border-color)',
                      borderRadius: 'var(--radius-md)',
                    }}
                  >
                    <div style={{ minWidth: 0 }}>
                      <div
                        style={{
                          display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                          flexWrap: 'wrap', fontSize: 'var(--text-sm)',
                        }}
                      >
                        {t.template_name}
                        {isFallback && <Badge tone="ok">fallback</Badge>}
                      </div>
                      <div
                        style={{
                          marginTop: 'var(--space-1)', fontSize: 'var(--text-xs)',
                          color: 'var(--text-muted)', overflow: 'hidden',
                          textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        }}
                      >
                        {t.subject_template}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 'var(--space-2)', flexShrink: 0 }}>
                      <button className="btn-secondary" onClick={() => setEditingTemplate({ ...t })}>
                        Edit
                      </button>
                      <button
                        className="icon-btn"
                        onClick={() => handleDeleteTemplate(t)}
                        disabled={isFallback}
                        title={isFallback
                          ? 'This is the fallback every agent without its own template uses'
                          : 'Delete this template'}
                        style={{ color: isFallback ? undefined : 'var(--accent-color)' }}
                      >
                        <Trash2 size={15} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {editingTemplate && (
            <div
              style={{
                marginTop: 'var(--space-4)', paddingTop: 'var(--space-4)',
                borderTop: '1px solid var(--border-color)',
                display: 'flex', flexDirection: 'column', gap: 'var(--space-4)',
              }}
            >
              <Field label="Template name" hint="Name it per agent to override the fallback.">
                <input
                  value={editingTemplate.template_name}
                  onChange={(e) => setEditingTemplate({ ...editingTemplate, template_name: e.target.value })}
                  placeholder="Critical Alerts - Agent: WIN-01"
                />
              </Field>
              <Field label="Subject">
                <input
                  value={editingTemplate.subject_template}
                  onChange={(e) => setEditingTemplate({ ...editingTemplate, subject_template: e.target.value })}
                  placeholder="[Sentora] Critical alerts on {{agent}}"
                />
              </Field>
              <Field label="Body">
                <textarea
                  className="mono"
                  value={editingTemplate.body_template}
                  onChange={(e) => setEditingTemplate({ ...editingTemplate, body_template: e.target.value })}
                  spellCheck={false}
                  placeholder={'Agent: {{agent}}\n\n{{body}}'}
                  style={{ width: '100%', height: 160, resize: 'vertical', lineHeight: 1.6 }}
                />
              </Field>
              <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                <button className="btn-secondary" onClick={() => setEditingTemplate(null)}>
                  Cancel
                </button>
                <button
                  className="btn-primary"
                  onClick={handleSaveTemplate}
                  disabled={templateIncomplete}
                  title={templateIncomplete ? 'Name, subject and body are all required' : undefined}
                >
                  <Save size={15} /> Save template
                </button>
              </div>
            </div>
          )}
        </Card>

        <Card title={<><Globe size={16} /> LDAP / Active Directory</>}>
          <div className="responsive-grid">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <Field label="Host">
                <input
                  value={ldapConfig.ldap_host || ''}
                  onChange={(e) => setLdapConfig({ ...ldapConfig, ldap_host: e.target.value })}
                  placeholder="ldap://company.local"
                />
              </Field>
              <Field label="Port">
                <input
                  value={ldapConfig.ldap_port ?? ''}
                  onChange={(e) => setLdapConfig({ ...ldapConfig, ldap_port: parseInt(e.target.value, 10) || 389 })}
                  placeholder="389"
                />
              </Field>
              <Field label="User search base">
                <input
                  value={ldapConfig.users_base || ''}
                  onChange={(e) => setLdapConfig({ ...ldapConfig, users_base: e.target.value })}
                  placeholder="ou=Users,dc=company,dc=local"
                />
              </Field>
              <Field label="Group search base">
                <input
                  value={ldapConfig.group_base || ''}
                  onChange={(e) => setLdapConfig({ ...ldapConfig, group_base: e.target.value })}
                  placeholder="ou=Groups,dc=company,dc=local"
                />
              </Field>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <Field label="Bind DN">
                <input
                  value={ldapConfig.bind_dn || ''}
                  onChange={(e) => setLdapConfig({ ...ldapConfig, bind_dn: e.target.value })}
                  placeholder="cn=admin,dc=company,dc=local"
                />
              </Field>
              <Field label="Bind password">
                <input
                  type="password"
                  value={ldapConfig.bind_password || ''}
                  onChange={(e) => setLdapConfig({ ...ldapConfig, bind_password: e.target.value })}
                  placeholder="••••••••"
                />
              </Field>
              <Field label="Login filter" hint="%s is replaced with the username being authenticated.">
                <input
                  value={ldapConfig.login_filter || ''}
                  onChange={(e) => setLdapConfig({ ...ldapConfig, login_filter: e.target.value })}
                  placeholder="(uid=%s)"
                />
              </Field>
              <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                <button className="btn-secondary" onClick={handleTestLdap}>
                  <Share2 size={15} /> Test connection
                </button>
                <button className="btn-primary" onClick={handleSaveLdap}>
                  <Save size={15} /> Save LDAP settings
                </button>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default AdminConfig;
