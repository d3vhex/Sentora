import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || (import.meta.env.DEV ? 'http://127.0.0.1:8000' : window.location.origin);

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor to add user ID for permission checks
api.interceptors.request.use((config) => {
  const userId = localStorage.getItem('userId');
  if (userId) {
    config.headers['X-User-ID'] = userId;
  }
  return config;
});

export const authService = {
  login: (credentials: any) => api.post('/login', credentials).then(res => {
    if (res.data.status === 'success') {
      localStorage.setItem('userId', res.data.user.id.toString());
      localStorage.setItem('user', JSON.stringify(res.data.user));
      return res.data;
    }
    throw new Error(res.data.message || 'Login failed');
  }),
  logout: () => {
    localStorage.removeItem('userId');
    localStorage.removeItem('user');
    // Clear any other potential stale data
    localStorage.clear(); 
    window.location.href = '/login';
  },
  isAuthenticated: () => !!localStorage.getItem('userId'),
  getUser: () => {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
  },
  hasPermission: (permission: string) => {
    const user = localStorage.getItem('user');
    if (!user) return false;
    const userData = JSON.parse(user);
    if (userData.role === 'admin') return true;
    const perms = userData.permissions || [];
    return perms.includes(permission) || perms.includes('all_permission');
  },
  changePassword: (data: any) => api.post('/change-password', data).then(res => res.data),
};

export const agentService = {
  getAgents: () => api.get('/devices').then(res => res.data.agents),
  checkAgentStatus: (agent: string) => api.get(`/${agent}/check`).then(res => res.data),
  
  // Monitoring
  getSiemEvents: (agent: string, params?: any) => api.get(`/${agent}/siem-events`, { params }).then(res => res.data),
  getEventsAlert: (agent: string, params?: any) => api.get(`/${agent}/events_alert`, { params }).then(res => res.data),
  getAgentResources: (agent: string) => api.get(`/${agent}/resources`).then(res => res.data),
  getAgentDisk: (agent: string) => api.get(`/${agent}/disks`).then(res => res.data),
  getVulnerabilities: (agent: string) => api.get(`/${agent}/vulnerabilities_report`).then(res => res.data),
  getPortscans: (agent: string) => api.get(`/${agent}/portscan_result`).then(res => res.data),
  getCriticalFiles: (agent: string) => api.get(`/${agent}/critical_files`).then(res => res.data),
  getPackages: (agent: string) => api.get(`/${agent}/packages`).then(res => res.data),
  getDockerContainers: (agent: string) => api.get(`/${agent}/docker_containers`).then(res => res.data),
  getAgentInfo: (agent: string) => api.get(`/${agent}/agent_info`).then(res => res.data),
  getAiLogs: (agent: string) => api.get(`/${agent}/ai_logs`).then(res => res.data),
  getAiInsights: (agent: string) => api.get(`/${agent}/ai_insights`).then(res => res.data),
  
  // Agent Lifecycle
  restartAgent: (agent: string) => api.post(`/${agent}/restart`).then(res => res.data),
  reloadAgentLicense: (agent: string) => api.post(`/${agent}/reload_license`).then(res => res.data),
  selfDestructAgent: (agent: string) => api.post(`/${agent}/self_destruct`).then(res => res.data),
  
  // Agent Config
  getAgentYamlConfig: (agent: string, type: string) => api.get(`/${agent}/config/${type}`).then(res => res.data),
  setAgentYamlConfig: (agent: string, type: string, content: string) => api.post(`/${agent}/config/${type}`, { content }).then(res => res.data),
  
  // SOAR Actions
  getSoarActions: (agent: string, params?: any) => api.get(`/${agent}/soar_actions`, { params }).then(res => res.data),
  executeSoarAction: (agent: string, data: any) => api.post(`/${agent}/soar/execute`, data).then(res => res.data),
  resolveSoarAction: (agent: string, id: number, comment: string) => api.patch(`/${agent}/soar_actions/${id}/resolve`, { comment }).then(res => res.data),

  // Shadow Mode (defensive AI proposals awaiting operator approval)
  getShadowPendingAll: () => api.get('/shadow/pending').then(res => res.data),
  getShadowPending: (agent: string) => api.get(`/${agent}/shadow/pending`).then(res => res.data),
  approveShadow: (agent: string, insightId: number) => api.post(`/${agent}/shadow/${insightId}/approve`).then(res => res.data),
  rejectShadow: (agent: string, insightId: number, note?: string) => api.post(`/${agent}/shadow/${insightId}/reject`, { note }).then(res => res.data),

  // Playbooks & Automations
  getPlaybooks: (agent: string) => api.get(`/${agent}/playbooks`).then(res => res.data),
  createPlaybook: (agent: string, data: any) => api.post(`/${agent}/playbooks`, data).then(res => res.data),
  updatePlaybook: (agent: string, id: number, data: any) => api.put(`/${agent}/playbooks/${id}`, data).then(res => res.data),
  deletePlaybook: (agent: string, id: number) => api.delete(`/${agent}/playbooks/${id}`).then(res => res.data),
  
  getPlaybookRuns: (agent: string, params?: any) => api.get(`/${agent}/playbooks/runs`, { params }).then(res => res.data),
  getPlaybookRunDetail: (agent: string, runId: number) => api.get(`/${agent}/playbooks/runs/${runId}`).then(res => res.data),
  
  getAutomations: (agent: string) => api.get(`/${agent}/automations`).then(res => res.data),
  createAutomation: (agent: string, data: any) => api.post(`/${agent}/automations`, data).then(res => res.data),
  updateAutomation: (agent: string, id: number, data: any) => api.put(`/${agent}/automations/${id}`, data).then(res => res.data),
  deleteAutomation: (agent: string, id: number) => api.delete(`/${agent}/automations/${id}`).then(res => res.data),
  
  getAllAlerts: () => api.get('/all_alerts').then(res => res.data),
  getServerResources: () => api.get('/server/resources').then(res => res.data),
  getGlobalStats: () => api.get('/api/global/stats').then(res => res.data),
  runManualAnalysis: (agent: string, limit: number = 100) => api.post(`/analyze-logs/${agent}`, { limit }).then(res => res.data),
  analyzeSelected: (agent: string, logs: any[]) => api.post(`/api/analyze-selected/${agent}`, { logs }).then(res => res.data),
  searchLogs: (params: { agent?: string, table?: string, q?: string, limit?: number }) => api.get('/api/logs/search', { params }).then(res => res.data),
  getCustom: (url: string) => api.get(url).then(res => res.data),
  scanVulns: (agent: string) => api.post(`/${agent}/vulns/scan`).then(res => res.data),
};

export const adminService = {
  getUsers: () => api.get('/users').then(res => res.data.users),
  createUser: (data: any) => api.post('/users', data).then(res => res.data),
  deleteUser: (id: number) => api.delete(`/users/${id}`).then(res => res.data),
  resetUserPassword: (id: number, password: string) => api.put(`/users/${id}/password`, { password }).then(res => res.data),
  
  getRoles: () => api.get('/roles').then(res => res.data.roles),
  createRole: (data: any) => api.post('/roles', data).then(res => res.data),
  deleteRole: (id: number) => api.delete(`/roles/${id}`).then(res => res.data),
  
  getPermissions: () => api.get('/permissions').then(res => res.data.permissions),
  updateRolePermissions: (roleId: number, roleName: string, permissions: string[]) => 
    api.put(`/roles/${roleId}`, { role_name: roleName, permissions }).then(res => res.data),
  
  getEmailConfig: () => api.get('/email-config').then(res => res.data),
  saveEmailConfig: (data: any) => api.post('/email-config', data).then(res => res.data),
  
  getAiConfig: (agent: string) => api.get(`/ai-config/${agent}`).then(res => res.data.config),
  updateAiConfig: (agent: string, data: any) => api.post(`/ai-config/${agent}`, data).then(res => res.data),
  
  getLdapConfig: () => api.get('/ldap').then(res => res.data),
  saveLdapConfig: (data: any) => api.post('/ldap', data).then(res => res.data),
  testLdap: (config: any) => api.post('/ldap/test-connection', config).then(res => res.data),
  
  getDatabases: () => api.get('/databases').then(res => res.data.databases),
  getDatabaseTables: (db: string) => api.get(`/databases/${db}/tables`).then(res => res.data.tables),
  dropDatabase: (db: string) => api.delete(`/databases/${db}`).then(res => res.data),
  getTableColumns: (db: string, table: string) => api.get(`/databases/${db}/tables/${table}/columns`).then(res => res.data.columns),
  getTableData: (db: string, table: string, limit: number = 100) => api.get(`/databases/${db}/tables/${table}/data`, { params: { limit } }).then(res => res.data.data),
  clearTable: (agent: string, table: string) => api.delete(`/${agent}/clear/${table}`).then(res => res.data),
  
  getLoginLogs: () => api.get('/login-logs').then(res => res.data),
  getAuditLogs: () => api.get('/audit-logs').then(res => res.data),
};

export default api;
