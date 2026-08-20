/**
 * Catalogue of SOAR actions a playbook step can perform.
 *
 * The editor used a flat 17-entry <select> where every action got the same
 * bare "target" text box — including the ones that take no parameter at all,
 * which left an empty field the operator could not tell was meant to stay
 * empty. Worse, nothing validated the value, so `block_ip` with a typo saved
 * happily and failed later on the endpoint, where the reason was invisible.
 *
 * Each entry here carries what the editor needs to guide input and what the
 * operator needs to judge the step before running it.
 */

export type ActionCategory = 'network' | 'process' | 'account' | 'file' | 'system' | 'container';

export type ActionSpec = {
  value: string;
  label: string;
  category: ActionCategory;
  /** What it does, in the operator's terms. Shown under the picker. */
  description: string;
  /** Undefined when the action takes no parameter. */
  param?: {
    label: string;
    placeholder: string;
    /** Returns an error string, or null when the value is acceptable. */
    validate: (value: string) => string | null;
  };
  /**
   * Cannot be undone from the console. `isolate_host` cuts the network path
   * the console itself uses to reach the agent; `delete_file` has no restore.
   * The editor warns before saving a playbook containing one.
   */
  destructive?: boolean;
};

const required = (label: string) => (v: string): string | null =>
  v.trim() ? null : `${label} is required`;

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

const validateIp = (v: string): string | null => {
  const t = v.trim();
  if (!t) return 'Target IP is required';
  // Templates are resolved at run time against the triggering event.
  if (t.includes('{{')) return null;
  if (!IPV4.test(t)) return `"${t}" is not a valid IPv4 address`;
  return null;
};

const validatePath = (v: string): string | null => {
  const t = v.trim();
  if (!t) return 'File path is required';
  if (t.includes('{{')) return null;
  const absolute = t.startsWith('/') || /^[A-Za-z]:[\\/]/.test(t);
  if (!absolute) return 'Use an absolute path — the agent resolves relative paths from its own working directory';
  return null;
};

const validateProcess = (v: string): string | null => {
  const t = v.trim();
  if (!t) return 'PID or process name is required';
  if (t.includes('{{')) return null;
  if (/^\d+$/.test(t)) {
    if (Number(t) <= 0) return 'PID must be a positive number';
    if (Number(t) === 1) return 'PID 1 is the init process — killing it takes the host down';
  }
  return null;
};

const validateUser = (v: string): string | null => {
  const t = v.trim();
  if (!t) return 'Username is required';
  if (t.includes('{{')) return null;
  if (/\s/.test(t)) return 'Usernames cannot contain spaces';
  return null;
};

export const ACTIONS: ActionSpec[] = [
  {
    value: 'block_ip', label: 'Block IP Address', category: 'network',
    description: 'Adds a firewall drop rule for the address on the endpoint.',
    param: { label: 'Target IP', placeholder: '203.0.113.10 or {{event.ip}}', validate: validateIp },
  },
  {
    value: 'unblock_ip', label: 'Unblock IP Address', category: 'network',
    description: 'Removes a previously added drop rule.',
    param: { label: 'Target IP', placeholder: '203.0.113.10', validate: validateIp },
  },
  {
    value: 'flush_dns', label: 'Flush DNS Cache', category: 'network',
    description: 'Clears the resolver cache. Useful after blocking a C2 domain.',
  },
  {
    value: 'isolate_host', label: 'Isolate Host from Network', category: 'network',
    description: 'Cuts all network access except the agent channel. You will lose remote access to this machine.',
    destructive: true,
  },
  {
    value: 'kill_process', label: 'Kill Process', category: 'process',
    description: 'Terminates a process by PID or image name.',
    param: { label: 'PID or Name', placeholder: '4812 or powershell.exe', validate: validateProcess },
  },
  {
    value: 'suspend_process', label: 'Suspend Process', category: 'process',
    description: 'Freezes a process without killing it, so it can be inspected first.',
    param: { label: 'PID or Name', placeholder: '4812 or powershell.exe', validate: validateProcess },
  },
  {
    value: 'restart_service', label: 'Restart Service', category: 'process',
    description: 'Restarts a system service by name.',
    param: { label: 'Service Name', placeholder: 'sshd', validate: required('Service name') },
  },
  {
    value: 'disable_user', label: 'Disable User Account', category: 'account',
    description: 'Locks the account. Existing sessions are not ended.',
    param: { label: 'Username', placeholder: 'jdoe or {{event.user}}', validate: validateUser },
  },
  {
    value: 'enable_user', label: 'Enable User Account', category: 'account',
    description: 'Unlocks a previously disabled account.',
    param: { label: 'Username', placeholder: 'jdoe', validate: validateUser },
  },
  {
    value: 'logoff_user', label: 'Log Off User', category: 'account',
    description: 'Ends an interactive session.',
    param: { label: 'Session ID', placeholder: '2', validate: required('Session ID') },
  },
  {
    value: 'lock_machine', label: 'Lock Machine', category: 'account',
    description: 'Locks the console, leaving the session running.',
  },
  {
    value: 'quarantine_file', label: 'Quarantine File', category: 'file',
    description: 'Moves the file to the agent quarantine directory. Reversible.',
    param: { label: 'File Path', placeholder: 'C:\\Users\\x\\evil.exe', validate: validatePath },
  },
  {
    value: 'delete_file', label: 'Delete File', category: 'file',
    description: 'Removes the file permanently. Quarantine is usually the better first move.',
    param: { label: 'File Path', placeholder: '/tmp/payload.sh', validate: validatePath },
    destructive: true,
  },
  {
    value: 'delete_registry_key', label: 'Delete Registry Key', category: 'file',
    description: 'Removes a registry key, typically a persistence entry.',
    param: { label: 'Registry Path', placeholder: 'HKLM\\Software\\...\\Run\\evil', validate: required('Registry path') },
    destructive: true,
  },
  {
    value: 'protect_shadows', label: 'Protect Volume Shadows (VSS)', category: 'system',
    description: 'Hardens shadow copies against deletion — a common ransomware precursor.',
  },
  {
    value: 'clear_temp', label: 'Clear Temp Folders', category: 'system',
    description: 'Empties temporary directories.',
  },
  {
    value: 'run_cmd', label: 'Run Custom Command', category: 'system',
    description: 'Executes an arbitrary command as the agent user. Not on the AI auto-action safe list — it always needs a human.',
    param: { label: 'Command', placeholder: 'systemctl status sshd', validate: required('Command') },
    destructive: true,
  },
];

export const CATEGORY_LABELS: Record<ActionCategory, string> = {
  network: 'Network',
  process: 'Process',
  account: 'Accounts',
  file: 'Files & Registry',
  system: 'System',
  container: 'Containers',
};

export const getAction = (value: string): ActionSpec | undefined =>
  ACTIONS.find(a => a.value === value);

/** Error for a step's parameter, or null when it is acceptable. */
export const validateStep = (action: string, target: string): string | null => {
  const spec = getAction(action);
  if (!spec) return `Unknown action "${action}"`;
  if (!spec.param) return null;
  return spec.param.validate(target || '');
};

/** Free-text search across label, value and description. */
export const searchActions = (query: string): ActionSpec[] => {
  const q = query.trim().toLowerCase();
  if (!q) return ACTIONS;
  return ACTIONS.filter(a =>
    a.label.toLowerCase().includes(q)
    || a.value.includes(q)
    || a.description.toLowerCase().includes(q)
  );
};
