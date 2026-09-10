/**
 * Who can sign in, and what each of them is allowed to do.
 *
 * The page had no loading, empty or failed state. `fetchData` caught its own
 * error and wrote it to the browser console, so a request that failed rendered
 * an empty user list - and on this page in particular that is the worst thing
 * it could render. "Nobody has access" and "we could not find out who has
 * access" look identical, and an operator who reads the first when the second
 * is true concludes the platform is locked down.
 *
 * The three dialogs here were three copies of the same forty lines. They are
 * `Modal` now, which also means Escape closes them.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { UserPlus, Shield, Trash2, Key } from 'lucide-react';
import { adminService } from '../services/api';
import {
  PageHeader, Card, Badge, DataTable, Row, Cell,
  EmptyState, ErrorState, LoadingState, Modal, Field, DialogButton,
} from '../components/ui';

type User = { id: number; username: string; role: string; created_at?: string };
type Permission = { id: number; name: string; description?: string };
type Role = { id: number; role_name: string; permissions: Permission[] };

const AdminUsers: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showUserModal, setShowUserModal] = useState(false);
  const [showRoleModal, setShowRoleModal] = useState(false);
  const [resetUser, setResetUser] = useState<User | null>(null);
  const [editingRole, setEditingRole] = useState<Role | null>(null);

  const [newUser, setNewUser] = useState({ username: '', password: '', role: '' });
  const [newRole, setNewRole] = useState({ role_name: '' });
  const [newPassword, setNewPassword] = useState('');

  const fetchData = useCallback(async () => {
    try {
      const [userData, roleData, permData] = await Promise.all([
        adminService.getUsers(),
        adminService.getRoles(),
        adminService.getPermissions(),
      ]);
      setUsers(userData);
      setRoles(roleData);
      setPermissions(permData);
      setError(null);
      setNewUser((prev) => (prev.role ? prev : { ...prev, role: roleData[0]?.role_name || '' }));
    } catch (err: any) {
      // Said on the page, not to the browser console. An empty table on the
      // access-control page reads as "no accounts exist".
      setError(err?.response?.data?.message || err?.message || 'Request failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await adminService.createUser(newUser);
      setShowUserModal(false);
      setNewUser({ username: '', password: '', role: roles[0]?.role_name || '' });
      fetchData();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to create user');
    }
  };

  const handleDeleteUser = async (id: number) => {
    if (!window.confirm('Delete this user?')) return;
    try {
      await adminService.deleteUser(id);
      fetchData();
    } catch {
      alert('Failed to delete user');
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetUser) return;
    try {
      await adminService.resetUserPassword(resetUser.id, newPassword);
      setResetUser(null);
      setNewPassword('');
      alert('Password reset successfully.');
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to reset password');
    }
  };

  const handleCreateRole = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await adminService.createRole(newRole);
      setShowRoleModal(false);
      setNewRole({ role_name: '' });
      fetchData();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to create role');
    }
  };

  const togglePermission = async (role: Role, permName: string) => {
    const current = Array.isArray(role.permissions) ? role.permissions.map((p) => p.name) : [];
    const updated = current.includes(permName)
      ? current.filter((p) => p !== permName)
      : [...current, permName];
    try {
      await adminService.updateRolePermissions(role.id, role.role_name, updated);
      fetchData();
    } catch {
      alert('Failed to update permissions');
    }
  };

  const handleDeleteRole = async (id: number) => {
    if (!window.confirm('Delete this role?')) return;
    try {
      await adminService.deleteRole(id);
      fetchData();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete role');
    }
  };

  return (
    <div>
      <PageHeader
        title="Identity & Access"
        subtitle="Who can sign in, which role they hold, and what that role is permitted to do."
        icon={<Shield size={22} />}
        actions={
          <>
            <button className="btn-secondary" onClick={() => setShowRoleModal(true)}>
              <Shield size={16} /> New role
            </button>
            <button className="btn-primary" onClick={() => setShowUserModal(true)}>
              <UserPlus size={16} /> Add user
            </button>
          </>
        }
      />

      {error && (
        <ErrorState
          title="Could not load users and roles"
          detail={`${error}. This is not an empty platform - the list below is unknown, not zero.`}
        />
      )}

      {!error && (
        <div className="responsive-grid">
          <Card title="Accounts">
            {loading ? (
              <LoadingState label="Loading accounts…" />
            ) : users.length === 0 ? (
              <EmptyState
                title="No accounts"
                detail="Every platform needs at least one. Add a user to begin."
              />
            ) : (
              <DataTable columns={['User', 'Role', 'Created', '']}>
                {users.map((user) => (
                  <Row key={user.id}>
                    <Cell>{user.username}</Cell>
                    <Cell>
                      <Badge tone={user.role === 'admin' ? 'critical' : 'info'}>
                        {user.role}
                      </Badge>
                    </Cell>
                    <Cell mono>{user.created_at || '—'}</Cell>
                    <Cell align="right">
                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)' }}>
                        <button
                          className="icon-btn"
                          title="Reset password"
                          onClick={() => { setResetUser(user); setNewPassword(''); }}
                        >
                          <Key size={15} />
                        </button>
                        <button
                          className="icon-btn"
                          title={user.username === 'admin' ? 'The admin account cannot be deleted' : 'Delete'}
                          onClick={() => handleDeleteUser(user.id)}
                          disabled={user.username === 'admin'}
                          style={{ color: 'var(--accent-color)' }}
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </Cell>
                  </Row>
                ))}
              </DataTable>
            )}
          </Card>

          <Card title="Roles">
            {loading ? (
              <LoadingState label="Loading roles…" />
            ) : roles.length === 0 ? (
              <EmptyState title="No roles defined" detail="A user needs a role to be created." />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {roles.map((role) => {
                  const open = editingRole?.id === role.id;
                  return (
                    <div
                      key={role.id}
                      style={{
                        border: '1px solid var(--border-color)',
                        borderRadius: 'var(--radius-md)',
                        padding: 'var(--space-3)',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex', alignItems: 'center',
                          justifyContent: 'space-between', gap: 'var(--space-2)',
                        }}
                      >
                        <Badge tone={role.role_name === 'admin' ? 'critical' : 'neutral'}>
                          {role.role_name}
                        </Badge>
                        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                          <button
                            className="btn-secondary"
                            onClick={() => setEditingRole(open ? null : role)}
                          >
                            {open ? 'Close' : 'Permissions'}
                          </button>
                          {role.role_name !== 'admin' && (
                            <button
                              className="icon-btn"
                              title="Delete role"
                              onClick={() => handleDeleteRole(role.id)}
                              style={{ color: 'var(--accent-color)' }}
                            >
                              <Trash2 size={14} />
                            </button>
                          )}
                        </div>
                      </div>

                      {open && (
                        <div
                          style={{
                            display: 'flex', flexDirection: 'column',
                            gap: 'var(--space-2)', marginTop: 'var(--space-3)',
                            paddingTop: 'var(--space-3)',
                            borderTop: '1px solid var(--border-color)',
                          }}
                        >
                          {role.role_name === 'admin' && (
                            <p
                              style={{
                                margin: 0, color: 'var(--text-muted)',
                                fontSize: 'var(--text-xs)',
                              }}
                            >
                              admin holds every permission and cannot be edited. A platform
                              with no full-access role is a platform nobody can recover.
                            </p>
                          )}
                          {permissions.map((perm) => {
                            const assigned = role.permissions?.some((p) => p.name === perm.name);
                            return (
                              <label
                                key={perm.id}
                                style={{
                                  display: 'flex', alignItems: 'center',
                                  gap: 'var(--space-2)', cursor: 'pointer',
                                  fontSize: 'var(--text-sm)',
                                  color: assigned ? 'var(--text-primary)' : 'var(--text-secondary)',
                                }}
                              >
                                <input
                                  type="checkbox"
                                  checked={!!assigned}
                                  onChange={() => togglePermission(role, perm.name)}
                                  disabled={role.role_name === 'admin'}
                                  style={{ width: 'auto', padding: 0 }}
                                />
                                {perm.description || perm.name}
                              </label>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </div>
      )}

      {showUserModal && (
        <Modal title="Create user" onClose={() => setShowUserModal(false)}>
          <form
            onSubmit={handleCreateUser}
            style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}
          >
            <Field label="Username">
              <input
                type="text"
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                required
                autoFocus
              />
            </Field>
            <Field label="Password">
              <input
                type="password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                required
              />
            </Field>
            <Field label="Role" hint="What this account is permitted to do.">
              <select
                value={newUser.role}
                onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
              >
                {roles.map((r) => (
                  <option key={r.id} value={r.role_name}>{r.role_name}</option>
                ))}
              </select>
            </Field>
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <DialogButton onClick={() => setShowUserModal(false)}>Cancel</DialogButton>
              <DialogButton type="submit" variant="solid">Create user</DialogButton>
            </div>
          </form>
        </Modal>
      )}

      {resetUser && (
        <Modal
          title="Reset password"
          subtitle={<>Set a new password for <strong>{resetUser.username}</strong>.</>}
          onClose={() => setResetUser(null)}
        >
          <form
            onSubmit={handleResetPassword}
            style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}
          >
            <Field label="New password" hint="At least six characters.">
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                minLength={6}
                autoFocus
              />
            </Field>
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <DialogButton onClick={() => setResetUser(null)}>Cancel</DialogButton>
              <DialogButton type="submit" variant="solid" tone="critical">
                Reset password
              </DialogButton>
            </div>
          </form>
        </Modal>
      )}

      {showRoleModal && (
        <Modal title="Create role" onClose={() => setShowRoleModal(false)}>
          <form
            onSubmit={handleCreateRole}
            style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}
          >
            <Field label="Role name" hint="Permissions are assigned after it exists.">
              <input
                type="text"
                value={newRole.role_name}
                onChange={(e) => setNewRole({ role_name: e.target.value })}
                required
                placeholder="analyst"
                autoFocus
              />
            </Field>
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              <DialogButton onClick={() => setShowRoleModal(false)}>Cancel</DialogButton>
              <DialogButton type="submit" variant="solid">Create role</DialogButton>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};

export default AdminUsers;
