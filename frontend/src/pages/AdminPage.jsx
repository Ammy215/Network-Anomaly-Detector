import { useEffect, useState } from 'react'
import { apiGet, apiPatch } from '../api'
import { useAuth } from '../auth/AuthContext'
import Card from '../components/ui/Card'
import Skeleton from '../components/ui/Skeleton'

const ROLE_OPTIONS = ['admin', 'analyst', 'viewer']

function UsersPanel() {
  const { user } = useAuth()
  const [users, setUsers] = useState(null)
  const [error, setError] = useState(null)
  const [savingId, setSavingId] = useState(null)

  function load() {
    apiGet('/api/admin/users')
      .then((data) => setUsers(data.users))
      .catch((err) => setError(err.message))
  }

  useEffect(load, [])

  async function changeRole(userId, role) {
    setSavingId(userId)
    setError(null)
    try {
      await apiPatch(`/api/admin/users/${userId}/role`, { role })
      load()
    } catch (err) {
      setError(err.message)
    } finally {
      setSavingId(null)
    }
  }

  return (
    <Card>
      <h3 className="mb-3 font-sans text-sm font-semibold text-text-primary">Users</h3>
      {error && <p className="mb-2 text-sm text-accent-red">{error}</p>}
      {!users ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      ) : (
        <table className="w-full border-collapse text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wide text-text-muted">
              <th className="px-3 py-2 font-medium">Email</th>
              <th className="px-3 py-2 font-medium">Role</th>
              <th className="px-3 py-2 font-medium">Joined</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-b border-border/60">
                <td className="px-3 py-2 font-mono text-text-primary">{u.email}</td>
                <td className="px-3 py-2">
                  <select
                    value={u.role}
                    disabled={savingId === u.id || u.id === user?.id}
                    title={u.id === user?.id ? "You can't change your own role." : undefined}
                    onChange={(e) => changeRole(u.id, e.target.value)}
                    className="rounded border border-border bg-bg-elevated px-2 py-1 font-mono text-xs text-text-primary disabled:opacity-50"
                  >
                    {ROLE_OPTIONS.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-3 py-2 text-text-muted">{new Date(u.created_at).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  )
}

function AuditLogPanel() {
  const [entries, setEntries] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    apiGet('/api/admin/audit-log')
      .then((data) => setEntries(data.entries))
      .catch((err) => setError(err.message))
  }, [])

  return (
    <Card delay={0.05}>
      <h3 className="mb-3 font-sans text-sm font-semibold text-text-primary">Audit log</h3>
      {error && <p className="mb-2 text-sm text-accent-red">{error}</p>}
      {!entries ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-8 w-full" />
          ))}
        </div>
      ) : entries.length === 0 ? (
        <p className="text-text-muted">No audit entries yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase tracking-wide text-text-muted">
                <th className="whitespace-nowrap px-3 py-2 font-medium">When</th>
                <th className="px-3 py-2 font-medium">Who</th>
                <th className="px-3 py-2 font-medium">Action</th>
                <th className="px-3 py-2 font-medium">Detail</th>
                <th className="px-3 py-2 font-medium">IP</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} className="border-b border-border/60">
                  <td className="whitespace-nowrap px-3 py-2 text-text-muted">
                    {new Date(e.created_at).toLocaleString()}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-text-primary">{e.user_email}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-text-primary">{e.action}</td>
                  <td className="px-3 py-2 font-mono text-xs text-text-muted">
                    {e.detail ? JSON.stringify(e.detail) : '—'}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-text-muted">
                    {e.ip_address ?? '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

export default function AdminPage() {
  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="font-sans text-xl font-bold text-text-primary">Admin</h2>
        <p className="mt-1 text-sm text-text-muted">Manage user roles and review the audit trail.</p>
      </div>
      <UsersPanel />
      <AuditLogPanel />
    </div>
  )
}
