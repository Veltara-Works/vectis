import { useState, useEffect } from 'react'
import { api } from '../api/client.ts'

interface AuditEntry {
  id: string; admin_id?: string; action: string; resource_type: string;
  resource_id?: string; details?: Record<string, unknown>; ip_address?: string; created_at: string;
}

const ACTION_OPTIONS = [
  '', 'auth.login', 'domain.create', 'domain.update', 'domain.delete',
  'mailbox.create', 'mailbox.update', 'mailbox.delete',
  'alias.create', 'alias.delete', 'admin.create', 'admin.delete',
]

export default function AuditLogPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [actionFilter, setActionFilter] = useState('')
  const [cursor, setCursor] = useState<string | undefined>(undefined)
  const [hasMore, setHasMore] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const load = async (nextCursor?: string) => {
    setLoading(true)
    setError('')
    try {
      const result = await api.listAudit({
        action: actionFilter || undefined,
        cursor: nextCursor,
        limit: 50,
      })
      const data = result.data || []
      if (nextCursor) {
        setEntries(prev => [...prev, ...data])
      } else {
        setEntries(data)
      }
      const pagination = result.meta?.pagination
      setCursor(pagination?.next_cursor || undefined)
      setHasMore(pagination?.has_more || false)
    } catch {
      setError('Failed to load audit log')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [actionFilter])

  const handleFilterChange = (value: string) => {
    setActionFilter(value)
    setCursor(undefined)
  }

  return (
    <div>
      <h2 className="page-title">Audit Log</h2>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="card">
        <div className="form-group">
          <label>Filter by Action</label>
          <select value={actionFilter} onChange={e => handleFilterChange(e.target.value)}>
            <option value="">All actions</option>
            {ACTION_OPTIONS.filter(a => a !== '').map(a => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="card">
        <table>
          <thead>
            <tr><th>Timestamp</th><th>Admin</th><th>Action</th><th>Resource</th><th>Resource ID</th><th>IP</th></tr>
          </thead>
          <tbody>
            {entries.map(e => (
              <tr key={e.id}>
                <td className="mono" style={{ whiteSpace: 'nowrap' }}>{new Date(e.created_at).toLocaleString()}</td>
                <td className="text-muted">{e.admin_id || '-'}</td>
                <td><span className="badge">{e.action}</span></td>
                <td className="text-muted">{e.resource_type}</td>
                <td className="mono text-muted" style={{ maxWidth: '12rem', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {e.resource_id || '-'}
                </td>
                <td className="mono text-muted">{e.ip_address || '-'}</td>
              </tr>
            ))}
            {entries.length === 0 && !loading && (
              <tr><td colSpan={6} className="text-muted">No audit entries found</td></tr>
            )}
          </tbody>
        </table>

        {hasMore && (
          <div style={{ marginTop: '1rem', textAlign: 'center' }}>
            <button className="btn btn-sm" onClick={() => load(cursor)} disabled={loading}>
              {loading ? 'Loading...' : 'Load More'}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
