import { useState, useEffect } from 'react'
import { api } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'

interface Session {
  id: string; ip_address: string; user_agent: string; created_at: string;
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = () => api.sessions().then(d => setSessions(d || [])).catch(() => setError('Failed to load sessions'))
  useEffect(() => { load() }, [])

  const handleRevoke = async (id: string) => {
    setError(''); setSuccess('')
    try {
      await api.deleteSession(id)
      setSuccess('Session revoked')
      load()
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to revoke session'))
    }
  }

  const handleRevokeAll = async () => {
    if (!confirm('Revoke all other sessions? You will remain logged in.')) return
    setError(''); setSuccess('')
    try {
      await api.logoutAll()
      setSuccess('All other sessions revoked. You have been logged out.')
      // After logout-all, current session is also invalidated — reload will redirect to login.
      setTimeout(() => window.location.reload(), 1500)
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to revoke sessions'))
    }
  }

  const parseUA = (ua: string) => {
    if (!ua) return 'Unknown'
    if (ua.length > 80) return ua.substring(0, 77) + '...'
    return ua
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 className="page-title" style={{ margin: 0 }}>Sessions</h2>
        <button className="btn btn-danger" onClick={handleRevokeAll}>Revoke All Sessions</button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <div className="card">
        <table>
          <thead>
            <tr><th>IP Address</th><th>User Agent</th><th>Created</th><th></th></tr>
          </thead>
          <tbody>
            {sessions.map(s => (
              <tr key={s.id}>
                <td className="mono">{s.ip_address || 'unknown'}</td>
                <td className="text-muted" title={s.user_agent}>{parseUA(s.user_agent)}</td>
                <td className="text-muted">{new Date(s.created_at).toLocaleString()}</td>
                <td><button className="btn btn-sm btn-danger" onClick={() => handleRevoke(s.id)}>Revoke</button></td>
              </tr>
            ))}
            {sessions.length === 0 && <tr><td colSpan={4} className="text-muted">No active sessions</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
