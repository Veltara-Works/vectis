import { useState, useEffect, FormEvent } from 'react'
import { api } from '../api/client.ts'

interface Admin {
  id: string; email: string; role: string; totp_enabled: boolean;
  created_at: string; last_login_at?: string;
}

export default function AdminsPage() {
  const [admins, setAdmins] = useState<Admin[]>([])
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ email: '', password: '', role: 'admin' })
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [totpURI, setTotpURI] = useState('')
  const [totpCode, setTotpCode] = useState('')

  const load = () => api.listAdmins().then(d => setAdmins(d || [])).catch(() => setError('Failed to load admins'))
  useEffect(() => { load() }, [])

  const handleAdd = async (e: FormEvent) => {
    e.preventDefault()
    setError(''); setSuccess('')
    try {
      await api.createAdmin(form.email, form.password, form.role)
      setForm({ email: '', password: '', role: 'admin' })
      setShowAdd(false)
      setSuccess(`Admin ${form.email} created`)
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create admin')
    }
  }

  const handleDelete = async (id: string, email: string) => {
    if (!confirm(`Delete admin ${email}? This cannot be undone.`)) return
    setError(''); setSuccess('')
    try {
      await api.deleteAdmin(id)
      setSuccess(`Admin ${email} deleted`)
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete admin')
    }
  }

  const handleTotpSetup = async () => {
    setError(''); setSuccess(''); setTotpURI(''); setTotpCode('')
    try {
      const result = await api.totpSetup()
      setTotpURI(result.provisioning_uri)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to setup TOTP')
    }
  }

  const handleTotpVerify = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      await api.totpVerify(totpCode)
      setSuccess('TOTP enabled successfully')
      setTotpURI('')
      setTotpCode('')
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Invalid TOTP code')
    }
  }

  const handleTotpDisable = async () => {
    const code = prompt('Enter your current authenticator code to disable TOTP:')
    if (!code) return
    setError(''); setSuccess('')
    try {
      await api.totpDisable(code)
      setSuccess('TOTP disabled')
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Invalid code or failed to disable TOTP')
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 className="page-title" style={{ margin: 0 }}>Admins</h2>
        <button className="btn" onClick={() => setShowAdd(!showAdd)}>
          {showAdd ? 'Cancel' : 'Add Admin'}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      {totpURI && (
        <div className="card">
          <h3 className="mb-1">Setup TOTP</h3>
          <p className="text-muted mb-1">Scan this URI in your authenticator app, then enter the 6-digit code to confirm:</p>
          <p className="mono" style={{ wordBreak: 'break-all', fontSize: '0.85rem' }}>{totpURI}</p>
          <form onSubmit={handleTotpVerify} style={{ marginTop: '1rem' }}>
            <div className="form-group">
              <label>Authenticator Code</label>
              <input type="text" value={totpCode} onChange={e => setTotpCode(e.target.value)}
                placeholder="6-digit code" required maxLength={6} pattern="[0-9]{6}" inputMode="numeric"
                autoComplete="one-time-code" autoFocus />
            </div>
            <button className="btn" type="submit">Verify &amp; Enable</button>
            <button type="button" className="btn btn-sm" style={{ marginLeft: '0.5rem' }}
              onClick={() => { setTotpURI(''); setTotpCode('') }}>Cancel</button>
          </form>
        </div>
      )}

      {showAdd && (
        <div className="card">
          <form onSubmit={handleAdd}>
            <div className="form-group">
              <label>Email</label>
              <input type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })}
                placeholder="admin@example.com" required autoFocus />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })}
                placeholder="Minimum 8 characters" required />
            </div>
            <div className="form-group">
              <label>Role</label>
              <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
                <option value="admin">admin</option>
                <option value="superadmin">superadmin</option>
              </select>
            </div>
            <button className="btn" type="submit">Create Admin</button>
          </form>
        </div>
      )}

      <div className="card">
        <table>
          <thead>
            <tr><th>Email</th><th>Role</th><th>TOTP</th><th>Last Login</th><th>Created</th><th></th></tr>
          </thead>
          <tbody>
            {admins.map(a => (
              <tr key={a.id}>
                <td><strong>{a.email}</strong></td>
                <td><span className="badge">{a.role}</span></td>
                <td>
                  <span className={`badge ${a.totp_enabled ? 'badge-success' : 'badge-warning'}`}>
                    {a.totp_enabled ? 'enabled' : 'disabled'}
                  </span>
                </td>
                <td className="text-muted">{a.last_login_at ? new Date(a.last_login_at).toLocaleString() : 'never'}</td>
                <td className="text-muted">{new Date(a.created_at).toLocaleDateString()}</td>
                <td>
                  {!a.totp_enabled && (
                    <button className="btn btn-sm" style={{ marginRight: '0.5rem' }} onClick={handleTotpSetup}>Setup TOTP</button>
                  )}
                  {a.totp_enabled && (
                    <button className="btn btn-sm btn-danger" style={{ marginRight: '0.5rem' }} onClick={handleTotpDisable}>Disable TOTP</button>
                  )}
                  <button className="btn btn-sm btn-danger" onClick={() => handleDelete(a.id, a.email)}>Delete</button>
                </td>
              </tr>
            ))}
            {admins.length === 0 && <tr><td colSpan={6} className="text-muted">No admin accounts</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
