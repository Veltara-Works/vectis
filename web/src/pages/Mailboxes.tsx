import { useState, useEffect, FormEvent } from 'react'
import { api } from '../api/client.ts'

interface Domain { id: string; name: string }
interface Mailbox {
  id: string; domain_id: string; local_part: string;
  display_name?: string; quota_mb: number; active: boolean; created_at: string;
}

export default function MailboxesPage() {
  const [domains, setDomains] = useState<Domain[]>([])
  const [selectedDomain, setSelectedDomain] = useState('')
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([])
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ local_part: '', password: '', display_name: '', quota_mb: '1024' })
  const [resetTarget, setResetTarget] = useState<{ id: string; email: string } | null>(null)
  const [resetPassword, setResetPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => { api.listDomains().then(d => setDomains(d || [])) }, [])

  useEffect(() => {
    if (selectedDomain) {
      api.listMailboxes(selectedDomain).then(m => setMailboxes(m || [])).catch(() => setMailboxes([]))
    }
  }, [selectedDomain])

  // Auto-select first domain
  useEffect(() => {
    if (domains.length > 0 && !selectedDomain) setSelectedDomain(domains[0].id)
  }, [domains])

  const domainName = domains.find(d => d.id === selectedDomain)?.name || ''

  const handleAdd = async (e: FormEvent) => {
    e.preventDefault()
    setError(''); setSuccess('')
    try {
      await api.createMailbox(
        selectedDomain, form.local_part, form.password,
        form.display_name || undefined, parseInt(form.quota_mb) || undefined
      )
      setForm({ local_part: '', password: '', display_name: '', quota_mb: '1024' })
      setShowAdd(false)
      setSuccess(`Mailbox ${form.local_part}@${domainName} created`)
      api.listMailboxes(selectedDomain).then(setMailboxes)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create mailbox')
    }
  }

  const handleDelete = async (id: string, localPart: string) => {
    if (!confirm(`Delete mailbox ${localPart}@${domainName}? This cannot be undone.`)) return
    try {
      // The API requires X-Confirm-Delete header — we'll use fetch directly
      const res = await fetch(`/api/v1/mailboxes/${id}`, {
        method: 'DELETE',
        headers: { 'X-Confirm-Delete': 'true' },
        credentials: 'include',
      })
      const json = await res.json()
      if (json.error) throw new Error(json.error.message)
      api.listMailboxes(selectedDomain).then(setMailboxes)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete mailbox')
    }
  }

  const handleResetPassword = async (e: FormEvent) => {
    e.preventDefault()
    if (!resetTarget) return
    setError(''); setSuccess('')
    try {
      await api.updateMailbox(resetTarget.id, { password: resetPassword })
      setSuccess(`Password reset for ${resetTarget.email}`)
      setResetTarget(null)
      setResetPassword('')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to reset password')
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 className="page-title" style={{ margin: 0 }}>Mailboxes</h2>
        <button className="btn" onClick={() => setShowAdd(!showAdd)} disabled={!selectedDomain}>
          {showAdd ? 'Cancel' : 'Add Mailbox'}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <div className="card">
        <div className="form-group">
          <label>Select Domain</label>
          <select value={selectedDomain} onChange={e => setSelectedDomain(e.target.value)}>
            {domains.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </div>
      </div>

      {showAdd && (
        <div className="card">
          <form onSubmit={handleAdd}>
            <div className="form-group">
              <label>Username</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input value={form.local_part} onChange={e => setForm({ ...form, local_part: e.target.value })}
                  placeholder="e.g. john" required autoFocus style={{ flex: 1 }} />
                <span className="text-muted">@{domainName}</span>
              </div>
              <small className="text-muted">The part before the @ in the email address</small>
            </div>
            <div className="form-group">
              <label>Password</label>
              <input type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })}
                placeholder="Password" required />
            </div>
            <div className="form-group">
              <label>Display Name (optional)</label>
              <input value={form.display_name} onChange={e => setForm({ ...form, display_name: e.target.value })}
                placeholder="John Doe" />
            </div>
            <div className="form-group">
              <label>Quota (MB)</label>
              <input type="number" value={form.quota_mb} onChange={e => setForm({ ...form, quota_mb: e.target.value })} />
            </div>
            <button className="btn" type="submit">Create Mailbox</button>
          </form>
        </div>
      )}

      {resetTarget && (
        <div className="card">
          <form onSubmit={handleResetPassword}>
            <h3 style={{ marginTop: 0, marginBottom: '1rem' }}>Reset Password for {resetTarget.email}</h3>
            <div className="form-group">
              <label>New Password</label>
              <input type="password" value={resetPassword} onChange={e => setResetPassword(e.target.value)}
                placeholder="Enter new password (min 8 characters)" required autoFocus />
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button className="btn" type="submit">Set Password</button>
              <button className="btn btn-sm" type="button" onClick={() => setResetTarget(null)}>Cancel</button>
            </div>
          </form>
        </div>
      )}

      <div className="card">
        <table>
          <thead>
            <tr><th>Email</th><th>Display Name</th><th>Quota</th><th>Active</th><th>Created</th><th></th></tr>
          </thead>
          <tbody>
            {mailboxes.map(m => (
              <tr key={m.id}>
                <td><strong>{m.local_part}@{domainName}</strong></td>
                <td className="text-muted">{m.display_name || '-'}</td>
                <td className="mono">{m.quota_mb} MB</td>
                <td><span className={`badge ${m.active ? 'badge-success' : 'badge-danger'}`}>{m.active ? 'yes' : 'no'}</span></td>
                <td className="text-muted">{new Date(m.created_at).toLocaleDateString()}</td>
                <td style={{ display: 'flex', gap: '0.5rem' }}>
                  <button className="btn btn-sm" onClick={() => { setResetTarget({ id: m.id, email: `${m.local_part}@${domainName}` }); setResetPassword('') }}>Reset Password</button>
                  <button className="btn btn-sm btn-danger" onClick={() => handleDelete(m.id, m.local_part)}>Delete</button>
                </td>
              </tr>
            ))}
            {mailboxes.length === 0 && <tr><td colSpan={6} className="text-muted">No mailboxes in this domain</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
