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
  const [showPassword, setShowPassword] = useState(false)
  const [showResetPw, setShowResetPw] = useState(false)
  const [passwordError, setPasswordError] = useState('')
  const [resetTarget, setResetTarget] = useState<{ id: string; email: string } | null>(null)
  const [resetPassword, setResetPassword] = useState('')
  const [resetPasswordError, setResetPasswordError] = useState('')
  const [impersonation, setImpersonation] = useState<{ username: string; password: string; imap_host: string; imap_port: number; expires_at: string } | null>(null)
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

  const generatePassword = (): string => {
    const lower = 'abcdefghijklmnopqrstuvwxyz'
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    const digits = '0123456789'
    const symbols = '!@#$%&*-_=+'
    const all = lower + upper + digits + symbols
    const arr = new Uint8Array(20)
    crypto.getRandomValues(arr)
    // Ensure at least one of each required type
    let pw = lower[arr[0] % lower.length]
      + upper[arr[1] % upper.length]
      + digits[arr[2] % digits.length]
      + symbols[arr[3] % symbols.length]
    for (let i = 4; i < arr.length; i++) pw += all[arr[i] % all.length]
    // Shuffle
    return pw.split('').sort(() => Math.random() - 0.5).join('')
  }

  const validatePassword = (pw: string): string => {
    if (pw.length < 12) return 'Password must be at least 12 characters'
    if (!/[a-zA-Z]/.test(pw)) return 'Password must contain at least one letter'
    if (!/[0-9]/.test(pw)) return 'Password must contain at least one number'
    return ''
  }

  const handleAdd = async (e: FormEvent) => {
    e.preventDefault()
    setError(''); setSuccess('')
    const pwErr = validatePassword(form.password)
    if (pwErr) { setPasswordError(pwErr); return }
    setPasswordError('')
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
      const text = await res.text()
      if (text) {
        const json = JSON.parse(text)
        if (json.error) throw new Error(json.error.message)
      }
      setSuccess(`Mailbox ${localPart}@${domainName} deleted`)
      api.listMailboxes(selectedDomain).then(m => setMailboxes(m || [])).catch(() => setMailboxes([]))
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete mailbox')
    }
  }

  const handleResetPassword = async (e: FormEvent) => {
    e.preventDefault()
    if (!resetTarget) return
    setError(''); setSuccess('')
    const pwErr = validatePassword(resetPassword)
    if (pwErr) { setResetPasswordError(pwErr); return }
    setResetPasswordError('')
    try {
      await api.updateMailbox(resetTarget.id, { password: resetPassword })
      setSuccess(`Password reset for ${resetTarget.email}`)
      setResetTarget(null)
      setResetPassword('')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to reset password')
    }
  }

  const handleImpersonate = async (id: string, email: string) => {
    setError(''); setSuccess('')
    try {
      const creds = await api.impersonate(id)
      setImpersonation({ ...creds, username: creds.username })
      setSuccess(`Temporary IMAP credentials generated for ${email}`)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to generate impersonation credentials')
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
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input type={showPassword ? 'text' : 'password'} value={form.password}
                  onChange={e => { setForm({ ...form, password: e.target.value }); setPasswordError('') }}
                  placeholder="Min 12 characters, letters + numbers" required style={{ flex: 1 }} />
                <button type="button" className="btn btn-sm" onClick={() => setShowPassword(!showPassword)}
                  style={{ whiteSpace: 'nowrap' }}>{showPassword ? 'Hide' : 'Show'}</button>
                <button type="button" className="btn btn-sm" onClick={() => {
                  const pw = generatePassword(); setForm({ ...form, password: pw }); setShowPassword(true); setPasswordError('')
                }} style={{ whiteSpace: 'nowrap' }}>Generate</button>
              </div>
              {passwordError && <small style={{ color: '#ef4444', marginTop: '0.25rem', display: 'block' }}>{passwordError}</small>}
              {form.password && !passwordError && (
                <small style={{ color: form.password.length >= 12 && /[a-zA-Z]/.test(form.password) && /[0-9]/.test(form.password) ? '#10b981' : '#f59e0b', marginTop: '0.25rem', display: 'block' }}>
                  {form.password.length < 12 ? `${form.password.length}/12 characters` : 'Password meets requirements'}
                </small>
              )}
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
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input type={showResetPw ? 'text' : 'password'} value={resetPassword}
                  onChange={e => { setResetPassword(e.target.value); setResetPasswordError('') }}
                  placeholder="Min 12 characters, letters + numbers" required autoFocus style={{ flex: 1 }} />
                <button type="button" className="btn btn-sm" onClick={() => setShowResetPw(!showResetPw)}
                  style={{ whiteSpace: 'nowrap' }}>{showResetPw ? 'Hide' : 'Show'}</button>
                <button type="button" className="btn btn-sm" onClick={() => {
                  const pw = generatePassword(); setResetPassword(pw); setShowResetPw(true); setResetPasswordError('')
                }} style={{ whiteSpace: 'nowrap' }}>Generate</button>
              </div>
              {resetPasswordError && <small style={{ color: '#ef4444', marginTop: '0.25rem', display: 'block' }}>{resetPasswordError}</small>}
              {resetPassword && !resetPasswordError && (
                <small style={{ color: resetPassword.length >= 12 && /[a-zA-Z]/.test(resetPassword) && /[0-9]/.test(resetPassword) ? '#10b981' : '#f59e0b', marginTop: '0.25rem', display: 'block' }}>
                  {resetPassword.length < 12 ? `${resetPassword.length}/12 characters` : 'Password meets requirements'}
                </small>
              )}
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button className="btn" type="submit">Set Password</button>
              <button className="btn btn-sm" type="button" onClick={() => setResetTarget(null)}>Cancel</button>
            </div>
          </form>
        </div>
      )}

      {impersonation && (
        <div className="card" style={{ borderColor: '#3b82f6' }}>
          <h3 style={{ marginTop: 0 }}>Temporary IMAP Credentials</h3>
          <p className="muted">Use these credentials to access this mailbox via any IMAP client. They expire automatically.</p>
          <table>
            <tbody>
              <tr><td><strong>IMAP Host</strong></td><td className="mono">{impersonation.imap_host}</td></tr>
              <tr><td><strong>IMAP Port</strong></td><td className="mono">{impersonation.imap_port}</td></tr>
              <tr><td><strong>Username</strong></td><td className="mono">{impersonation.username}</td></tr>
              <tr><td><strong>Password</strong></td><td className="mono">{impersonation.password}</td></tr>
              <tr><td><strong>Expires</strong></td><td>{new Date(impersonation.expires_at).toLocaleString()}</td></tr>
            </tbody>
          </table>
          <button className="btn btn-sm" style={{ marginTop: '0.5rem' }} onClick={() => setImpersonation(null)}>Dismiss</button>
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
                  <button className="btn btn-sm" onClick={() => handleImpersonate(m.id, `${m.local_part}@${domainName}`)}>View as User</button>
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
