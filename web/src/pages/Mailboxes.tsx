import { useState, useEffect, FormEvent } from 'react'
import { api, type ImportJob } from '../api/client.ts'

interface Domain { id: string; name: string }
interface Mailbox {
  id: string; domain_id: string; local_part: string;
  display_name?: string; quota_mb: number; active: boolean; created_at: string;
  send_suspended?: boolean; send_suspended_reason?: string;
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
  const [copied, setCopied] = useState('')
  const [impersonation, setImpersonation] = useState<{ username: string; password: string; imap_host: string; imap_port: number; expires_at: string } | null>(null)
  const [importTarget, setImportTarget] = useState<{ id: string; email: string } | null>(null)
  const [importForm, setImportForm] = useState({ source_host: '', source_port: '993', source_user: '', source_password: '', source_tls: true })
  const [importJobs, setImportJobs] = useState<ImportJob[]>([])
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  // Poll the target mailbox's import jobs while the Import panel is open, so
  // progress/status updates live without a manual refresh.
  useEffect(() => {
    if (!importTarget) return
    let active = true
    const load = () => api.listImports(importTarget.id).then(j => { if (active) setImportJobs(j || []) }).catch(() => {})
    load()
    const t = setInterval(load, 3000)
    return () => { active = false; clearInterval(t) }
  }, [importTarget])

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

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(label); setTimeout(() => setCopied(''), 2000)
    })
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
      setImpersonation(null)
      setResetTarget(null)
      api.listMailboxes(selectedDomain).then(m => setMailboxes(m || [])).catch(() => setMailboxes([]))
      setTimeout(() => setSuccess(''), 5000)
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

  const handleToggleSend = async (m: Mailbox, email: string) => {
    setError(''); setSuccess('')
    try {
      if (m.send_suspended) {
        await api.resumeMailboxSend(m.id)
        setSuccess(`Sending re-enabled for ${email}`)
      } else {
        if (!confirm(`Suspend sending for ${email}? They can still receive mail, but cannot send via any client or the API until resumed.`)) return
        await api.suspendMailboxSend(m.id, 'Suspended by admin')
        setSuccess(`Sending suspended for ${email} (receive-only)`)
      }
      api.listMailboxes(selectedDomain).then(m => setMailboxes(m || [])).catch(() => setMailboxes([]))
      setTimeout(() => setSuccess(''), 5000)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update sending status')
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

  const openImport = (id: string, email: string) => {
    setError(''); setSuccess('')
    setImportTarget({ id, email })
    setImportJobs([])
    setImportForm({ source_host: '', source_port: '993', source_user: '', source_password: '', source_tls: true })
  }

  const handleStartImport = async (e: FormEvent) => {
    e.preventDefault()
    if (!importTarget) return
    setError(''); setSuccess('')
    try {
      await api.startImport(importTarget.id, {
        source_host: importForm.source_host,
        source_port: parseInt(importForm.source_port) || undefined,
        source_tls: importForm.source_tls,
        source_user: importForm.source_user,
        source_password: importForm.source_password,
      })
      setSuccess(`Import queued for ${importTarget.email}. Messages already present are skipped on re-runs.`)
      setImportForm({ ...importForm, source_password: '' })
      api.listImports(importTarget.id).then(j => setImportJobs(j || [])).catch(() => {})
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to start import')
    }
  }

  const handleCancelImport = async (jobId: string) => {
    if (!importTarget) return
    setError(''); setSuccess('')
    try {
      await api.cancelImport(importTarget.id, jobId)
      setSuccess('Import cancellation requested')
      api.listImports(importTarget.id).then(j => setImportJobs(j || [])).catch(() => {})
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to cancel import')
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
                {form.password && <button type="button" className="btn btn-sm" onClick={() => copyToClipboard(form.password, 'create')}
                  style={{ whiteSpace: 'nowrap' }}>{copied === 'create' ? 'Copied!' : 'Copy'}</button>}
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
                {resetPassword && <button type="button" className="btn btn-sm" onClick={() => copyToClipboard(resetPassword, 'reset')}
                  style={{ whiteSpace: 'nowrap' }}>{copied === 'reset' ? 'Copied!' : 'Copy'}</button>}
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

      {importTarget && (
        <div className="card" style={{ borderColor: '#3b82f6' }}>
          <h3 style={{ marginTop: 0 }}>Import Mail into {importTarget.email}</h3>
          <p className="muted">Pull all mail from an external IMAP account (folders, flags and dates preserved). Safe to re-run for cutover — messages already present are skipped.</p>
          <form onSubmit={handleStartImport}>
            <div className="form-group">
              <label>Source IMAP Host</label>
              <input value={importForm.source_host} onChange={e => setImportForm({ ...importForm, source_host: e.target.value })}
                placeholder="e.g. imap.gmail.com" required autoFocus />
            </div>
            <div style={{ display: 'flex', gap: '1rem' }}>
              <div className="form-group" style={{ flex: 1 }}>
                <label>Port</label>
                <input type="number" value={importForm.source_port} onChange={e => setImportForm({ ...importForm, source_port: e.target.value })} />
              </div>
              <div className="form-group" style={{ flex: 2, display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '1.5rem' }}>
                <input type="checkbox" id="import-tls" checked={importForm.source_tls}
                  onChange={e => setImportForm({ ...importForm, source_tls: e.target.checked, source_port: e.target.checked ? '993' : '143' })} />
                <label htmlFor="import-tls" style={{ margin: 0 }}>Implicit TLS (uncheck for STARTTLS on 143)</label>
              </div>
            </div>
            <div className="form-group">
              <label>Source Username</label>
              <input value={importForm.source_user} onChange={e => setImportForm({ ...importForm, source_user: e.target.value })}
                placeholder="full login at the source server" required />
            </div>
            <div className="form-group">
              <label>Source Password</label>
              <input type="password" value={importForm.source_password} onChange={e => setImportForm({ ...importForm, source_password: e.target.value })}
                placeholder="stored encrypted; used only for the import" required />
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button className="btn" type="submit">Start Import</button>
              <button className="btn btn-sm" type="button" onClick={() => setImportTarget(null)}>Close</button>
            </div>
          </form>

          {importJobs.length > 0 && (
            <table style={{ marginTop: '1rem' }}>
              <thead>
                <tr><th>Status</th><th>Progress</th><th>Imported</th><th>Skipped</th><th>Folder</th><th>Started</th><th></th></tr>
              </thead>
              <tbody>
                {importJobs.map(j => (
                  <tr key={j.id}>
                    <td>
                      <span className={`badge ${j.status === 'completed' ? 'badge-success' : j.status === 'failed' ? 'badge-danger' : j.status === 'cancelled' ? 'badge-muted' : 'badge-warning'}`}
                        title={j.error_message || ''}>{j.status}</span>
                    </td>
                    <td className="mono">{j.progress < 0 ? '—' : `${j.progress}%`}{j.total_messages > 0 ? ` of ${j.total_messages}` : ''}</td>
                    <td className="mono">{j.imported_count}</td>
                    <td className="mono">{j.skipped_count}</td>
                    <td className="text-muted">{j.current_folder || '-'}</td>
                    <td className="text-muted">{new Date(j.started_at).toLocaleString()}</td>
                    <td>
                      {(j.status === 'pending' || j.status === 'running') && (
                        <button className="btn btn-sm btn-danger" onClick={() => handleCancelImport(j.id)}>Cancel</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      <div className="card">
        <table>
          <thead>
            <tr><th>Email</th><th>Display Name</th><th>Quota</th><th>Active</th><th>Sending</th><th>Created</th><th></th></tr>
          </thead>
          <tbody>
            {mailboxes.map(m => (
              <tr key={m.id}>
                <td><strong>{m.local_part}@{domainName}</strong></td>
                <td className="text-muted">{m.display_name || '-'}</td>
                <td className="mono">{m.quota_mb} MB</td>
                <td><span className={`badge ${m.active ? 'badge-success' : 'badge-danger'}`}>{m.active ? 'yes' : 'no'}</span></td>
                <td>
                  <span className={`badge ${m.send_suspended ? 'badge-danger' : 'badge-success'}`}
                    title={m.send_suspended ? (m.send_suspended_reason || 'Sending suspended') : 'Sending allowed'}>
                    {m.send_suspended ? 'suspended' : 'allowed'}
                  </span>
                </td>
                <td className="text-muted">{new Date(m.created_at).toLocaleDateString()}</td>
                <td style={{ display: 'flex', gap: '0.5rem' }}>
                  <button className="btn btn-sm" onClick={() => handleImpersonate(m.id, `${m.local_part}@${domainName}`)}>View as User</button>
                  <button className="btn btn-sm" onClick={() => openImport(m.id, `${m.local_part}@${domainName}`)}>Import Mail</button>
                  <button className="btn btn-sm" onClick={() => { setResetTarget({ id: m.id, email: `${m.local_part}@${domainName}` }); setResetPassword('') }}>Reset Password</button>
                  <button className={`btn btn-sm ${m.send_suspended ? '' : 'btn-danger'}`}
                    onClick={() => handleToggleSend(m, `${m.local_part}@${domainName}`)}>
                    {m.send_suspended ? 'Resume Sending' : 'Suspend Sending'}
                  </button>
                  <button className="btn btn-sm btn-danger" onClick={() => handleDelete(m.id, m.local_part)}>Delete</button>
                </td>
              </tr>
            ))}
            {mailboxes.length === 0 && <tr><td colSpan={7} className="text-muted">No mailboxes in this domain</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
