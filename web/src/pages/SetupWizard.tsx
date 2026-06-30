import { useState, useEffect, FormEvent } from 'react'
import { api } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'

interface Domain {
  id: string; name: string; active: boolean; dkim_enabled: boolean;
  dkim_selector: string; verification_status?: string; verification_token?: string; created_at: string;
}

interface Mailbox {
  id: string; domain_id: string; local_part: string;
  display_name?: string; quota_mb: number; active: boolean; created_at: string;
}

interface DkimRecord { dns_name: string; dns_value: string; selector: string }
interface Check { name: string; status: string; value?: string; hint?: string }

const STEPS = [
  { num: 1, title: 'Add Domain', desc: 'Register your first domain' },
  { num: 2, title: 'DNS Records', desc: 'Configure MX, SPF, DKIM & DMARC' },
  { num: 3, title: 'Verify Domain', desc: 'Prove domain ownership via TXT record' },
  { num: 4, title: 'Create Mailbox', desc: 'Set up your first email account' },
  { num: 5, title: 'Deliverability', desc: 'Check your email configuration' },
]

export default function SetupWizard() {
  const [step, setStep] = useState(1)
  const [domains, setDomains] = useState<Domain[]>([])
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  // Step 1 — domain creation
  const [domainName, setDomainName] = useState('')
  const [createdDomain, setCreatedDomain] = useState<Domain | null>(null)

  // Step 2 — DNS records
  const [dkim, setDkim] = useState<DkimRecord | null>(null)

  // Step 3 — verification
  const [verifying, setVerifying] = useState(false)
  const [verifyHint, setVerifyHint] = useState<{ name: string; value: string } | null>(null)

  // Step 4 — mailbox creation
  const [mbForm, setMbForm] = useState({ local_part: '', password: '', display_name: '', quota_mb: '1024' })
  const [showPassword, setShowPassword] = useState(false)
  const [passwordError, setPasswordError] = useState('')
  const [copied, setCopied] = useState('')

  // Step 5 — deliverability
  const [checks, setChecks] = useState<Check[]>([])
  const [checkLoading, setCheckLoading] = useState(false)

  // Server hostname (for the "Connect your device" panel) — fetched once
  // from /config so the IMAP/SMTP host is the actual server FQDN, not a
  // guess based on the mail-domain name.
  const [serverHost, setServerHost] = useState('')

  // Load existing state to determine starting step
  useEffect(() => {
    loadState()
    api.getConfig().then(c => setServerHost(c.config.hostname)).catch(() => {})
  }, [])

  const loadState = async () => {
    setLoading(true)
    try {
      const allDomains = await api.listDomains()
      setDomains(allDomains || [])

      if (allDomains && allDomains.length > 0) {
        const domain = allDomains[0]
        setCreatedDomain(domain as Domain)

        // Load DKIM for DNS step
        try {
          const dkimData = await api.getDKIM(domain.id)
          setDkim(dkimData)
        } catch { /* DKIM not yet available */ }

        if (domain.verification_status === 'verified') {
          // Check for mailboxes
          const mbs = await api.listMailboxes(domain.id)
          setMailboxes(mbs || [])

          if (mbs && mbs.length > 0) {
            setStep(5) // All done except deliverability review
          } else {
            setStep(4) // Need mailbox
          }
        } else {
          setStep(3) // Need verification
        }
      }
      // else step stays at 1
    } catch {
      setError('Failed to load setup state')
    } finally {
      setLoading(false)
    }
  }

  const activeDomain = createdDomain

  // ─── Step 1: Create domain ───
  const handleCreateDomain = async (e: FormEvent) => {
    e.preventDefault()
    setError(''); setSuccess('')
    try {
      const result = await api.createDomain(domainName)
      const allDomains = await api.listDomains()
      const domain = (allDomains || []).find((d: Domain) => d.id === result.domain.id) || allDomains[0]
      setCreatedDomain(domain as Domain)
      setDomains(allDomains || [])

      // Load DKIM
      try {
        const dkimData = await api.getDKIM(result.domain.id)
        setDkim(dkimData)
      } catch { /* */ }

      setSuccess(`Domain ${result.domain.name} created`)
      setStep(2)
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to create domain'))
    }
  }

  // ─── Step 3: Verify domain ───
  const handleVerify = async () => {
    if (!activeDomain) return
    setError(''); setSuccess(''); setVerifying(true)
    try {
      const result = await api.verifyDomain(activeDomain.id)
      if (result.found) {
        setSuccess('Domain verified successfully!')
        setCreatedDomain({ ...activeDomain, verification_status: 'verified' })
        setVerifyHint(null)
        setStep(4)
      } else {
        setVerifyHint({ name: result.txt_record_name, value: result.txt_record_value })
        setError('TXT record not found yet. Add the record shown below and try again.')
      }
    } catch (err: unknown) {
      setError(extractError(err, 'Verification failed'))
    } finally {
      setVerifying(false)
    }
  }

  // ─── Step 4: Create mailbox ───
  const generatePassword = (): string => {
    const lower = 'abcdefghijklmnopqrstuvwxyz'
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    const digits = '0123456789'
    const symbols = '!@#$%&*-_=+'
    const all = lower + upper + digits + symbols
    const arr = new Uint8Array(20)
    crypto.getRandomValues(arr)
    let pw = lower[arr[0] % lower.length]
      + upper[arr[1] % upper.length]
      + digits[arr[2] % digits.length]
      + symbols[arr[3] % symbols.length]
    for (let i = 4; i < arr.length; i++) pw += all[arr[i] % all.length]
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

  const handleCreateMailbox = async (e: FormEvent) => {
    e.preventDefault()
    if (!activeDomain) return
    setError(''); setSuccess('')
    const pwErr = validatePassword(mbForm.password)
    if (pwErr) { setPasswordError(pwErr); return }
    setPasswordError('')
    try {
      await api.createMailbox(
        activeDomain.id, mbForm.local_part, mbForm.password,
        mbForm.display_name || undefined, parseInt(mbForm.quota_mb) || undefined
      )
      setSuccess(`Mailbox ${mbForm.local_part}@${activeDomain.name} created`)
      const mbs = await api.listMailboxes(activeDomain.id)
      setMailboxes(mbs || [])
      setStep(5)
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to create mailbox'))
    }
  }

  // ─── Step 5: Deliverability ───
  const runDeliverability = async () => {
    if (!activeDomain) return
    setCheckLoading(true); setError('')
    try {
      const result = await api.deliverability(activeDomain.id)
      setChecks(result?.checks || [])
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to run checks'))
    } finally {
      setCheckLoading(false)
    }
  }

  useEffect(() => {
    if (step === 5 && activeDomain && checks.length === 0) runDeliverability()
  }, [step])

  const checkLabel = (name: string) => {
    switch (name) {
      case 'mx': return 'MX Record'
      case 'spf': return 'SPF Record'
      case 'dkim': return 'DKIM Record'
      case 'dmarc': return 'DMARC Policy'
      case 'ptr': return 'PTR (Reverse DNS)'
      default: return name.toUpperCase()
    }
  }

  const statusBadge = (status: string) => {
    switch (status) {
      case 'pass': return 'badge-success'
      case 'fail': return 'badge-danger'
      default: return 'badge-warning'
    }
  }

  if (loading) {
    return <div style={{ display: 'flex', justifyContent: 'center', padding: '4rem', color: 'var(--text-muted)' }}>Loading setup state...</div>
  }

  const passCount = checks.filter(c => c.status === 'pass').length
  const allPassed = checks.length > 0 && passCount === checks.length

  return (
    <div>
      <h2 className="page-title">Setup Wizard</h2>

      {/* Progress bar */}
      <div className="wizard-steps">
        {STEPS.map(s => (
          <div key={s.num} className={`wizard-step ${step === s.num ? 'wizard-step-active' : ''} ${step > s.num ? 'wizard-step-done' : ''}`}>
            <div className="wizard-step-num">
              {step > s.num ? '\u2713' : s.num}
            </div>
            <div className="wizard-step-label">
              <div className="wizard-step-title">{s.title}</div>
              <div className="wizard-step-desc">{s.desc}</div>
            </div>
          </div>
        ))}
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      {/* ─── Step 1: Add Domain ─── */}
      {step === 1 && (
        <div className="card">
          <h3 style={{ marginTop: 0, marginBottom: '0.5rem' }}>Add Your Domain</h3>
          <p className="text-muted mb-1">
            Enter the domain name you want to use for email. This will be the part after the @ in your email addresses.
          </p>
          <form onSubmit={handleCreateDomain}>
            <div className="form-group">
              <label>Domain Name</label>
              <input value={domainName} onChange={e => setDomainName(e.target.value)}
                placeholder="example.com" required autoFocus />
            </div>
            <button className="btn" type="submit">Create Domain</button>
          </form>
        </div>
      )}

      {/* ─── Step 2: DNS Records ─── */}
      {step === 2 && activeDomain && (
        <div>
          <div className="card">
            <h3 style={{ marginTop: 0, marginBottom: '0.5rem' }}>Configure DNS Records</h3>
            <p className="text-muted mb-1">
              The records below are required for email delivery and security.
              Add them where <strong>{activeDomain.name}</strong>'s DNS is
              managed — usually your domain registrar (GoDaddy, Namecheap,
              etc.) or <strong>Cloudflare</strong> if your nameservers point
              there. Use the <em>Copy Value</em> buttons to grab each record.
            </p>
            <p className="text-muted mb-1" style={{ fontSize: '0.9em' }}>
              Not sure where to go? Check your registrar's dashboard for a
              "DNS" or "Nameservers" section. If the nameservers read
              <code>*.ns.cloudflare.com</code>, your DNS lives at Cloudflare.
            </p>
          </div>

          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong>MX Record</strong>
              <span className="badge badge-warning">required</span>
            </div>
            <table style={{ marginTop: '0.5rem' }}>
              <tbody>
                <tr><td className="text-muted" style={{ width: '80px' }}>Type</td><td className="mono">MX</td></tr>
                <tr><td className="text-muted">Name</td><td className="mono">{activeDomain.name}</td></tr>
                <tr><td className="text-muted">Value</td><td className="mono">mail.{activeDomain.name}</td></tr>
                <tr><td className="text-muted">Priority</td><td className="mono">10</td></tr>
              </tbody>
            </table>
            <button className="btn btn-sm mt-1" onClick={() => copyToClipboard(`mail.${activeDomain.name}`, 'mx')}>
              {copied === 'mx' ? 'Copied!' : 'Copy Value'}
            </button>
          </div>

          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong>SPF Record</strong>
              <span className="badge badge-warning">required</span>
            </div>
            <table style={{ marginTop: '0.5rem' }}>
              <tbody>
                <tr><td className="text-muted" style={{ width: '80px' }}>Type</td><td className="mono">TXT</td></tr>
                <tr><td className="text-muted">Name</td><td className="mono">{activeDomain.name}</td></tr>
                <tr><td className="text-muted">Value</td><td className="mono" style={{ wordBreak: 'break-all' }}>v=spf1 mx a ~all</td></tr>
              </tbody>
            </table>
            <button className="btn btn-sm mt-1" onClick={() => copyToClipboard('v=spf1 mx a ~all', 'spf')}>
              {copied === 'spf' ? 'Copied!' : 'Copy Value'}
            </button>
          </div>

          {dkim && (
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <strong>DKIM Record</strong>
                <span className="badge badge-warning">required</span>
              </div>
              <table style={{ marginTop: '0.5rem' }}>
                <tbody>
                  <tr><td className="text-muted" style={{ width: '80px' }}>Type</td><td className="mono">TXT</td></tr>
                  <tr><td className="text-muted">Name</td><td className="mono" style={{ wordBreak: 'break-all' }}>{dkim.dns_name}</td></tr>
                  <tr><td className="text-muted">Value</td><td className="mono" style={{ wordBreak: 'break-all' }}>{dkim.dns_value}</td></tr>
                </tbody>
              </table>
              <button className="btn btn-sm mt-1" onClick={() => copyToClipboard(dkim.dns_value, 'dkim')}>
                {copied === 'dkim' ? 'Copied!' : 'Copy Value'}
              </button>
            </div>
          )}

          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong>DMARC Record</strong>
              <span className="badge badge-success">recommended</span>
            </div>
            <table style={{ marginTop: '0.5rem' }}>
              <tbody>
                <tr><td className="text-muted" style={{ width: '80px' }}>Type</td><td className="mono">TXT</td></tr>
                <tr><td className="text-muted">Name</td><td className="mono">_dmarc.{activeDomain.name}</td></tr>
                <tr><td className="text-muted">Value</td><td className="mono" style={{ wordBreak: 'break-all' }}>v=DMARC1; p=quarantine; rua=mailto:postmaster@{activeDomain.name}</td></tr>
              </tbody>
            </table>
            <button className="btn btn-sm mt-1" onClick={() => copyToClipboard(`v=DMARC1; p=quarantine; rua=mailto:postmaster@${activeDomain.name}`, 'dmarc')}>
              {copied === 'dmarc' ? 'Copied!' : 'Copy Value'}
            </button>
          </div>

          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong>Verification TXT Record</strong>
              <span className="badge badge-warning">required</span>
            </div>
            <table style={{ marginTop: '0.5rem' }}>
              <tbody>
                <tr><td className="text-muted" style={{ width: '80px' }}>Type</td><td className="mono">TXT</td></tr>
                <tr><td className="text-muted">Name</td><td className="mono">{activeDomain.name}</td></tr>
                <tr><td className="text-muted">Value</td><td className="mono" style={{ wordBreak: 'break-all' }}>{activeDomain.verification_token}</td></tr>
              </tbody>
            </table>
            <button className="btn btn-sm mt-1" onClick={() => copyToClipboard(activeDomain.verification_token || '', 'verify')}>
              {copied === 'verify' ? 'Copied!' : 'Copy Value'}
            </button>
          </div>

          <p className="text-muted" style={{ fontSize: '0.85rem', marginBottom: '1rem' }}>
            DNS changes can take up to 24 hours to propagate. You can proceed to verification once your records are in place.
          </p>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className="btn" onClick={() => setStep(3)}>Continue to Verification</button>
          </div>
        </div>
      )}

      {/* ─── Step 3: Verify Domain ─── */}
      {step === 3 && activeDomain && (
        <div>
          <div className="card">
            <h3 style={{ marginTop: 0, marginBottom: '0.5rem' }}>Verify Domain Ownership</h3>
            <p className="text-muted mb-1">
              Click the button below to check if your DNS TXT verification record for <strong>{activeDomain.name}</strong> has propagated.
            </p>

            {verifyHint && (
              <div style={{ background: 'var(--bg)', borderRadius: '6px', padding: '1rem', marginBottom: '1rem' }}>
                <p className="text-muted" style={{ fontSize: '0.85rem', marginBottom: '0.5rem' }}>Add this TXT record to your DNS:</p>
                <p className="mono"><strong>Name:</strong> {verifyHint.name}</p>
                <p className="mono" style={{ wordBreak: 'break-all' }}><strong>Value:</strong> {verifyHint.value}</p>
              </div>
            )}

            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button className="btn" onClick={handleVerify} disabled={verifying}>
                {verifying ? 'Checking...' : 'Verify Now'}
              </button>
              <button className="btn btn-sm" style={{ background: 'var(--bg-input)' }} onClick={() => setStep(2)}>
                Back to DNS Records
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Step 4: Create Mailbox ─── */}
      {step === 4 && activeDomain && (
        <div className="card">
          <h3 style={{ marginTop: 0, marginBottom: '0.5rem' }}>Create Your First Mailbox</h3>
          <p className="text-muted mb-1">
            Set up an email account on <strong>{activeDomain.name}</strong>. A welcome email with connection details will be delivered to the new mailbox.
          </p>
          <form onSubmit={handleCreateMailbox}>
            <div className="form-group">
              <label>Username</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input value={mbForm.local_part} onChange={e => setMbForm({ ...mbForm, local_part: e.target.value })}
                  placeholder="e.g. john.doe" required autoFocus style={{ flex: 1 }} />
                <span className="text-muted">@{activeDomain.name}</span>
              </div>
            </div>
            <div className="form-group">
              <label>Password</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input type={showPassword ? 'text' : 'password'} value={mbForm.password}
                  onChange={e => { setMbForm({ ...mbForm, password: e.target.value }); setPasswordError('') }}
                  placeholder="Min 12 characters, letters + numbers" required style={{ flex: 1 }} />
                <button type="button" className="btn btn-sm" onClick={() => setShowPassword(!showPassword)}
                  style={{ whiteSpace: 'nowrap' }}>{showPassword ? 'Hide' : 'Show'}</button>
                <button type="button" className="btn btn-sm" onClick={() => {
                  const pw = generatePassword(); setMbForm({ ...mbForm, password: pw }); setShowPassword(true); setPasswordError('')
                }} style={{ whiteSpace: 'nowrap' }}>Generate</button>
                {mbForm.password && <button type="button" className="btn btn-sm" onClick={() => copyToClipboard(mbForm.password, 'pw')}
                  style={{ whiteSpace: 'nowrap' }}>{copied === 'pw' ? 'Copied!' : 'Copy'}</button>}
              </div>
              {passwordError && <small style={{ color: 'var(--danger)', marginTop: '0.25rem', display: 'block' }}>{passwordError}</small>}
              {mbForm.password && !passwordError && (
                <small style={{ color: mbForm.password.length >= 12 && /[a-zA-Z]/.test(mbForm.password) && /[0-9]/.test(mbForm.password) ? 'var(--success)' : 'var(--warning)', marginTop: '0.25rem', display: 'block' }}>
                  {mbForm.password.length < 12 ? `${mbForm.password.length}/12 characters` : 'Password meets requirements'}
                </small>
              )}
            </div>
            <div className="form-group">
              <label>Display Name (optional)</label>
              <input value={mbForm.display_name} onChange={e => setMbForm({ ...mbForm, display_name: e.target.value })}
                placeholder="John Doe" />
            </div>
            <div className="form-group">
              <label>Quota (MB)</label>
              <input type="number" value={mbForm.quota_mb} onChange={e => setMbForm({ ...mbForm, quota_mb: e.target.value })} />
            </div>
            <button className="btn" type="submit">Create Mailbox</button>
          </form>
        </div>
      )}

      {/* ─── Step 5: Deliverability Review ─── */}
      {step === 5 && activeDomain && (
        <div>
          <div className="card">
            <h3 style={{ marginTop: 0, marginBottom: '0.5rem' }}>Deliverability Review</h3>
            <p className="text-muted mb-1">
              Checking email configuration for <strong>{activeDomain.name}</strong>. All checks should pass for reliable email delivery.
            </p>
            {checks.length > 0 && (
              <div style={{ marginBottom: '0.5rem' }}>
                <span className={`badge ${allPassed ? 'badge-success' : 'badge-warning'}`}>
                  {passCount}/{checks.length} checks passed
                </span>
              </div>
            )}
            <button className="btn btn-sm" onClick={runDeliverability} disabled={checkLoading}>
              {checkLoading ? 'Checking...' : 'Refresh'}
            </button>
          </div>

          {checkLoading && checks.length === 0 && (
            <div className="card"><p className="text-muted">Running deliverability checks...</p></div>
          )}

          {checks.map(check => (
            <div className="card" key={check.name}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: check.value || (check.status !== 'pass' && check.hint) ? '0.75rem' : 0 }}>
                <strong>{checkLabel(check.name)}</strong>
                <span className={`badge ${statusBadge(check.status)}`}>{check.status}</span>
              </div>
              {check.value && (
                <p className="mono text-muted" style={{ wordBreak: 'break-all', marginBottom: check.status !== 'pass' && check.hint ? '0.5rem' : 0 }}>
                  {check.value}
                </p>
              )}
              {check.status !== 'pass' && check.hint && (
                <p style={{ color: check.status === 'fail' ? 'var(--danger)' : 'var(--warning)', fontSize: '0.85rem' }}>
                  {check.hint}
                </p>
              )}
            </div>
          ))}

          {mailboxes.length > 0 && serverHost && (
            <div className="card">
              <h3 style={{ marginTop: 0, marginBottom: '0.5rem' }}>Connect Your Mail App</h3>
              <p className="text-muted mb-1">
                Use these settings in Outlook, Apple Mail, Thunderbird, or any
                IMAP/SMTP client. SSL/TLS is recommended — the alternative
                (STARTTLS on 587/143) works but is less robust on flaky networks.
              </p>
              <div className="card" style={{ background: 'var(--bg-input)', marginBottom: '0.75rem' }}>
                <strong>Secure SSL/TLS Settings (Recommended)</strong>
                <table style={{ marginTop: '0.5rem', width: '100%' }}>
                  <tbody>
                    <tr>
                      <td className="text-muted" style={{ width: '180px', verticalAlign: 'top' }}>Username</td>
                      <td className="mono">{mailboxes[0].local_part}@{activeDomain.name}</td>
                    </tr>
                    <tr>
                      <td className="text-muted" style={{ verticalAlign: 'top' }}>Password</td>
                      <td>The mailbox password you set when creating it.</td>
                    </tr>
                    <tr>
                      <td className="text-muted" style={{ verticalAlign: 'top' }}>Incoming Server</td>
                      <td>
                        <div className="mono">{serverHost}</div>
                        <div className="mono text-muted" style={{ fontSize: '0.85rem' }}>IMAP Port: 993 &nbsp;&nbsp; POP3 Port: 995</div>
                      </td>
                    </tr>
                    <tr>
                      <td className="text-muted" style={{ verticalAlign: 'top' }}>Outgoing Server</td>
                      <td>
                        <div className="mono">{serverHost}</div>
                        <div className="mono text-muted" style={{ fontSize: '0.85rem' }}>SMTP Port: 465 (SSL) or 587 (STARTTLS)</div>
                      </td>
                    </tr>
                    <tr>
                      <td className="text-muted">Authentication</td>
                      <td>Required for IMAP, POP3, and SMTP.</td>
                    </tr>
                  </tbody>
                </table>
                <button className="btn btn-sm mt-1" onClick={() => copyToClipboard(
                  `Username: ${mailboxes[0].local_part}@${activeDomain.name}\nIncoming (IMAP/SSL): ${serverHost}:993\nIncoming (POP3/SSL): ${serverHost}:995\nOutgoing (SMTP/SSL): ${serverHost}:465\nOutgoing (SMTP/STARTTLS): ${serverHost}:587`,
                  'connect'
                )}>
                  {copied === 'connect' ? 'Copied!' : 'Copy All Settings'}
                </button>
              </div>
              <p className="text-muted" style={{ fontSize: '0.85rem' }}>
                <strong>IMAP vs POP3:</strong> IMAP keeps mail in sync across devices (read on phone, marked read on laptop too).
                POP3 downloads mail to one device only — older clients sometimes default to it. <strong>Use IMAP unless you have a specific reason not to.</strong>
              </p>
            </div>
          )}

          {allPassed && (
            <div className="card" style={{ borderColor: 'var(--success)' }}>
              <h3 style={{ marginTop: 0, color: 'var(--success)' }}>Setup Complete!</h3>
              <p className="text-muted">
                Your mail server is fully configured and ready to send and receive email.
                You can manage domains, mailboxes, and aliases from the admin panel.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
