import { useState, useEffect } from 'react'
import { api } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'
import DomainSelect from '../components/DomainSelect.tsx'

interface Domain { id: string; name: string }
interface Check { name: string; status: string; value?: string; hint?: string }

const statusBadge = (status: string) => {
  switch (status) {
    case 'pass': return 'badge-success'
    case 'fail': return 'badge-danger'
    case 'warn': return 'badge-warning'
    default: return 'badge-warning'
  }
}

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

export default function DeliverabilityPage() {
  const [domains, setDomains] = useState<Domain[]>([])
  const [selectedDomain, setSelectedDomain] = useState('')
  const [checks, setChecks] = useState<Check[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => { api.listDomains().then(d => setDomains(d || [])).catch(() => setError('Failed to load domains')) }, [])

  // Auto-select first domain
  useEffect(() => {
    if (domains.length > 0 && !selectedDomain) setSelectedDomain(domains[0].id)
  }, [domains])

  const runChecks = () => {
    if (!selectedDomain) return
    setLoading(true)
    setError('')
    setChecks([])
    api.deliverability(selectedDomain)
      .then(result => setChecks(result?.checks || []))
      .catch(err => setError(extractError(err, 'Failed to run deliverability checks')))
      .finally(() => setLoading(false))
  }

  // Load checks when domain changes
  useEffect(() => {
    if (selectedDomain) runChecks()
  }, [selectedDomain])

  const domainName = domains.find(d => d.id === selectedDomain)?.name || ''
  const passCount = checks.filter(c => c.status === 'pass').length
  const totalCount = checks.length

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 className="page-title" style={{ margin: 0 }}>Deliverability</h2>
        <button className="btn" onClick={runChecks} disabled={!selectedDomain || loading}>
          {loading ? 'Checking...' : 'Refresh'}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="card">
        <div className="form-group">
          <label>Select Domain</label>
          <DomainSelect value={selectedDomain} onChange={setSelectedDomain} domains={domains} />
        </div>
      </div>

      {checks.length > 0 && (
        <>
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
              <strong style={{ fontSize: '1.1rem' }}>{domainName}</strong>
              <span className={`badge ${passCount === totalCount ? 'badge-success' : 'badge-warning'}`}>
                {passCount}/{totalCount} checks passed
              </span>
            </div>
          </div>

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
        </>
      )}

      {!loading && checks.length === 0 && selectedDomain && (
        <div className="card">
          <p className="text-muted">No check results yet. Click Refresh to run deliverability checks.</p>
        </div>
      )}
    </div>
  )
}
