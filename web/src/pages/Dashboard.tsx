import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.ts'

interface SetupProgress {
  hasDomain: boolean
  domainVerified: boolean
  hasMailbox: boolean
  loading: boolean
}

export default function DashboardPage() {
  const [health, setHealth] = useState<{ status: string; services: Record<string, { status: string; response_ms: number }> } | null>(null)
  const [domains, setDomains] = useState<Array<{ id: string; name: string; active: boolean; verification_status?: string }>>([])
  const [error, setError] = useState('')
  const [configApplying, setConfigApplying] = useState(false)
  const [configMessage, setConfigMessage] = useState('')
  const [setup, setSetup] = useState<SetupProgress>({ hasDomain: false, domainVerified: false, hasMailbox: false, loading: true })

  useEffect(() => {
    api.health().then(setHealth).catch(() => setError('Failed to load health'))
    api.listDomains().then(async (d) => {
      const allDomains = d || []
      setDomains(allDomains)
      const hasDomain = allDomains.length > 0
      const domainVerified = allDomains.some((dom: { verification_status?: string }) => dom.verification_status === 'verified')
      let hasMailbox = false
      if (hasDomain) {
        try {
          const mbs = await api.listMailboxes(allDomains[0].id)
          hasMailbox = (mbs || []).length > 0
        } catch { /* */ }
      }
      setSetup({ hasDomain, domainVerified, hasMailbox, loading: false })
    }).catch(() => {})
  }, [])

  const handleConfigApply = async () => {
    setConfigApplying(true)
    setConfigMessage('')
    setError('')
    try {
      const result = await api.applyConfig()
      setConfigMessage(result.message || 'Configuration applied successfully')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to apply configuration')
    } finally {
      setConfigApplying(false)
    }
  }

  const totalMailboxes = domains.length // Simplified — real count would come from API

  return (
    <div>
      <h2 className="page-title">Dashboard</h2>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="stats">
        <div className="stat">
          <div className="stat-label">System Status</div>
          <div className="stat-value">
            {health ? (
              <span className={health.status === 'healthy' ? 'badge badge-success' : 'badge badge-danger'}>
                {health.status}
              </span>
            ) : '...'}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Domains</div>
          <div className="stat-value">{domains.length}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Active Domains</div>
          <div className="stat-value">{domains.filter(d => d.active).length}</div>
        </div>
      </div>

      {!setup.loading && !(setup.hasDomain && setup.domainVerified && setup.hasMailbox) && (
        <div className="card" style={{ borderColor: 'var(--primary)' }}>
          <h3 style={{ marginTop: 0, marginBottom: '0.75rem' }}>Getting Started</h3>
          <div className="setup-checklist">
            <div className={`setup-check ${setup.hasDomain ? 'setup-check-done' : ''}`}>
              <span className="setup-check-icon">{setup.hasDomain ? '\u2713' : '1'}</span>
              <span>Add your first domain</span>
            </div>
            <div className={`setup-check ${setup.hasDomain && setup.domainVerified ? 'setup-check-done' : ''}`}>
              <span className="setup-check-icon">{setup.domainVerified ? '\u2713' : '2'}</span>
              <span>Configure DNS and verify domain</span>
            </div>
            <div className={`setup-check ${setup.hasMailbox ? 'setup-check-done' : ''}`}>
              <span className="setup-check-icon">{setup.hasMailbox ? '\u2713' : '3'}</span>
              <span>Create your first mailbox</span>
            </div>
            <div className="setup-check">
              <span className="setup-check-icon">4</span>
              <span>Review deliverability</span>
            </div>
          </div>
          <Link to="/admin/setup" className="btn" style={{ display: 'inline-block', marginTop: '1rem', textDecoration: 'none' }}>
            {setup.hasDomain ? 'Resume Setup' : 'Start Setup'}
          </Link>
        </div>
      )}

      <div className="card">
        <h3 className="mb-1">Configuration</h3>
        <p className="text-muted mb-1">Apply pending configuration changes to Postfix, Dovecot, and Rspamd.</p>
        {configMessage && <div className="alert alert-success">{configMessage}</div>}
        <button className="btn" onClick={handleConfigApply} disabled={configApplying}>
          {configApplying ? 'Applying...' : 'Reload Config'}
        </button>
      </div>

      {health && (
        <div className="card">
          <h3 className="mb-1">Service Health</h3>
          <table>
            <thead>
              <tr><th>Service</th><th>Status</th></tr>
            </thead>
            <tbody>
              {Object.entries(health.services).map(([name, svc]) => (
                <tr key={name}>
                  <td>{name}</td>
                  <td>
                    <span className={`badge ${svc.status === 'healthy' ? 'badge-success' : 'badge-danger'}`}>
                      {svc.status}
                    </span>
                  </td>
                </tr>
              ))}
              {/*
                The api container has no Docker socket access (only the
                orchestrator does), so container-level health for
                postfix/dovecot/rspamd/traefik can't be queried here.
                Render them as "pending" — but only if the health API
                didn't already report on them, so we don't double-count
                when the orchestrator eventually takes over these checks.
                Docker's own restart policy + the api readiness probe
                still catch hard failures today.
              */}
              {['postfix', 'dovecot', 'rspamd', 'traefik']
                .filter((name) => !(name in health.services))
                .map((name) => (
                  <tr key={`pending-${name}`}>
                    <td>{name}</td>
                    <td>
                      <span className="badge badge-muted" title="Monitored by Docker restart policy. Full health checks moving to the orchestrator in a future release.">
                        pending
                      </span>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
