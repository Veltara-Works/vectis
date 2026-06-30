import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'

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
  const [selfUpgradeUntilMs, setSelfUpgradeUntilMs] = useState(0)
  const selfUpgradeActive = selfUpgradeUntilMs > Date.now()

  useEffect(() => {
    // Poll orchestrator status so the Dashboard shows the "finalising upgrade"
    // banner too — users may land here after clicking Apply on Updates, and
    // without this they'd see stale "healthy" rows with no hint that
    // orchestrator is mid-restart (rc36+).
    const loadOrchStatus = () => api.orchestratorStatus()
      .then(s => setSelfUpgradeUntilMs(s.self_upgrade_until ? Date.parse(s.self_upgrade_until) : 0))
      .catch(() => {})
    loadOrchStatus()
    const t = setInterval(loadOrchStatus, 5000)
    return () => clearInterval(t)
  }, [])

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
      setError(extractError(err, 'Failed to apply configuration'))
    } finally {
      setConfigApplying(false)
    }
  }

  const totalMailboxes = domains.length // Simplified — real count would come from API

  return (
    <div>
      <h2 className="page-title">Dashboard</h2>

      {error && <div className="alert alert-error">{error}</div>}
      {selfUpgradeActive && (
        <div className="alert alert-warning" style={{ marginBottom: '0.75rem' }}>
          The orchestrator is <strong>finalising the update</strong>.
          The orchestrator container will restart automatically in ~
          {Math.max(0, Math.ceil((selfUpgradeUntilMs - Date.now()) / 1000))}s.
          No action is needed. This page will refresh itself when update is completed. Please wait.
        </div>
      )}

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
                Render them as "unchecked" — but only if the health API
                didn't already report on them, so we don't double-count
                when the orchestrator eventually takes over these checks.

                Important: do NOT render anything that implies "this
                service is healthy" here — the api genuinely cannot tell.
                Earlier versions rendered "pending" with a reassuring
                tooltip, which looked affirmative even when the service
                was crashlooping. "unchecked" + the honest tooltip below
                is the rc29 correction.
              */}
              {['postfix', 'dovecot', 'rspamd', 'traefik']
                .filter((name) => !(name in health.services))
                .map((name) => (
                  <tr key={`unchecked-${name}`}>
                    <td>{name}</td>
                    <td>
                      <span className="badge badge-muted" title="This service's runtime health cannot be checked from the api container (no Docker socket access). Its status here reflects only whether the api knows about it — NOT whether it is actually running. Check 'docker ps' on the host, or wait for the orchestrator-driven health rollup in a future release.">
                        unchecked
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
