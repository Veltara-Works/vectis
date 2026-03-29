import { useState, useEffect } from 'react'
import { api } from '../api/client.ts'

export default function DashboardPage() {
  const [health, setHealth] = useState<{ status: string; services: Record<string, { status: string; response_ms: number }> } | null>(null)
  const [domains, setDomains] = useState<Array<{ id: string; name: string; active: boolean }>>([])
  const [error, setError] = useState('')
  const [configApplying, setConfigApplying] = useState(false)
  const [configMessage, setConfigMessage] = useState('')

  useEffect(() => {
    api.health().then(setHealth).catch(() => setError('Failed to load health'))
    api.listDomains().then(d => setDomains(d || [])).catch(() => {})
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
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
