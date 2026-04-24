import { useState, useEffect } from 'react'
import { api } from '../api/client.ts'

interface OrchestratorStatus {
  state: string; current_operation?: string; last_operation?: string;
  // Set during the rc36+ orchestrator self-replace window (~30s between Apply
  // recording "completed" and the helper container firing). Presence signals
  // "don't worry, the orchestrator is about to restart on the new version".
  self_upgrade_until?: string;
}

interface HistoryEntry {
  id: string; action: string; status: string; plan_summary?: string;
  error?: string; started_at: string; completed_at?: string; admin_id?: string;
}

interface PlanChange {
  service: string;
  type: string; // "create" | "update" | "remove" | "config" | "migrate"
  old_image?: string;
  new_image?: string;
  detail?: string;
}

interface PlanResult {
  id: string;
  created_at: string;
  config_hash: string;
  baseline_versions?: Record<string, string>;
  changes: PlanChange[];
  migrations_up: number;
  release_tag?: string;
  warnings?: string[];
}

interface ApplyResult {
  message: string; steps?: Array<{ service: string; status: string }>;
}

export default function UpdatesPage() {
  const [status, setStatus] = useState<OrchestratorStatus | null>(null)
  const [history, setHistory] = useState<HistoryEntry[]>([])
  const [plan, setPlan] = useState<PlanResult | null>(null)
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [planning, setPlanning] = useState(false)
  const [applying, setApplying] = useState(false)
  const [rollingBack, setRollingBack] = useState(false)

  const loadStatus = () => api.orchestratorStatus().then(setStatus).catch(() => {})
  const loadHistory = () => api.orchestratorHistory().then(d => setHistory(d || [])).catch(() => {})

  useEffect(() => {
    loadStatus()
    loadHistory()
  }, [])

  // During the orchestrator self-replace window, poll status every 2s so the
  // countdown banner stays responsive and disappears promptly once the helper
  // has fired. Falls back to a single initial load when no window is active.
  const selfUpgradeUntilMs = status?.self_upgrade_until
    ? Date.parse(status.self_upgrade_until) : 0
  const selfUpgradeActive = selfUpgradeUntilMs > Date.now()
  useEffect(() => {
    if (!selfUpgradeActive) return
    const timer = setInterval(loadStatus, 2000)
    return () => clearInterval(timer)
  }, [selfUpgradeActive])

  const handlePlan = async () => {
    setPlanning(true)
    setError(''); setSuccess(''); setPlan(null); setApplyResult(null)
    try {
      const result = await api.orchestratorPlan()
      setPlan(result)
      setSuccess('Plan generated successfully')
      loadStatus()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to generate plan')
    } finally {
      setPlanning(false)
    }
  }

  const handleApply = async () => {
    if (!confirm('Apply the update plan? This will modify running services.')) return
    setApplying(true)
    setError(''); setSuccess(''); setApplyResult(null)
    try {
      const result = await api.orchestratorApply()
      setApplyResult(result)
      setSuccess(result.message || 'Update applied successfully')
      setPlan(null)
      loadStatus()
      loadHistory()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to apply update')
    } finally {
      setApplying(false)
    }
  }

  const handleRollback = async () => {
    if (!confirm('Rollback the last operation? This will revert services to their previous state.')) return
    setRollingBack(true)
    setError(''); setSuccess('')
    try {
      const result = await api.orchestratorRollback()
      setSuccess(result.message || 'Rollback completed successfully')
      loadStatus()
      loadHistory()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to rollback')
    } finally {
      setRollingBack(false)
    }
  }

  const stateColor = (state: string) => {
    switch (state) {
      case 'idle': return 'badge-success'
      case 'planning': case 'applying': return 'badge-warning'
      case 'error': return 'badge-danger'
      default: return ''
    }
  }

  const statusColor = (s: string) => {
    switch (s) {
      case 'completed': return 'badge-success'
      case 'failed': return 'badge-danger'
      case 'running': return 'badge-warning'
      default: return ''
    }
  }

  return (
    <div>
      <h2 className="page-title">Updates</h2>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}
      {selfUpgradeActive && (
        <SelfUpgradeBanner untilMs={selfUpgradeUntilMs} />
      )}

      <div className="card">
        <h3 className="mb-1">Orchestrator Status</h3>
        {status ? (
          <div>
            <p>
              State: <span className={`badge ${stateColor(status.state)}`}>{status.state}</span>
            </p>
            {status.current_operation && (
              <p className="text-muted">Current operation: {status.current_operation}</p>
            )}
          </div>
        ) : (
          <p className="text-muted">Unable to reach orchestrator</p>
        )}
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
          <button className="btn" onClick={handlePlan} disabled={planning || applying}>
            {planning ? 'Planning...' : 'Plan Update'}
          </button>
          <button className="btn" onClick={handleApply} disabled={applying || planning}>
            {applying ? 'Applying...' : 'Apply Update'}
          </button>
          <button className="btn btn-danger" onClick={handleRollback} disabled={rollingBack || applying}>
            {rollingBack ? 'Rolling back...' : 'Rollback'}
          </button>
        </div>
      </div>

      {plan && (
        <div className="card">
          <h3 className="mb-1">Update Plan</h3>
          {plan.release_tag && (
            <p className="text-muted" style={{ marginBottom: '0.75rem' }}>
              Release channel target: <strong className="mono">{plan.release_tag}</strong>
            </p>
          )}
          {plan.warnings && plan.warnings.length > 0 && (
            <div className="alert alert-warning" style={{ marginBottom: '0.75rem' }}>
              {plan.warnings.map((w, i) => (
                <div key={i}>⚠ {w}</div>
              ))}
            </div>
          )}
          {plan.changes && plan.changes.length > 0 ? (
            <table>
              <thead>
                <tr><th>Service</th><th>Action</th><th>Change</th></tr>
              </thead>
              <tbody>
                {plan.changes.map((c, i) => (
                  <tr key={i}>
                    <td><strong>{c.service}</strong></td>
                    <td><span className="badge">{c.type}</span></td>
                    <td className="text-muted mono" style={{ fontSize: '0.85rem' }}>
                      {c.old_image && c.new_image
                        ? `${c.old_image}  →  ${c.new_image}`
                        : c.new_image || c.detail || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : plan.migrations_up > 0 ? null : (
            <p className="text-muted">No changes needed — all services are up to date.</p>
          )}
          {plan.migrations_up > 0 && (
            <p className="text-muted" style={{ marginTop: '0.75rem' }}>
              Database migrations pending: <strong>{plan.migrations_up}</strong>
            </p>
          )}
        </div>
      )}

      {applyResult && applyResult.steps && applyResult.steps.length > 0 && (
        <div className="card">
          <h3 className="mb-1">Apply Progress</h3>
          <table>
            <thead>
              <tr><th>Service</th><th>Status</th></tr>
            </thead>
            <tbody>
              {applyResult.steps.map((s, i) => (
                <tr key={i}>
                  <td><strong>{s.service}</strong></td>
                  <td><span className={`badge ${statusColor(s.status)}`}>{s.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="card">
        <h3 className="mb-1">Operation History</h3>
        <table>
          <thead>
            <tr><th>Started</th><th>Action</th><th>Status</th><th>Summary</th><th>Completed</th></tr>
          </thead>
          <tbody>
            {history.map(h => (
              <tr key={h.id}>
                <td className="mono" style={{ whiteSpace: 'nowrap' }}>{new Date(h.started_at).toLocaleString()}</td>
                <td><span className="badge">{h.action}</span></td>
                <td><span className={`badge ${statusColor(h.status)}`}>{h.status}</span></td>
                <td className="text-muted">{h.plan_summary || h.error || '-'}</td>
                <td className="text-muted" style={{ whiteSpace: 'nowrap' }}>
                  {h.completed_at ? new Date(h.completed_at).toLocaleString() : '-'}
                </td>
              </tr>
            ))}
            {history.length === 0 && <tr><td colSpan={5} className="text-muted">No operations recorded</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// SelfUpgradeBanner renders a countdown banner while the orchestrator is in
// its self-replace window (rc36+). Without this, the ~30s gap between Apply
// recording "completed" and the helper container firing looks like a stalled
// upgrade because orchestrator's own image tag still reads as the old version.
// The banner auto-hides once the countdown passes (the status poll drops the
// field, the effect unmounts the banner).
function SelfUpgradeBanner({ untilMs }: { untilMs: number }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])
  const remaining = Math.max(0, Math.ceil((untilMs - now) / 1000))
  return (
    <div className="alert alert-warning" style={{ marginBottom: '0.75rem' }}>
      <strong>Orchestrator is finalising its self-upgrade.</strong>{' '}
      The orchestrator container will restart automatically in ~{remaining}s — no action needed.
      This page will refresh itself when the window closes.
    </div>
  )
}
