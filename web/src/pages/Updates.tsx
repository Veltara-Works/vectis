import { useState, useEffect } from 'react'
import { api } from '../api/client.ts'

interface OrchestratorStatus {
  state: string; current_step?: string; last_operation?: string;
  // Set during the rc36+ orchestrator self-replace window (~30s between Apply
  // recording "completed" and the helper container firing). Presence signals
  // "don't worry, the orchestrator is about to restart on the new version".
  self_upgrade_until?: string;
}

// States during which the orchestrator is actively working. The UI polls
// while in any of these so the History row flips running→completed on its
// own, and so the in-progress banner surfaces `current_step` without waiting
// for the user to refresh. Without this, the ~60s Apply window before
// self_upgrade_until is written feels frozen (rc45 human-UI finding).
const NON_TERMINAL_STATES = new Set(['validating', 'planning', 'applying', 'rolling_back'])

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

  // Poll status + history every 2s whenever the orchestrator is actively
  // working OR we're inside the self-replace countdown window. Before rc46
  // this only polled during self_upgrade — which meant the poll never
  // started, because self_upgrade_until is only written ~60s into Apply
  // and nothing was re-fetching status to see it. The row stayed at
  // "running" indefinitely until the user hard-refreshed.
  const selfUpgradeUntilMs = status?.self_upgrade_until
    ? Date.parse(status.self_upgrade_until) : 0
  const selfUpgradeActive = selfUpgradeUntilMs > Date.now()
  const inFlight = status ? NON_TERMINAL_STATES.has(status.state) : false
  const shouldPoll = inFlight || selfUpgradeActive
  useEffect(() => {
    if (!shouldPoll) return
    const timer = setInterval(() => {
      loadStatus()
      loadHistory()
    }, 2000)
    return () => clearInterval(timer)
  }, [shouldPoll])

  const handlePlan = async () => {
    setPlanning(true)
    setError(''); setSuccess(''); setPlan(null); setApplyResult(null)
    try {
      const result = await api.orchestratorPlan()
      setPlan(result)
      const noChanges = !result.changes || result.changes.length === 0
      setSuccess(noChanges
        ? 'Plan generated — no changes needed, all services are up to date.'
        : 'Plan generated successfully. Review the changes below, then click Apply Update to proceed.')
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
      // The API responds 202 once the orchestrator has *accepted* the apply —
      // it hasn't finished yet. Say so honestly; the in-progress banner +
      // auto-refreshing History row are the ongoing feedback. Showing
      // "Update applied successfully" here (pre-rc46 behaviour) led users
      // to believe the update was done when it was still ~60s away.
      setSuccess('Update started — this page will refresh automatically as the orchestrator progresses.')
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
      {inFlight && !selfUpgradeActive && (
        <OperationInProgressBanner state={status?.state || ''} />
      )}
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
                <td className="text-muted" style={{ wordBreak: 'break-word', maxWidth: '32rem' }}>
                  <HistorySummary entry={h} />
                </td>
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

// OperationInProgressBanner fills the visual gap during the ~60s Apply window
// before self_upgrade_until is written. Without it the user sees a stable
// "running" row and nothing else — identical to a hang. rc45 human-UI
// finding: users will hit Rollback mid-Apply if they think it's stuck, so
// surfacing "we're still working" here is a safety feature, not just polish.
//
// rc48 reworded to state-aware prose. The earlier "Orchestrator is
// applying — step: apply" dumped the raw state + a redundant step field
// as tuples instead of English. The step field turned out to be the same
// value as state anyway (internal/orchestrator/client.go sets CurrentStep
// to lastOp.Type), so it added no signal — just awkward grammar.
function OperationInProgressBanner({ state }: { state: string }) {
  type Msg = { phrase: string; duration: string; safety: string }
  const messages: Record<string, Msg> = {
    validating: {
      phrase: 'validating the update plan',
      duration: 'a few seconds',
      safety: 'Please wait — do not click Rollback.',
    },
    applying: {
      phrase: 'applying the update',
      duration: 'around 60 seconds',
      safety: 'Please wait — the page will refresh itself; do not click Rollback.',
    },
    planning: {
      phrase: 'preparing the update plan',
      duration: 'a few seconds',
      safety: 'Please wait.',
    },
    rolling_back: {
      phrase: 'rolling back to the previous version',
      duration: 'around 60 seconds',
      safety: 'Please wait — do not click Apply Update.',
    },
  }
  const m = messages[state]
  if (!m) {
    return (
      <div className="alert alert-warning" style={{ marginBottom: '0.75rem' }}>
        The orchestrator is <strong>{state}</strong>. Please wait.
      </div>
    )
  }
  return (
    <div className="alert alert-warning" style={{ marginBottom: '0.75rem' }}>
      The orchestrator is <strong>{m.phrase}</strong>. This usually takes {m.duration}. {m.safety}
    </div>
  )
}

// HistorySummary renders the plan_summary JSON blob (or error text) for a row
// in the Operation History table. Before rc46 the raw JSON was dumped straight
// into the cell, which overflowed on desktop and was unreadable on mobile.
// Now: a human-readable one-liner with the raw JSON available behind a
// <details> toggle for anyone who actually wants it.
function HistorySummary({ entry }: { entry: HistoryEntry }) {
  if (entry.error) return <span>{entry.error}</span>
  if (!entry.plan_summary) return <span>-</span>

  try {
    const ps = JSON.parse(entry.plan_summary) as {
      changes?: Array<{ service: string; type: string; old_image?: string; new_image?: string }>
      migrations_up?: number
    }
    const changeCount = ps.changes?.length ?? 0
    const migrations = ps.migrations_up ?? 0
    // Best-effort target tag: grab the shared :tag suffix from the first change.
    let targetTag = ''
    const firstChange = ps.changes?.[0]
    if (firstChange?.new_image) {
      const m = firstChange.new_image.match(/:([^:/]+)$/)
      if (m) targetTag = m[1]
    }
    const parts: string[] = []
    parts.push(`${changeCount} service${changeCount === 1 ? '' : 's'}`)
    if (targetTag) parts.push(`→ ${targetTag}`)
    if (migrations > 0) parts.push(`${migrations} migration${migrations === 1 ? '' : 's'}`)
    const oneLiner = parts.join(', ')
    return (
      <details>
        <summary style={{ cursor: 'pointer' }}>{oneLiner}</summary>
        <pre style={{ marginTop: '0.5rem', fontSize: '0.75rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
          {JSON.stringify(ps, null, 2)}
        </pre>
      </details>
    )
  } catch {
    return <span style={{ wordBreak: 'break-all' }}>{entry.plan_summary}</span>
  }
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
      The orchestrator is <strong>finalising the update</strong>.
      The orchestrator container will restart automatically in ~{remaining}s.
      No action is needed. This page will refresh itself when update is completed. Please wait.
    </div>
  )
}
