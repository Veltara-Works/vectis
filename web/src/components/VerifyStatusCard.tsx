import type { VerifyStatus } from '../api/client.ts'

export interface VerifyDescription {
  badge: 'badge-success' | 'badge-danger' | 'badge-warning' | 'badge-muted'
  label: string
  detail: string
}

function ago(iso: string | undefined, now: number): string {
  if (!iso) return ''
  const mins = Math.max(0, Math.round((now - Date.parse(iso)) / 60000))
  if (mins < 60) return `${mins} min ago`
  const hours = Math.round(mins / 60)
  if (hours < 48) return `${hours} h ago`
  return `${Math.round(hours / 24)} days ago`
}

// describeVerify turns the last `vectis verify` record into one dashboard
// line. Pure, so the wording is unit-tested.
export function describeVerify(v: VerifyStatus, now: number = Date.now()): VerifyDescription {
  const when = ago(v.checked_at, now)
  switch (v.status) {
    case 'pass':
      return v.stale
        ? { badge: 'badge-warning', label: 'stale', detail: `Last verified ${v.version ?? ''} ${when}: the verify timer may have stopped.` }
        : { badge: 'badge-success', label: 'verified', detail: `This box runs exactly what was published for ${v.version ?? 'its version'} (checked ${when}).` }
    case 'fail': {
      const since = v.failing_since ? `, failing since ${ago(v.failing_since, now)}` : ''
      const what = v.failed_checks?.length ? ` Mismatched: ${v.failed_checks.join(', ')}.` : ''
      return { badge: 'badge-danger', label: 'FAILED', detail: `Does NOT match what was published for ${v.version ?? 'its version'}${since}.${what} Investigate now.` }
    }
    case 'unverifiable':
      return { badge: 'badge-muted', label: 'unverifiable', detail: `Could not establish what ${v.version ?? 'this version'} should run (checked ${when}); not a tamper signal.` }
    case 'never':
      return { badge: 'badge-muted', label: 'not yet', detail: 'No result recorded yet. Install the timer with: sudo vectis verify install-timer' }
    default:
      return { badge: 'badge-muted', label: 'unknown', detail: 'The last verify record could not be read.' }
  }
}

export default function VerifyStatusCard({ status, loadFailed }: { status?: VerifyStatus; loadFailed?: boolean }) {
  const d: VerifyDescription = loadFailed || !status
    ? { badge: 'badge-warning', label: 'unavailable', detail: 'Could not load the last verify result (network or server error). Check `vectis verify` on the host.' }
    : describeVerify(status)
  return (
    <div className="card">
      <h3 className="mb-1">Release integrity</h3>
      <p style={{ margin: 0 }}>
        <span className={`badge ${d.badge}`}>{d.label}</span>{' '}
        {d.detail}
      </p>
    </div>
  )
}
