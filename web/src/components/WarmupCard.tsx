import { useEffect, useState, type FormEvent } from 'react'
import { api, ApiError, type WarmupEntry } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'

// WARMUP_DAYS matches mail.WarmupDays in the API.
const WARMUP_DAYS = 30

// formatReset shows when today's count resets, in the viewer's local time.
export function formatReset(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  return d.toLocaleString(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' })
}

// usage describes today's count against the limit.
export function usage(e: Pick<WarmupEntry, 'daily_sent' | 'daily_limit'>): { badge: string; text: string } {
  const text = `${e.daily_sent.toLocaleString()} of ${e.daily_limit.toLocaleString()} external recipients today`
  if (e.daily_sent >= e.daily_limit) return { badge: 'badge-warning', text: `limit reached: ${text}` }
  return { badge: 'badge-success', text }
}

// WarmupCard shows the IP warmup: the active schedule's day and today's
// count, or a form to start one. While it runs, mail to recipients outside
// this server is limited per day (the send API answers 429 WARMUP_LIMIT,
// SMTP submission defers with 452). Hidden for admins without access (403).
export default function WarmupCard() {
  const [entries, setEntries] = useState<WarmupEntry[] | null>(null)
  const [hidden, setHidden] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [ip, setIP] = useState('')
  const [label, setLabel] = useState('')

  const load = () =>
    api.warmupList().then(d => { setEntries(d ?? []); setError('') }).catch((err: unknown) => {
      if (err instanceof ApiError && err.status === 403) { setHidden(true); return }
      setError(extractError(err, 'Could not load IP warmup'))
    })

  useEffect(() => { load() }, [])

  const start = (ev: FormEvent) => {
    ev.preventDefault()
    setBusy(true)
    api.warmupStart(ip.trim(), label.trim() || undefined)
      .then(() => { setIP(''); setLabel(''); return load() })
      .catch((err: unknown) => setError(extractError(err, 'Could not start the warmup')))
      .finally(() => setBusy(false))
  }

  const cancel = (e: WarmupEntry) => {
    if (!confirm(`Cancel the warmup for ${e.ip_address}? Sending will no longer be limited.`)) return
    setBusy(true)
    api.warmupCancel(e.id)
      .then(load)
      .catch((err: unknown) => setError(extractError(err, 'Could not cancel the warmup')))
      .finally(() => setBusy(false))
  }

  if (hidden) return null

  const active = entries?.find(e => e.active)
  const finished = entries?.filter(e => !e.active) ?? []

  return (
    <div className="card">
      <h3 style={{ marginTop: 0 }}>IP warmup</h3>
      {error && <div className="alert alert-error">{error}</div>}

      {active && (() => {
        const u = usage(active)
        return (
          <div>
            <p style={{ marginBottom: '0.5rem' }}>
              <strong className="mono">{active.ip_address}</strong>
              {active.label && <span className="text-muted"> ({active.label})</span>}{' '}
              <span className="badge badge-muted">day {active.warmup_day} of {active.days_total}</span>
            </p>
            <p style={{ marginBottom: '0.5rem' }}>
              <span className={`badge ${u.badge}`}>{u.text}</span>
            </p>
            <p className="text-muted" style={{ fontSize: '0.85rem' }}>
              The count resets and the limit rises at {formatReset(active.next_reset_at)}. Over the limit, the send API
              answers 429 and SMTP clients are asked to retry later; nothing bounces. Mail to domains on this server
              doesn't count.
            </p>
            <button className="btn btn-secondary" onClick={() => cancel(active)} disabled={busy}>Cancel warmup</button>
          </div>
        )
      })()}

      {entries && !active && (
        <form onSubmit={start}>
          <p className="text-muted" style={{ fontSize: '0.85rem' }}>
            A new sending IP has no reputation yet. A warmup limits mail to recipients outside this server to a daily
            amount that starts at 50 and rises over {WARMUP_DAYS} days, so mailbox providers learn to trust the IP gradually.
            Use the IP this server sends from (shown under Blocklist status).
          </p>
          <div className="form-group">
            <label htmlFor="warmup-ip">Sending IP</label>
            <input id="warmup-ip" className="mono" value={ip} onChange={e => setIP(e.target.value)} placeholder="203.0.113.7" required />
          </div>
          <div className="form-group">
            <label htmlFor="warmup-label">Label (optional)</label>
            <input id="warmup-label" value={label} onChange={e => setLabel(e.target.value)} />
          </div>
          <button className="btn" type="submit" disabled={busy || ip.trim() === ''}>
            {busy ? 'Starting...' : 'Start warmup'}
          </button>
        </form>
      )}

      {finished.map(e => (
        <p key={e.id} className="text-muted" style={{ fontSize: '0.85rem', marginBottom: 0 }}>
          <span className="mono">{e.ip_address}</span>: warmup complete.
        </p>
      ))}
    </div>
  )
}
