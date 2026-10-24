import { useEffect, useState } from 'react'
import { api, ApiError, type RBLCheck, type RBLStatusResponse } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'
import SpamhausNotice from './SpamhausNotice.tsx'

export const rblBadge = (status: RBLCheck['status']) => {
  switch (status) {
    case 'listed': return 'badge-danger'
    case 'clean': return 'badge-success'
    default: return 'badge-muted'
  }
}

// summarizeIP gives one line per IP. Unknown results are called out, never
// folded into "clean".
export function summarizeIP(listed: number, unknown: number, total: number): { badge: string; text: string } {
  if (total === 0) return { badge: 'badge-muted', text: 'not checked yet' }
  if (listed > 0) return { badge: 'badge-danger', text: `listed on ${listed} of ${total}` }
  if (unknown > 0) return { badge: 'badge-warning', text: `not listed on ${total - unknown}; ${unknown} could not be checked` }
  return { badge: 'badge-success', text: `not listed on any of ${total}` }
}

// BlocklistCard shows the server's sending IPs against the DNS blocklists the
// API checks every 6 hours. Hidden for admins without access (403).
export default function BlocklistCard() {
  const [data, setData] = useState<RBLStatusResponse | null>(null)
  const [hidden, setHidden] = useState(false)
  const [error, setError] = useState('')
  const [checking, setChecking] = useState(false)

  const load = () =>
    api.rblStatus().then(d => { setData(d); setError('') }).catch((err: unknown) => {
      if (err instanceof ApiError && err.status === 403) { setHidden(true); return }
      setError(extractError(err, 'Could not load blocklist status'))
    })

  useEffect(() => { load() }, [])

  const checkNow = () => {
    setChecking(true)
    api.rblCheckNow()
      .then(load)
      .catch((err: unknown) => setError(extractError(err, 'Blocklist check failed')))
      .finally(() => setChecking(false))
  }

  if (hidden) return null

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
        <h3 style={{ margin: 0 }}>Blocklist status</h3>
        <button className="btn btn-secondary" onClick={checkNow} disabled={checking}>
          {checking ? 'Checking...' : 'Check now'}
        </button>
      </div>
      {error && <div className="alert alert-error">{error}</div>}
      {data && data.spamhaus_dqs !== undefined && <SpamhausNotice configured={data.spamhaus_dqs} />}
      {data && data.ips.length === 0 && (
        <p className="text-muted" style={{ margin: 0 }}>
          No results yet. The server's IP comes from the mail hostname's DNS A record; the first check runs shortly after start-up.
        </p>
      )}
      {data?.ips.map(ip => {
        const checks = ip.checks ?? []
        const s = summarizeIP(ip.listed_count, ip.unknown_count, checks.length)
        return (
          <div key={ip.ip_address} style={{ marginBottom: '1rem' }}>
            <p style={{ marginBottom: '0.5rem' }}>
              <strong className="mono">{ip.ip_address}</strong>{' '}
              <span className={`badge ${s.badge}`}>{s.text}</span>
            </p>
            <table className="table">
              <thead>
                <tr><th>Blocklist</th><th>Status</th><th>Detail</th></tr>
              </thead>
              <tbody>
                {checks.map(c => (
                  <tr key={c.rbl_name}>
                    <td>{c.list_name}</td>
                    <td><span className={`badge ${rblBadge(c.status)}`}>{c.status === 'clean' ? 'not listed' : c.status}</span></td>
                    <td className="text-muted" style={{ fontSize: '0.85rem' }}>
                      {c.status === 'listed' && c.delist_url && (
                        <a href={c.delist_url} target="_blank" rel="noopener noreferrer">Request delisting</a>
                      )}
                      {c.status === 'unknown' && (c.response || 'could not be checked')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      })}
    </div>
  )
}
