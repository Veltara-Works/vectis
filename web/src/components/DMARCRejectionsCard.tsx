import { useState, useEffect } from 'react'
import { api, type DMARCRejections } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'

interface Props {
  domainID: string
  // Fills the DMARC exception form; omitted when exceptions aren't available (no Pro).
  onUse?: (fromDomain: string, network: string) => void
}

// R_SPF_FAIL → "fail"; *_NA (no SPF record / no DKIM signature) → "none".
const symbolLabel = (s: string) => {
  const v = (s || 'none').replace(/^R_(SPF|DKIM)_/, '').toLowerCase()
  return v === 'na' ? 'none' : v
}

// Mail to this domain that DMARC enforcement rejected (#265). The only other
// trace of these is an SMTP log line, so a legitimate sender with broken DNS
// would otherwise go unnoticed.
export default function DMARCRejectionsCard({ domainID, onUse }: Props) {
  const [days, setDays] = useState(7)
  const [data, setData] = useState<DMARCRejections | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let live = true
    setError('')
    api.dmarcRejections(domainID, days)
      .then(d => { if (live) setData(d) })
      .catch((e: unknown) => { if (live) { setData(null); setError(extractError(e, 'Failed to load DMARC rejections')) } })
    return () => { live = false }
  }, [domainID, days])

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem' }}>
        <h3 style={{ margin: 0 }}>Rejected by DMARC</h3>
        <select aria-label="Period" value={days} onChange={e => setDays(Number(e.target.value))}>
          <option value={1}>Last 24 hours</option>
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
        </select>
      </div>
      <p className="text-muted" style={{ fontSize: '0.9rem' }}>
        Mail to this domain that failed DMARC for a sender publishing <span className="mono">p=reject</span>, and
        was refused. Most of it is forgery and should stay refused. A sender you recognise here has broken
        SPF/DKIM: ask them to fix it{onUse ? ', or add a DMARC exception for the network they send from' : ''}.
        {!onUse && ' DMARC exceptions are part of Vectis Mail Pro.'}
      </p>

      {error && <div className="alert alert-error">{error}</div>}

      {data && (
        <table>
          <thead>
            <tr><th>Sender</th><th>Rejected</th><th>Last</th><th>Sent from</th><th>SPF / DKIM</th></tr>
          </thead>
          <tbody>
            {data.senders.map(s => (
              <tr key={s.from_domain}>
                <td>
                  <span className="mono"><strong>{s.from_domain}</strong></span>
                  {s.example_from && s.example_from !== s.from_domain && (
                    <div className="text-muted mono" style={{ fontSize: '0.85rem' }}>{s.example_from}</div>
                  )}
                </td>
                <td>{s.count}</td>
                <td className="text-muted">{new Date(s.last_seen).toLocaleString()}</td>
                <td>
                  {s.sources.map(src => (
                    <div key={src.ip} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span className="mono">{src.ip}</span>
                      {src.hostname && <span className="text-muted mono" style={{ fontSize: '0.85rem' }}>{src.hostname}</span>}
                      <span className="text-muted">×{src.count}</span>
                      {onUse && src.ip && (
                        <button
                          className="btn btn-sm btn-secondary"
                          aria-label={`Use ${src.ip} for ${s.from_domain}`}
                          onClick={() => onUse(s.from_domain, src.ip)}
                        >
                          Use
                        </button>
                      )}
                    </div>
                  ))}
                </td>
                <td className="mono">{symbolLabel(s.spf)} / {symbolLabel(s.dkim)}</td>
              </tr>
            ))}
            {data.senders.length === 0 && (
              <tr><td colSpan={5} className="text-muted">
                No mail to this domain was rejected by DMARC in the last {data.days === 1 ? '24 hours' : `${data.days} days`}.
              </td></tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  )
}
