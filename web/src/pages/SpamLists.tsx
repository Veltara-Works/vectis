import { useState, useEffect, FormEvent } from 'react'
import { useParams, Link } from 'react-router'
import { api, type SpamListEntry, type SpamListKind } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'

type Entry = SpamListEntry

const tabLabel: Record<SpamListKind, string> = {
  block: 'Block list',
  allow: 'Allow list',
  dmarc_exception: 'DMARC exceptions',
}

interface DomainLite {
  id: string
  name: string
}

interface SpamListsPageProps {
  features?: string[]
}

export default function SpamListsPage({ features = [] }: SpamListsPageProps) {
  const { domainID } = useParams<{ domainID: string }>()
  const hasAdvancedSpam = features.includes('advanced_spam')

  const [domain, setDomain] = useState<DomainLite | null>(null)
  const [entries, setEntries] = useState<Entry[]>([])
  const [activeTab, setActiveTab] = useState<SpamListKind>('block')
  const [scope, setScope] = useState<'email' | 'domain'>('domain')
  const [pattern, setPattern] = useState('')
  const [network, setNetwork] = useState('')
  const isException = activeTab === 'dmarc_exception'
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const load = async () => {
    if (!domainID) return
    try {
      const list = await api.listDomains()
      const d = (list || []).find(x => x.id === domainID)
      if (d) setDomain({ id: d.id, name: d.name })
      const items = await api.listSpamListEntries(domainID)
      setEntries(items || [])
    } catch (e: unknown) {
      setError(extractError(e, 'Failed to load spam list entries'))
    }
  }

  useEffect(() => { load() }, [domainID])

  if (!hasAdvancedSpam) {
    return (
      <div>
        <h2 className="page-title">Spam Lists</h2>
        <div className="card">
          <p>
            Per-domain allow/block lists are part of <strong>Advanced Spam Filtering</strong>,
            included with the Vectis Mail Pro plan.
          </p>
          <p className="text-muted">
            Activate a Pro license on the{' '}
            <Link to="/admin/license">License page</Link> to enable this feature.
          </p>
        </div>
      </div>
    )
  }

  const handleAdd = async (e: FormEvent) => {
    e.preventDefault()
    if (!domainID) return
    setSubmitting(true)
    setError(''); setSuccess('')
    try {
      if (isException) {
        await api.createSpamListEntry(domainID, activeTab, 'domain', pattern.trim(), network.trim())
        setSuccess(`Added DMARC exception: ${pattern.trim()} from ${network.trim()}`)
      } else {
        await api.createSpamListEntry(domainID, activeTab, scope, pattern.trim())
        setSuccess(`Added ${activeTab} entry: ${pattern.trim()}`)
      }
      setPattern('')
      setNetwork('')
      await load()
    } catch (e: unknown) {
      setError(extractError(e, 'Failed to add entry'))
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (id: string, p: string) => {
    if (!domainID) return
    if (!confirm(`Remove ${p}?`)) return
    setError(''); setSuccess('')
    try {
      await api.deleteSpamListEntry(domainID, id)
      setSuccess(`Removed ${p}`)
      await load()
    } catch (e: unknown) {
      setError(extractError(e, 'Failed to delete entry'))
    }
  }

  const filtered = entries.filter(e => e.kind === activeTab)
  const placeholder = isException ? 'registrar.example' : scope === 'email' ? 'sender@example.com' : 'spam-domain.com'

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 className="page-title" style={{ margin: 0 }}>
          Spam Lists{domain ? <> — <span className="mono">{domain.name}</span></> : null}
        </h2>
        <Link className="btn" to="/admin/domains">← Domains</Link>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <div className="card">
        <p className="text-muted">
          Entries take effect within seconds of being saved. Allow-listed senders bypass spam scoring;
          block-listed senders are rejected before delivery. Patterns are case-insensitive.
        </p>
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
          {(['block', 'allow', 'dmarc_exception'] as SpamListKind[]).map(k => (
            <button
              key={k}
              className={`btn ${activeTab === k ? '' : 'btn-secondary'}`}
              onClick={() => setActiveTab(k)}
            >
              {tabLabel[k]}
            </button>
          ))}
        </div>

        {isException && (
          <p className="text-muted" style={{ fontSize: '0.9rem' }}>
            DMARC enforcement rejects mail that fails DMARC for a domain publishing <span className="mono">p=reject</span>.
            Some legitimate senders publish that policy but send from a server their own SPF doesn't list, so all their
            mail is rejected. An exception lets that sender's domain through DMARC for this domain, but only from the
            network you name: an IP, a range (at most /24, or /48 for IPv6), or a hostname (start with a dot for a
            suffix, e.g. <span className="mono">.mail.example.net</span>). Use the narrowest network that covers them.
            If they send from a shared platform, others on that platform could also send as their domain from it.
            Spam scoring and antivirus still apply. The best fix is still for the sender to correct their SPF/DKIM.
          </p>
        )}

        <form onSubmit={handleAdd}>
          {!isException && (
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '0.75rem' }}>
            <label>
              <input
                type="radio"
                checked={scope === 'domain'}
                onChange={() => setScope('domain')}
              />{' '}Domain
            </label>
            <label>
              <input
                type="radio"
                checked={scope === 'email'}
                onChange={() => setScope('email')}
              />{' '}Email address
            </label>
          </div>
          )}
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <input
              aria-label={isException ? 'Sender domain (header From)' : 'Pattern'}
              value={pattern}
              onChange={e => setPattern(e.target.value)}
              placeholder={placeholder}
              required
              style={{ flexGrow: 1 }}
            />
            {isException && (
              <input
                aria-label="Sends from (IP, range or hostname)"
                className="mono"
                value={network}
                onChange={e => setNetwork(e.target.value)}
                placeholder="27.111.95.31 or .mail.example.net"
                required
                style={{ flexGrow: 1 }}
              />
            )}
            <button className="btn" type="submit" disabled={submitting || !pattern.trim() || (isException && !network.trim())}>
              {submitting ? 'Adding...' : isException ? 'Add exception' : `Add ${activeTab}`}
            </button>
          </div>
        </form>
      </div>

      <div className="card">
        <table>
          <thead>
            {isException
              ? <tr><th>Sender domain</th><th>Sends from</th><th>Added</th><th></th></tr>
              : <tr><th>Pattern</th><th>Scope</th><th>Added</th><th></th></tr>}
          </thead>
          <tbody>
            {filtered.map(e => (
              <tr key={e.id}>
                <td className="mono"><strong>{e.pattern}</strong></td>
                <td className={isException ? 'mono' : undefined}>{isException ? e.network : e.scope}</td>
                <td className="text-muted">{new Date(e.created_at).toLocaleString()}</td>
                <td><button className="btn btn-sm btn-danger" onClick={() => handleDelete(e.id, e.network ? `${e.pattern} from ${e.network}` : e.pattern)}>Remove</button></td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={4} className="text-muted">No {isException ? 'DMARC exceptions' : `${activeTab} entries`}</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
