import { useState, useEffect, FormEvent } from 'react'
import { useParams, Link } from 'react-router-dom'
import { api } from '../api/client.ts'

interface Entry {
  id: string
  domain_id: string
  kind: 'allow' | 'block'
  scope: 'email' | 'domain'
  pattern: string
  created_at: string
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
  const [activeTab, setActiveTab] = useState<'allow' | 'block'>('block')
  const [scope, setScope] = useState<'email' | 'domain'>('domain')
  const [pattern, setPattern] = useState('')
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
      setError(e instanceof Error ? e.message : 'Failed to load spam list entries')
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
      await api.createSpamListEntry(domainID, activeTab, scope, pattern.trim())
      setPattern('')
      setSuccess(`Added ${activeTab} entry: ${pattern.trim()}`)
      await load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to add entry')
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
      setError(e instanceof Error ? e.message : 'Failed to delete entry')
    }
  }

  const filtered = entries.filter(e => e.kind === activeTab)
  const placeholder = scope === 'email' ? 'sender@example.com' : 'spam-domain.com'

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
          <button
            className={`btn ${activeTab === 'block' ? '' : 'btn-secondary'}`}
            onClick={() => setActiveTab('block')}
          >
            Block list
          </button>
          <button
            className={`btn ${activeTab === 'allow' ? '' : 'btn-secondary'}`}
            onClick={() => setActiveTab('allow')}
          >
            Allow list
          </button>
        </div>

        <form onSubmit={handleAdd}>
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
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <input
              value={pattern}
              onChange={e => setPattern(e.target.value)}
              placeholder={placeholder}
              required
              style={{ flexGrow: 1 }}
            />
            <button className="btn" type="submit" disabled={submitting || !pattern.trim()}>
              {submitting ? 'Adding...' : `Add ${activeTab}`}
            </button>
          </div>
        </form>
      </div>

      <div className="card">
        <table>
          <thead>
            <tr><th>Pattern</th><th>Scope</th><th>Added</th><th></th></tr>
          </thead>
          <tbody>
            {filtered.map(e => (
              <tr key={e.id}>
                <td className="mono"><strong>{e.pattern}</strong></td>
                <td>{e.scope}</td>
                <td className="text-muted">{new Date(e.created_at).toLocaleString()}</td>
                <td><button className="btn btn-sm btn-danger" onClick={() => handleDelete(e.id, e.pattern)}>Remove</button></td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={4} className="text-muted">No {activeTab} entries</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
