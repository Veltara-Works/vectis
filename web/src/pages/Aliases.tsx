import { useState, useEffect, FormEvent } from 'react'
import { api } from '../api/client.ts'

interface Domain { id: string; name: string }
interface Alias {
  id: string; domain_id: string; source_local_part: string;
  destination: string; active: boolean; created_at: string;
}

export default function AliasesPage() {
  const [domains, setDomains] = useState<Domain[]>([])
  const [selectedDomain, setSelectedDomain] = useState('')
  const [aliases, setAliases] = useState<Alias[]>([])
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ source_local_part: '', destination: '' })
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => { api.listDomains().then(setDomains) }, [])

  useEffect(() => {
    if (selectedDomain) {
      api.listAliases(selectedDomain).then(setAliases).catch(() => setAliases([]))
    }
  }, [selectedDomain])

  // Auto-select first domain
  useEffect(() => {
    if (domains.length > 0 && !selectedDomain) setSelectedDomain(domains[0].id)
  }, [domains])

  const domainName = domains.find(d => d.id === selectedDomain)?.name || ''

  const handleAdd = async (e: FormEvent) => {
    e.preventDefault()
    setError(''); setSuccess('')
    try {
      await api.createAlias(selectedDomain, form.source_local_part, form.destination)
      const source = form.source_local_part || '*'
      setForm({ source_local_part: '', destination: '' })
      setShowAdd(false)
      setSuccess(`Alias ${source}@${domainName} created`)
      api.listAliases(selectedDomain).then(setAliases)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create alias')
    }
  }

  const handleDelete = async (id: string, sourceLocalPart: string) => {
    const source = sourceLocalPart || '*'
    if (!confirm(`Delete alias ${source}@${domainName}? This cannot be undone.`)) return
    try {
      await api.deleteAlias(id)
      api.listAliases(selectedDomain).then(setAliases)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete alias')
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 className="page-title" style={{ margin: 0 }}>Aliases</h2>
        <button className="btn" onClick={() => setShowAdd(!showAdd)} disabled={!selectedDomain}>
          {showAdd ? 'Cancel' : 'Add Alias'}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <div className="card">
        <div className="form-group">
          <label>Select Domain</label>
          <select value={selectedDomain} onChange={e => setSelectedDomain(e.target.value)}>
            {domains.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </div>
      </div>

      {showAdd && (
        <div className="card">
          <form onSubmit={handleAdd}>
            <div className="form-group">
              <label>Source Local Part</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input value={form.source_local_part} onChange={e => setForm({ ...form, source_local_part: e.target.value })}
                  placeholder="user (leave empty for catch-all)" autoFocus style={{ flex: 1 }} />
                <span className="text-muted">@{domainName}</span>
              </div>
              <small className="text-muted">Leave empty to create a catch-all alias</small>
            </div>
            <div className="form-group">
              <label>Destination</label>
              <input value={form.destination} onChange={e => setForm({ ...form, destination: e.target.value })}
                placeholder="user@example.com" required />
            </div>
            <button className="btn" type="submit">Create Alias</button>
          </form>
        </div>
      )}

      <div className="card">
        <table>
          <thead>
            <tr><th>Source</th><th>Destination</th><th>Active</th><th>Created</th><th></th></tr>
          </thead>
          <tbody>
            {aliases.map(a => (
              <tr key={a.id}>
                <td><strong>{a.source_local_part ? `${a.source_local_part}@${domainName}` : `*@${domainName} (catch-all)`}</strong></td>
                <td className="mono">{a.destination}</td>
                <td><span className={`badge ${a.active ? 'badge-success' : 'badge-danger'}`}>{a.active ? 'yes' : 'no'}</span></td>
                <td className="text-muted">{new Date(a.created_at).toLocaleDateString()}</td>
                <td><button className="btn btn-sm btn-danger" onClick={() => handleDelete(a.id, a.source_local_part)}>Delete</button></td>
              </tr>
            ))}
            {aliases.length === 0 && <tr><td colSpan={5} className="text-muted">No aliases in this domain</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
