import { useState, FormEvent } from 'react'
import { api } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'

const SERVICES = ['postfix', 'dovecot', 'rspamd', 'clamav', 'postgres', 'valkey', 'traefik']

export default function LogSearchPage() {
  const [service, setService] = useState('postfix')
  const [pattern, setPattern] = useState('')
  const [results, setResults] = useState<unknown>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // Audit export state
  const [exportFormat, setExportFormat] = useState('json')

  const handleSearch = async (e: FormEvent) => {
    e.preventDefault()
    setError(''); setResults(null); setLoading(true)
    try {
      const data = await api.searchLogs({ service, pattern, limit: 500 })
      setResults(data)
    } catch (err: unknown) {
      setError(extractError(err, 'Search failed'))
    } finally {
      setLoading(false)
    }
  }

  const handleExport = () => {
    const url = api.auditExportUrl(exportFormat)
    window.open(url, '_blank')
  }

  return (
    <div>
      <h2>Log Search</h2>
      <p className="muted">Search service logs via Loki or Docker. Export audit logs for compliance.</p>

      {error && <div className="alert alert-danger">{error}</div>}

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <h3>Service Logs</h3>
        <form onSubmit={handleSearch}>
          <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
            <div className="form-group" style={{ flex: 1 }}>
              <label>Service</label>
              <select value={service} onChange={e => setService(e.target.value)}>
                {SERVICES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div className="form-group" style={{ flex: 2 }}>
              <label>Search Pattern</label>
              <input value={pattern} onChange={e => setPattern(e.target.value)}
                placeholder="e.g. error, reject, timeout, user@domain.com" />
            </div>
          </div>
          <button type="submit" className="btn" disabled={loading}>
            {loading ? 'Searching...' : 'Search'}
          </button>
        </form>
      </div>

      {results !== null && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <h3>Results</h3>
          <pre style={{ maxHeight: '500px', overflow: 'auto', fontSize: '0.8rem', whiteSpace: 'pre-wrap', background: '#0d1117', padding: '1rem', borderRadius: '4px' }}>
            {typeof results === 'string' ? results : JSON.stringify(results, null, 2)}
          </pre>
        </div>
      )}

      <div className="card">
        <h3>Audit Log Export</h3>
        <p className="muted">Download the audit log for compliance archival (last 90 days by default).</p>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'end' }}>
          <div className="form-group">
            <label>Format</label>
            <select value={exportFormat} onChange={e => setExportFormat(e.target.value)}>
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
            </select>
          </div>
          <button className="btn" onClick={handleExport}>Download Export</button>
        </div>
      </div>
    </div>
  )
}
