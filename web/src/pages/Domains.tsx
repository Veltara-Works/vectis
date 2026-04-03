import { useState, useEffect, FormEvent } from 'react'
import { api } from '../api/client.ts'

interface Domain {
  id: string; name: string; active: boolean; dkim_enabled: boolean;
  dkim_selector: string; dkim_key_path?: string; spam_threshold: number;
  verification_status?: string; verification_token?: string; created_at: string;
}

export default function DomainsPage() {
  const [domains, setDomains] = useState<Domain[]>([])
  const [showAdd, setShowAdd] = useState(false)
  const [newName, setNewName] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [dkimInfo, setDkimInfo] = useState<{ dns_name: string; dns_value: string } | null>(null)
  const [verifyInfo, setVerifyInfo] = useState<{ domain: string; token: string; name: string } | null>(null)

  const load = () => api.listDomains().then(d => setDomains(d || [])).catch(() => setError('Failed to load domains'))
  useEffect(() => { load() }, [])

  const handleAdd = async (e: FormEvent) => {
    e.preventDefault()
    setError(''); setSuccess('')
    try {
      const result = await api.createDomain(newName)
      setNewName('')
      setShowAdd(false)
      setSuccess(`Domain ${result.domain.name} created`)
      if (result.dkim) setDkimInfo(result.dkim)
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create domain')
    }
  }

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete domain ${name}? All mailboxes and aliases must be removed first.`)) return
    try {
      await api.deleteDomain(id)
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete domain')
    }
  }

  const handleVerify = async (id: string) => {
    setError(''); setSuccess('')
    try {
      const result = await api.verifyDomain(id)
      if (result.found) {
        setSuccess(`Domain ${result.domain} verified successfully`)
        setVerifyInfo(null)
      } else {
        setVerifyInfo({ domain: result.domain, token: result.txt_record_value, name: result.txt_record_name })
        setError(`TXT record not found for ${result.domain}. Add the record below and try again.`)
      }
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Verification failed')
    }
  }

  const verificationBadge = (status?: string) => {
    switch (status) {
      case 'verified': return <span className="badge badge-success">verified</span>
      case 'pending': return <span className="badge badge-warning">pending</span>
      default: return <span className="badge badge-danger">unverified</span>
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 className="page-title" style={{ margin: 0 }}>Domains</h2>
        <button className="btn" onClick={() => setShowAdd(!showAdd)}>
          {showAdd ? 'Cancel' : 'Add Domain'}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      {dkimInfo && (
        <div className="card">
          <h3 className="mb-1">DKIM DNS Record</h3>
          <p className="text-muted mb-1">Add this TXT record to your DNS:</p>
          <p className="mono"><strong>Name:</strong> {dkimInfo.dns_name}</p>
          <p className="mono mt-1" style={{ wordBreak: 'break-all' }}><strong>Value:</strong> {dkimInfo.dns_value}</p>
          <button className="btn btn-sm mt-1" onClick={() => setDkimInfo(null)}>Dismiss</button>
        </div>
      )}

      {verifyInfo && (
        <div className="card">
          <h3 className="mb-1">Domain Verification Required</h3>
          <p className="text-muted mb-1">Add this TXT record to <strong>{verifyInfo.domain}</strong> DNS to verify ownership:</p>
          <p className="mono"><strong>Type:</strong> TXT</p>
          <p className="mono"><strong>Name:</strong> {verifyInfo.name}</p>
          <p className="mono mt-1" style={{ wordBreak: 'break-all' }}><strong>Value:</strong> {verifyInfo.token}</p>
          <p className="text-muted" style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>DNS changes can take up to 24 hours to propagate. Click "Verify" again once the record is in place.</p>
          <button className="btn btn-sm mt-1" onClick={() => setVerifyInfo(null)}>Dismiss</button>
        </div>
      )}

      {showAdd && (
        <div className="card">
          <form onSubmit={handleAdd}>
            <div className="form-group">
              <label>Domain Name</label>
              <input value={newName} onChange={e => setNewName(e.target.value)}
                placeholder="example.com" required autoFocus />
            </div>
            <button className="btn" type="submit">Create Domain</button>
          </form>
        </div>
      )}

      <div className="card">
        <table>
          <thead>
            <tr><th>Domain</th><th>Verified</th><th>Active</th><th>DKIM</th><th>Selector</th><th>Created</th><th></th></tr>
          </thead>
          <tbody>
            {domains.map(d => (
              <tr key={d.id}>
                <td><strong>{d.name}</strong></td>
                <td>
                  {verificationBadge(d.verification_status)}
                  {d.verification_status !== 'verified' && (
                    <button className="btn btn-sm" style={{ marginLeft: '0.5rem' }} onClick={() => handleVerify(d.id)}>Verify</button>
                  )}
                </td>
                <td><span className={`badge ${d.active ? 'badge-success' : 'badge-danger'}`}>{d.active ? 'yes' : 'no'}</span></td>
                <td><span className={`badge ${d.dkim_key_path ? 'badge-success' : 'badge-warning'}`}>{d.dkim_key_path ? 'configured' : 'none'}</span></td>
                <td className="mono">{d.dkim_selector}</td>
                <td className="text-muted">{new Date(d.created_at).toLocaleDateString()}</td>
                <td><button className="btn btn-sm btn-danger" onClick={() => handleDelete(d.id, d.name)}>Delete</button></td>
              </tr>
            ))}
            {domains.length === 0 && <tr><td colSpan={7} className="text-muted">No domains yet</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
