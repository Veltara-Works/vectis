import { useState, useEffect, FormEvent } from 'react'
import { Link } from 'react-router'
import { api } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'

interface Domain {
  id: string; name: string; active: boolean; dkim_enabled: boolean;
  dkim_selector: string; dkim_key_path?: string;
  // Per-domain spam overrides (Pro). Absent/null = the system-wide config.yaml value.
  spam_threshold?: number | null; reject_threshold?: number | null; greylist_enabled?: boolean | null;
  verification_status?: string; verification_token?: string; created_at: string;
}

// Greylisting is three-way per domain: '' follows the system default, so
// saving the form never pins a domain to "off" by accident.
type Greylist = '' | 'on' | 'off'
const greylistOf = (v?: boolean | null): Greylist => (v === true ? 'on' : v === false ? 'off' : '')
const greylistValue = (g: Greylist): boolean | null => (g === 'on' ? true : g === 'off' ? false : null)
// An empty threshold input means "no override": sent as null, which clears it.
const thresholdValue = (v: string): number | null => (v === '' ? null : parseFloat(v))
const thresholdText = (v?: number | null): string => (v !== undefined && v !== null ? String(v) : '')

interface DomainsPageProps {
  features?: string[]
}

export default function DomainsPage({ features = [] }: DomainsPageProps) {
  const hasAdvancedSpam = features.includes('advanced_spam')

  const [domains, setDomains] = useState<Domain[]>([])
  const [showAdd, setShowAdd] = useState(false)
  const [newName, setNewName] = useState('')
  const [newSpamThreshold, setNewSpamThreshold] = useState('')
  const [newRejectThreshold, setNewRejectThreshold] = useState('')
  const [newGreylist, setNewGreylist] = useState<Greylist>('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [dkimInfo, setDkimInfo] = useState<{ dns_name: string; dns_value: string } | null>(null)
  const [verifyInfo, setVerifyInfo] = useState<{ domain: string; token: string; name: string } | null>(null)

  const [editingId, setEditingId] = useState<string | null>(null)
  const [editSpamThreshold, setEditSpamThreshold] = useState('')
  const [editRejectThreshold, setEditRejectThreshold] = useState('')
  const [editGreylist, setEditGreylist] = useState<Greylist>('')
  const [savingEdit, setSavingEdit] = useState(false)

  const load = () => api.listDomains().then(d => setDomains(d || [])).catch(() => setError('Failed to load domains'))
  useEffect(() => { load() }, [])

  const handleAdd = async (e: FormEvent) => {
    e.preventDefault()
    setError(''); setSuccess('')
    try {
      const advanced = hasAdvancedSpam
        ? {
            spam_threshold: thresholdValue(newSpamThreshold),
            reject_threshold: thresholdValue(newRejectThreshold),
            greylist_enabled: greylistValue(newGreylist),
          }
        : undefined
      const result = await api.createDomain(newName, advanced)
      setNewName('')
      setNewSpamThreshold('')
      setNewRejectThreshold('')
      setNewGreylist('')
      setShowAdd(false)
      setSuccess(`Domain ${result.domain.name} created`)
      if (result.dkim) setDkimInfo(result.dkim)
      load()
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to create domain'))
    }
  }

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete domain ${name}? All mailboxes and aliases must be removed first.`)) return
    try {
      await api.deleteDomain(id)
      load()
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to delete domain'))
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
      setError(extractError(err, 'Verification failed'))
    }
  }

  const startEditAdvanced = (d: Domain) => {
    setEditingId(d.id)
    setEditSpamThreshold(thresholdText(d.spam_threshold))
    setEditRejectThreshold(thresholdText(d.reject_threshold))
    setEditGreylist(greylistOf(d.greylist_enabled))
  }

  const cancelEditAdvanced = () => {
    setEditingId(null)
    setEditSpamThreshold('')
    setEditRejectThreshold('')
    setEditGreylist('')
  }

  const saveEditAdvanced = async (id: string) => {
    setSavingEdit(true)
    setError(''); setSuccess('')
    try {
      await api.updateDomain(id, {
        spam_threshold: thresholdValue(editSpamThreshold),
        reject_threshold: thresholdValue(editRejectThreshold),
        greylist_enabled: greylistValue(editGreylist),
      })
      setSuccess('Spam settings updated')
      cancelEditAdvanced()
      load()
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to update domain'))
    } finally {
      setSavingEdit(false)
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
            {hasAdvancedSpam && (
              <>
                <div className="form-group">
                  <label htmlFor="new-spam-threshold">Spam Threshold <span className="text-muted">(optional — Pro)</span></label>
                  <input
                    id="new-spam-threshold"
                    type="number"
                    step="0.1"
                    min="0.1"
                    max="999.9"
                    value={newSpamThreshold}
                    onChange={e => setNewSpamThreshold(e.target.value)}
                    placeholder="leave empty to use system default"
                  />
                  <p className="text-muted" style={{ fontSize: '0.85rem' }}>
                    Score at or above which inbound mail to this domain is marked as spam and filed to Junk. Leave empty to inherit the system-wide default.
                  </p>
                </div>
                <div className="form-group">
                  <label>Reject Threshold <span className="text-muted">(optional — Pro)</span></label>
                  <input
                    type="number"
                    step="0.1"
                    min="0.1"
                    max="50"
                    value={newRejectThreshold}
                    onChange={e => setNewRejectThreshold(e.target.value)}
                    placeholder="leave empty to use system default"
                  />
                  <p className="text-muted" style={{ fontSize: '0.85rem' }}>
                    Score above which inbound mail to this domain is rejected at SMTP. Leave empty to inherit the system-wide default.
                  </p>
                </div>
                <div className="form-group">
                  <label htmlFor="new-greylist">Greylisting <span className="text-muted">(Pro)</span></label>
                  <select id="new-greylist" value={newGreylist} onChange={e => setNewGreylist(e.target.value as Greylist)}>
                    <option value="">System default</option>
                    <option value="on">On</option>
                    <option value="off">Off</option>
                  </select>
                </div>
              </>
            )}
            <button className="btn" type="submit">Create Domain</button>
          </form>
        </div>
      )}

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Domain</th><th>Verified</th><th>Active</th><th>DKIM</th><th>Selector</th>
              {hasAdvancedSpam && <th>Spam</th>}
              {hasAdvancedSpam && <th>Reject</th>}
              {hasAdvancedSpam && <th>Greylist</th>}
              <th>Created</th><th></th>
            </tr>
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
                {hasAdvancedSpam && (
                  <td className="mono">
                    {editingId === d.id ? (
                      <input
                        aria-label={`Spam threshold for ${d.name}`}
                        type="number"
                        step="0.1"
                        min="0.1"
                        max="999.9"
                        value={editSpamThreshold}
                        onChange={e => setEditSpamThreshold(e.target.value)}
                        placeholder="default"
                        style={{ width: '5rem' }}
                      />
                    ) : (
                      d.spam_threshold !== undefined && d.spam_threshold !== null
                        ? d.spam_threshold.toFixed(1)
                        : <span className="text-muted">default</span>
                    )}
                  </td>
                )}
                {hasAdvancedSpam && (
                  <td className="mono">
                    {editingId === d.id ? (
                      <input
                        aria-label={`Reject threshold for ${d.name}`}
                        type="number"
                        step="0.1"
                        min="0.1"
                        max="50"
                        value={editRejectThreshold}
                        onChange={e => setEditRejectThreshold(e.target.value)}
                        placeholder="default"
                        style={{ width: '5rem' }}
                      />
                    ) : (
                      d.reject_threshold !== undefined && d.reject_threshold !== null
                        ? d.reject_threshold.toFixed(1)
                        : <span className="text-muted">default</span>
                    )}
                  </td>
                )}
                {hasAdvancedSpam && (
                  <td>
                    {editingId === d.id ? (
                      <select
                        aria-label={`Greylisting for ${d.name}`}
                        value={editGreylist}
                        onChange={e => setEditGreylist(e.target.value as Greylist)}
                      >
                        <option value="">default</option>
                        <option value="on">on</option>
                        <option value="off">off</option>
                      </select>
                    ) : greylistOf(d.greylist_enabled) === '' ? (
                      <span className="text-muted">default</span>
                    ) : (
                      <span className={`badge ${d.greylist_enabled ? 'badge-success' : ''}`}>
                        {d.greylist_enabled ? 'on' : 'off'}
                      </span>
                    )}
                  </td>
                )}
                <td className="text-muted">{new Date(d.created_at).toLocaleDateString()}</td>
                <td>
                  {hasAdvancedSpam && editingId === d.id ? (
                    <>
                      <button className="btn btn-sm" disabled={savingEdit} onClick={() => saveEditAdvanced(d.id)}>
                        {savingEdit ? 'Saving...' : 'Save'}
                      </button>
                      <button className="btn btn-sm" style={{ marginLeft: '0.25rem' }} disabled={savingEdit} onClick={cancelEditAdvanced}>
                        Cancel
                      </button>
                    </>
                  ) : (
                    <>
                      {hasAdvancedSpam && (
                        <>
                          <button className="btn btn-sm" onClick={() => startEditAdvanced(d)}>Edit spam</button>
                          <Link className="btn btn-sm" to={`/admin/domains/${d.id}/spam-lists`} style={{ marginLeft: '0.25rem' }}>
                            Spam lists
                          </Link>
                        </>
                      )}
                      <button className="btn btn-sm btn-danger" style={{ marginLeft: '0.25rem' }} onClick={() => handleDelete(d.id, d.name)}>Delete</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
            {domains.length === 0 && (
              <tr><td colSpan={hasAdvancedSpam ? 10 : 7} className="text-muted">No domains yet</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
