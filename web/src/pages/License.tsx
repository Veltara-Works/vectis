import { useState, useEffect } from 'react'
import { api } from '../api/client.ts'

// LicenseState mirrors the GET /api/v1/license response. The masked id is
// what we render — never the full subscription_id (that would leak per-
// customer credentials back through the UI).
interface LicenseState {
  configured: boolean
  from_db?: boolean
  tier: 'free' | 'pro' | 'enterprise'
  status?: string
  subscription_id_masked?: string
  tenant_id?: string
  server_id?: string
  base_url?: string
  last_check_at?: string
  expires_at?: string
  grace_remaining_days?: number
}

export default function LicensePage() {
  const [state, setState] = useState<LicenseState | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [showForm, setShowForm] = useState(false)

  // Form fields. license_key + service_key are the two values customers
  // paste from their ValidonX dashboard. tenant_id is recommended but
  // can be auto-resolved server-side from the API key. Subscription ID,
  // base URL, and server ID are optional. Subsequent edits only need the
  // fields they want to change — backend merges with current runtime config.
  const [form, setForm] = useState({
    license_key: '',
    service_key: '',
    tenant_id: '',
    subscription_id: '',
    base_url: '',
    server_id: '',
  })

  const load = async () => {
    setLoading(true)
    try {
      const s = await api.getLicense()
      setState(s)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load license state')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleActivate = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    setError('')
    setSuccess('')
    try {
      await api.setLicense(form)
      setSuccess('License activated. Pro features are now unlocked.')
      setShowForm(false)
      setForm({ license_key: '', service_key: '', tenant_id: '', subscription_id: '', base_url: '', server_id: '' })
      await load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to activate license')
    } finally {
      setSubmitting(false)
    }
  }

  const handleRevalidate = async () => {
    // Re-running setLicense with empty body merges nothing; backend re-checks
    // against the existing config. Useful if the subscription was just
    // re-activated on ValidonX side and the operator wants to refresh
    // cached entitlements without waiting.
    setSubmitting(true)
    setError('')
    setSuccess('')
    try {
      await api.setLicense({})
      setSuccess('License re-validated against ValidonX.')
      await load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Re-validation failed')
    } finally {
      setSubmitting(false)
    }
  }

  const handleRemove = async () => {
    if (!confirm('Remove this license? Pro/Enterprise features will be locked. Existing data is preserved.')) return
    setRemoving(true)
    setError('')
    setSuccess('')
    try {
      await api.removeLicense()
      setSuccess('License removed. Server is now in Free tier.')
      await load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to remove license')
    } finally {
      setRemoving(false)
    }
  }

  const tierBadgeClass = (tier?: string) => {
    if (tier === 'enterprise') return 'badge badge-success'
    if (tier === 'pro') return 'badge badge-success'
    return 'badge'
  }

  if (loading) return <div><h2 className="page-title">License</h2><p className="text-muted">Loading...</p></div>

  return (
    <div>
      <h2 className="page-title">License</h2>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <div className="card">
        <h3 className="mb-1">Current tier</h3>
        <p>
          <span className={tierBadgeClass(state?.tier)}>
            {state?.tier ? state.tier.toUpperCase() : 'FREE'}
          </span>
          {state?.status && (
            <>
              {' '}
              <span className="badge">{state.status}</span>
            </>
          )}
        </p>

        {state?.configured ? (
          <>
            <p className="text-muted">
              Subscription: <strong className="mono">{state.subscription_id_masked || '—'}</strong>
              {state.tenant_id && (<>{' · '}Tenant: <span className="mono">{state.tenant_id}</span></>)}
            </p>
            {state.expires_at && (
              <p className="text-muted">
                Cached entitlements expire: {new Date(state.expires_at).toLocaleString()}
                {state.grace_remaining_days !== undefined && state.grace_remaining_days > 0 && (
                  <> ({state.grace_remaining_days} day grace remaining if ValidonX is unreachable)</>
                )}
              </p>
            )}
            {state.last_check_at && (
              <p className="text-muted">
                Last verified with ValidonX: {new Date(state.last_check_at).toLocaleString()}
              </p>
            )}
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
              <button className="btn" onClick={handleRevalidate} disabled={submitting || removing}>
                {submitting ? 'Re-validating...' : 'Re-validate now'}
              </button>
              <button className="btn btn-danger" onClick={handleRemove} disabled={submitting || removing}>
                {removing ? 'Removing...' : 'Remove license'}
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="text-muted">
              This server is running in Free tier. Pro features (per-domain
              analytics, OIDC SSO, priority support) are not available.
            </p>
            <p className="text-muted">
              To activate Pro, sign into your{' '}
              <a href="https://validonx.com/" target="_blank" rel="noopener noreferrer">
                ValidonX dashboard
              </a>
              {' '}and paste your License Key and Service Key below. The
              server validates against ValidonX before activating, then
              features unlock immediately — no restart required.
            </p>
            {!showForm && (
              <button className="btn" onClick={() => setShowForm(true)}>
                Activate Pro / Enterprise
              </button>
            )}
          </>
        )}
      </div>

      {showForm && (
        <div className="card">
          <h3 className="mb-1">Activate license</h3>
          <p className="text-muted mb-1">
            Paste your License Key and Service Key from the ValidonX
            dashboard. Empty fields use values from{' '}
            <span className="mono">secrets.yaml</span> if present.
          </p>
          <form onSubmit={handleActivate} autoComplete="off">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <label>
                <div>License Key <span className="text-muted">(from ValidonX → Licenses tab; the "Subscription License" string)</span></div>
                <input
                  name="vectis_license_key"
                  value={form.license_key}
                  onChange={e => setForm({ ...form, license_key: e.target.value })}
                  placeholder="VLDX-..."
                  autoComplete="off"
                />
              </label>
              <label>
                <div>Service Key <span className="text-muted">(from ValidonX → API Keys tab)</span></div>
                <input
                  name="vectis_service_key"
                  value={form.service_key}
                  onChange={e => setForm({ ...form, service_key: e.target.value })}
                  placeholder="vx_..."
                  autoComplete="off"
                  type="password"
                />
              </label>
              <label>
                <div>Tenant ID <span className="text-muted">(from ValidonX → Overview tab; tenant code)</span></div>
                <input
                  name="vectis_tenant_id"
                  value={form.tenant_id}
                  onChange={e => setForm({ ...form, tenant_id: e.target.value })}
                  placeholder="your-tenant-code"
                  autoComplete="off"
                />
              </label>
              <label>
                <div>Subscription ID <span className="text-muted">(optional, audit/display only)</span></div>
                <input
                  name="vectis_subscription_id"
                  value={form.subscription_id}
                  onChange={e => setForm({ ...form, subscription_id: e.target.value })}
                  placeholder="sub_..."
                  autoComplete="off"
                />
              </label>
              <label>
                <div>Base URL <span className="text-muted">(optional, defaults to https://api.validonx.com)</span></div>
                <input
                  name="vectis_base_url"
                  value={form.base_url}
                  onChange={e => setForm({ ...form, base_url: e.target.value })}
                  placeholder="https://api.validonx.com"
                  autoComplete="off"
                />
              </label>
              <label>
                <div>Server ID <span className="text-muted">(optional)</span></div>
                <input
                  name="vectis_server_id"
                  value={form.server_id}
                  onChange={e => setForm({ ...form, server_id: e.target.value })}
                  placeholder="server-name"
                  autoComplete="off"
                />
              </label>
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="submit" className="btn" disabled={submitting}>
                  {submitting ? 'Validating with ValidonX...' : 'Activate'}
                </button>
                <button type="button" className="btn" onClick={() => setShowForm(false)} disabled={submitting}>
                  Cancel
                </button>
              </div>
            </div>
          </form>
        </div>
      )}
    </div>
  )
}
