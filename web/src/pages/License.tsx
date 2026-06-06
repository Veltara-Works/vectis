import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
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
  const [searchParams] = useSearchParams()
  // Set by /admin/license?checkout=success|cancel — Stripe Checkout redirects
  // here after the customer completes or abandons the in-product upgrade flow.
  // The banner naturally disappears once they paste their credentials and the
  // Free-tier branch unmounts.
  const checkoutStatus = searchParams.get('checkout')

  const [state, setState] = useState<LicenseState | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [upgrading, setUpgrading] = useState(false)

  // Form fields. license_key + service_key + tenant_id are the three
  // required values customers paste from their ValidonX dashboard.
  // tenant_id is required because ValidonX never returns it on the wire
  // (path-2 ADR-041 — tenant is bound to the API key on their side); the
  // server cannot derive it. Subscription ID, base URL, and server ID
  // are optional. Subsequent edits only need the fields they want to
  // change — backend merges with current runtime config.
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

  const handleStartCheckout = async () => {
    // Mint a Stripe Checkout session via the admin-side proxy, then redirect
    // the browser to Stripe-hosted checkout. The success/cancel return URLs are
    // server-set to vectismail.com/upgrade/{success,cancelled} (allowlisted by
    // Vx) — NOT back to this install — so after payment the buyer lands on the
    // marketing site, which guides them back here to paste the provisioning
    // credentials (license_key + service_key + tenant_id) that Vx emails them.
    setUpgrading(true)
    setError('')
    setSuccess('')
    try {
      const { url } = await api.createUpgradeCheckoutSession({})
      window.location.assign(url)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not start checkout')
      setUpgrading(false)
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
            {checkoutStatus === 'success' && (
              <div className="alert alert-success">
                Thanks for subscribing to Vectis Mail Pro! Check your email
                for your License Key, Service Key, and Tenant ID, then paste
                them below to activate Pro features on this install.
              </div>
            )}
            {checkoutStatus === 'cancel' && (
              <div className="alert">
                Checkout cancelled — no charge was made. Click "Subscribe to
                Vectis Mail Pro" below whenever you're ready.
              </div>
            )}

            <p className="text-muted">
              This server is running in Free tier. Pro features (per-domain
              analytics, advanced spam filtering — per-domain reject thresholds,
              greylisting, allow/block lists — OIDC SSO, custom branding,
              priority support) are not available.
            </p>
            <p className="text-muted">
              Subscribe to Vectis Mail Pro for $29 USD/month to unlock Pro
              features. Checkout runs securely on Stripe; after payment your
              activation credentials are emailed to you — paste them on this
              page and Pro features unlock immediately, no restart required.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem', flexWrap: 'wrap' }}>
              <button className="btn" onClick={handleStartCheckout} disabled={upgrading}>
                {upgrading ? 'Starting checkout...' : 'Subscribe to Vectis Mail Pro — $29 USD/mo'}
              </button>
              {!showForm && (
                <button className="btn btn-sm" onClick={() => setShowForm(true)} disabled={upgrading}>
                  Already purchased? Paste credentials
                </button>
              )}
            </div>
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
                <div>License Key <span className="text-muted">(required, from ValidonX → Licenses tab; the "Subscription License" string)</span></div>
                <input
                  name="vectis_license_key"
                  value={form.license_key}
                  onChange={e => setForm({ ...form, license_key: e.target.value })}
                  placeholder="VLDX-..."
                  autoComplete="off"
                  required
                />
              </label>
              <label>
                <div>Service Key <span className="text-muted">(required, from ValidonX → API Keys tab)</span></div>
                <input
                  name="vectis_service_key"
                  value={form.service_key}
                  onChange={e => setForm({ ...form, service_key: e.target.value })}
                  placeholder="vx_..."
                  autoComplete="off"
                  type="password"
                  required
                />
              </label>
              <label>
                <div>Tenant ID <span className="text-muted">(required, from ValidonX → Overview tab; tenant code)</span></div>
                <input
                  name="vectis_tenant_id"
                  value={form.tenant_id}
                  onChange={e => setForm({ ...form, tenant_id: e.target.value })}
                  placeholder="your-tenant-code"
                  autoComplete="off"
                  required
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
