import { useEffect, useState } from 'react'
import { api, ApiError } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'

// BillingPage is the customer-facing entrance to subscription management.
// It does NOT show subscription details itself — those live on the License
// page. Instead it mints a Stripe Customer Portal session via the Vectis
// /account/billing-portal-session endpoint (which proxies through ValidonX)
// and redirects the browser to the returned URL.
//
// Why a separate route instead of a button on /admin/license: the user
// requirement (project_billing_portal_proxy.md) is a clean URL bar —
// customers see "vectismail.com/account/billing" rather than any vendor
// brand. The page renders a brief stub while the redirect is in flight.
//
// Auto-redirect on mount keeps the UX one-click from the link target. A
// "Try again" button surfaces if the API call fails (license not yet
// configured, ValidonX unreachable, etc.).
export default function BillingPage() {
  const [error, setError] = useState('')
  const [unavailable, setUnavailable] = useState(false)
  const [redirecting, setRedirecting] = useState(true)

  const startSession = async () => {
    setError('')
    setUnavailable(false)
    setRedirecting(true)
    try {
      const { url } = await api.createBillingPortalSession(window.location.origin + '/admin/license')
      window.location.assign(url)
    } catch (e: unknown) {
      setRedirecting(false)
      // No Stripe customer behind this tenant (free tier or a manually-issued
      // Enterprise license): there is no self-serve billing portal. Show a
      // clean, non-retryable message rather than a "Try again" loop.
      if (e instanceof ApiError && e.code === 'BILLING_PORTAL_UNAVAILABLE') {
        setUnavailable(true)
        setError(e.message)
      } else {
        setError(extractError(e, 'Failed to start billing session'))
      }
    }
  }

  useEffect(() => { void startSession() }, [])

  return (
    <div style={{ maxWidth: '640px', margin: '0 auto', padding: '2rem 1rem', textAlign: 'center' }}>
      <h1>Billing</h1>
      {redirecting && !error && (
        <p style={{ color: '#94a3b8' }}>
          Opening your billing portal&hellip; If you aren&apos;t redirected automatically,
          {' '}<button onClick={startSession} style={{ padding: 0, background: 'none', border: 'none', color: 'var(--brand-primary, #3b82f6)', cursor: 'pointer', textDecoration: 'underline' }}>click here</button>.
        </p>
      )}
      {error && unavailable && (
        <div style={{ marginTop: '1rem' }}>
          <p style={{ color: '#94a3b8', marginBottom: '1rem' }}>{error}</p>
          <a href="/admin/license" className="btn">Back to License</a>
        </div>
      )}
      {error && !unavailable && (
        <div style={{ marginTop: '1rem' }}>
          <p style={{ color: '#ef4444', marginBottom: '1rem' }}>{error}</p>
          <button onClick={startSession} className="btn btn-primary" style={{ marginRight: '0.5rem' }}>Try again</button>
          <a href="/admin/license" className="btn">Back to License</a>
        </div>
      )}
    </div>
  )
}
