import { useState, useEffect } from 'react'
import { api } from '../api/client.ts'

// Single Sign-On settings. Two concerns live here:
//
//   1. Your SSO identity (all roles) — whether the *current* admin's account is
//      linked to a federated identity (SAML or OIDC), with a Disconnect button.
//      Disconnect is refused server-side if no local password is set, so a
//      federated-only admin cannot lock themselves out.
//
//   2. Service Provider metadata (super_admin only) — the SP metadata XML an
//      operator hands to their IdP (Okta / Entra / ADFS) when wiring up SAML.
//      The providers list is empty unless the install is entitled to saml_sso
//      (Enterprise), so non-Enterprise installs see the upsell empty-state.
export default function SSOPage() {
  const [me, setMe] = useState<Awaited<ReturnType<typeof api.me>> | null>(null)
  const [samlProviders, setSamlProviders] = useState<string[]>([])
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const load = () => {
    api.me().then(setMe).catch(() => setError('Failed to load account'))
    // Empty unless the install is entitled to saml_sso. Failures are non-fatal:
    // the metadata section just renders its empty-state.
    api.samlProviders().then(setSamlProviders).catch(() => setSamlProviders([]))
  }
  useEffect(() => { load() }, [])

  const isSuperAdmin = me?.role === 'super_admin'
  // Entitlement, not provider count, decides the empty-state copy: an entitled
  // install with no providers yet needs "configure providers", whereas a
  // non-entitled install needs the upsell. samlProviders is [] in both cases.
  const samlEntitled = (me?.features ?? []).includes('saml_sso')

  const handleDisconnectSAML = async () => {
    if (!confirm('Disconnect SAML from your account? You will sign in with your password (and TOTP, if enabled) afterwards.')) return
    setError(''); setSuccess('')
    try {
      const r = await api.samlDisconnect()
      setSuccess(r.message || 'SAML disconnected')
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to disconnect SAML')
    }
  }

  const handleDisconnectOIDC = async () => {
    if (!confirm('Disconnect OIDC from your account? You will sign in with your password (and TOTP, if enabled) afterwards.')) return
    setError(''); setSuccess('')
    try {
      const r = await api.oidcDisconnect()
      setSuccess(r.message || 'OIDC disconnected')
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to disconnect OIDC')
    }
  }

  const hasSAML = !!me?.saml_provider
  const hasOIDC = !!me?.oidc_provider

  return (
    <div>
      <h2 className="page-title">Single Sign-On</h2>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ marginTop: 0 }}>Your SSO identity</h3>
        {!hasSAML && !hasOIDC && (
          <p className="text-muted">No single sign-on identity is linked to your account. You sign in with your email and password.</p>
        )}
        {hasSAML && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: hasOIDC ? '0.75rem' : 0 }}>
            <div>
              <strong>SAML</strong> — linked to <span className="mono">{me?.saml_provider}</span>
            </div>
            <button className="btn btn-sm btn-danger" onClick={handleDisconnectSAML}>Disconnect</button>
          </div>
        )}
        {hasOIDC && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <strong>OIDC</strong> — linked to <span className="mono">{me?.oidc_provider}</span>
            </div>
            <button className="btn btn-sm btn-danger" onClick={handleDisconnectOIDC}>Disconnect</button>
          </div>
        )}
        {(hasSAML || hasOIDC) && (
          <p className="text-muted" style={{ fontSize: '0.85rem', marginTop: '1rem', marginBottom: 0 }}>
            Set a password before disconnecting if you sign in only via SSO — otherwise the disconnect is refused to stop you locking yourself out.
          </p>
        )}
      </div>

      {isSuperAdmin && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Service Provider (SP) metadata</h3>
          <p className="text-muted" style={{ fontSize: '0.9rem' }}>
            Hand this metadata to your identity provider (Okta, Microsoft Entra ID, ADFS) when configuring SAML.
            It contains the SP entity ID, the Assertion Consumer Service URL, and the SP signing certificate — no secrets.
            {' '}See the{' '}
            <a href="https://vectismail.com/docs/" target="_blank" rel="noopener noreferrer">SAML setup guide</a>.
          </p>
          {samlProviders.length === 0 ? (
            samlEntitled ? (
              <p className="text-muted">
                No SAML providers are configured yet. Add providers under the install's SAML
                secrets (see the setup guide above) and run <span className="mono">vectis config apply</span> — they will appear here.
              </p>
            ) : (
              <p className="text-muted">
                SAML 2.0 SSO is an Enterprise feature. <a href="https://vectismail.com/pricing" target="_blank" rel="noopener noreferrer">View plans</a> to enable it, then configure your providers.
              </p>
            )
          ) : (
            <table>
              <thead>
                <tr><th>Provider</th><th></th></tr>
              </thead>
              <tbody>
                {samlProviders.map(p => (
                  <tr key={p}>
                    <td className="mono">{p}</td>
                    <td>
                      <a className="btn btn-sm" href={api.samlMetadataUrl(p)} target="_blank" rel="noopener noreferrer">
                        Download SP metadata
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}
