import { useState, useEffect, FormEvent } from 'react'
import { api } from '../api/client.ts'

const providerLabels: Record<string, string> = {
  google: 'Google',
  azure: 'Microsoft',
  keycloak: 'Keycloak',
}

export default function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [totpSession, setTotpSession] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [oidcProviders, setOidcProviders] = useState<string[]>([])
  const [samlProviders, setSamlProviders] = useState<string[]>([])

  useEffect(() => {
    api.oidcProviders().then(p => setOidcProviders(p)).catch(() => {})
    // SAML providers come back empty unless the install is entitled to
    // saml_sso (Enterprise), so non-Enterprise logins show no SAML buttons.
    api.samlProviders().then(p => setSamlProviders(p)).catch(() => {})
  }, [])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (totpSession) {
        // Step 2: submit TOTP code.
        const result = await api.login('', '', totpSession, totpCode)
        if (result.admin) onLogin()
      } else {
        // Step 1: submit email + password.
        const result = await api.login(email, password)
        if (result.requires_totp && result.totp_session) {
          setTotpSession(result.totp_session)
        } else if (result.admin) {
          onLogin()
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Login failed')
      if (totpSession) {
        // Clear TOTP session on failure so user can retry from scratch.
        setTotpSession('')
        setTotpCode('')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-box">
        <div className="card">
          <h2 style={{ marginBottom: '1.5rem', textAlign: 'center' }}>Vectis Mail Admin</h2>
          {error && <div className="alert alert-error">{error}</div>}
          <form onSubmit={handleSubmit}>
            {!totpSession ? (
              <>
                <div className="form-group">
                  <label>Email</label>
                  <input type="email" value={email} onChange={e => setEmail(e.target.value)}
                    placeholder="admin@example.com" required autoFocus />
                </div>
                <div className="form-group">
                  <label>Password</label>
                  <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                    placeholder="Password" required />
                </div>
              </>
            ) : (
              <div className="form-group">
                <label>Authenticator Code</label>
                <input type="text" value={totpCode} onChange={e => setTotpCode(e.target.value)}
                  placeholder="6-digit code" required autoFocus
                  maxLength={6} pattern="[0-9]{6}" inputMode="numeric" autoComplete="one-time-code" />
                <p className="text-muted" style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>
                  Enter the code from your authenticator app
                </p>
              </div>
            )}
            <button className="btn" style={{ width: '100%' }} disabled={loading}>
              {loading ? 'Signing in...' : totpSession ? 'Verify' : 'Sign In'}
            </button>
            {totpSession && (
              <button type="button" className="btn btn-sm" style={{ width: '100%', marginTop: '0.5rem' }}
                onClick={() => { setTotpSession(''); setTotpCode(''); setError('') }}>
                Back to login
              </button>
            )}
          </form>
          {(oidcProviders.length > 0 || samlProviders.length > 0) && !totpSession && (
            <>
              <div style={{ textAlign: 'center', margin: '1.25rem 0 1rem', color: '#64748b', fontSize: '0.85rem' }}>
                or sign in with
              </div>
              {oidcProviders.map(p => (
                <a key={`oidc-${p}`} href={`/api/v1/auth/oidc/login/${p}`}
                  className="btn" style={{ width: '100%', marginBottom: '0.5rem', textAlign: 'center', display: 'block', textDecoration: 'none' }}>
                  {providerLabels[p] || p}
                </a>
              ))}
              {/* SAML is SP-initiated: the GET /login/{provider} route builds a
                  signed AuthnRequest and redirects the browser to the IdP. */}
              {samlProviders.map(p => (
                <a key={`saml-${p}`} href={`/api/v1/auth/saml/login/${p}`}
                  className="btn" style={{ width: '100%', marginBottom: '0.5rem', textAlign: 'center', display: 'block', textDecoration: 'none' }}>
                  {providerLabels[p] || p}
                </a>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
