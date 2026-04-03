import { useState, FormEvent } from 'react'
import { api } from '../api/client.ts'

export default function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [totpSession, setTotpSession] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

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
        </div>
      </div>
    </div>
  )
}
