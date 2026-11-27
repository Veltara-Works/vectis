import { useEffect, useState, FormEvent } from 'react'
import { api } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'
import { RESET_PATH, passwordProblem } from '../lib/passwordReset.ts'

// Reached from the link in a password-reset email: /admin/reset-password?token=…
// (emails sent before v0.1.68 link to /reset-password, which App also routes here).
export default function ResetPasswordPage() {
  // Read the token once, then take it out of the address bar and history, so
  // it isn't left in the browser history or passed on in a Referer header.
  const [token] = useState(() => new URLSearchParams(window.location.search).get('token') ?? '')
  useEffect(() => {
    if (window.location.search) window.history.replaceState(null, '', RESET_PATH)
  }, [])

  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    const problem = passwordProblem(password, confirm)
    if (problem) { setError(problem); return }
    setError('')
    setLoading(true)
    try {
      await api.resetPassword(token, password)
      setDone(true)
      setPassword('')
      setConfirm('')
    } catch (err: unknown) {
      setError(extractError(err, 'Could not reset the password'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-box">
        <div className="card">
          <h2 style={{ marginBottom: '1.5rem', textAlign: 'center' }}>Choose a new password</h2>
          {!token ? (
            <>
              <div className="alert alert-error">
                This reset link is incomplete. Open the link from the email again, or request a new one.
              </div>
              <a href="/admin" className="btn" style={{ width: '100%', display: 'block', textAlign: 'center', textDecoration: 'none' }}>
                Back to sign in
              </a>
            </>
          ) : done ? (
            <>
              <div className="alert alert-info" role="status">
                Your password has been changed, and you have been signed out everywhere. Sign in with your new password.
              </div>
              <a href="/admin" className="btn" style={{ width: '100%', display: 'block', textAlign: 'center', textDecoration: 'none' }}>
                Sign in
              </a>
            </>
          ) : (
            <form onSubmit={handleSubmit}>
              {error && <div className="alert alert-error" role="alert">{error}</div>}
              <div className="form-group">
                <label htmlFor="reset-new">New password</label>
                <input id="reset-new" type="password" value={password} onChange={e => setPassword(e.target.value)}
                  autoComplete="new-password" required autoFocus />
              </div>
              <div className="form-group">
                <label htmlFor="reset-confirm">Confirm new password</label>
                <input id="reset-confirm" type="password" value={confirm} onChange={e => setConfirm(e.target.value)}
                  autoComplete="new-password" required />
              </div>
              <button className="btn" style={{ width: '100%' }} disabled={loading}>
                {loading ? 'Saving...' : 'Set new password'}
              </button>
              <p style={{ textAlign: 'center', marginTop: '1rem' }}>
                <a href="/admin" className="link-btn">Back to sign in</a>
              </p>
            </form>
          )}
        </div>
      </div>
    </div>
  )
}
