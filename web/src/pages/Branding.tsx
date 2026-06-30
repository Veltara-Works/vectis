import { useState, useEffect } from 'react'
import { api, type BrandingResponse } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'

interface Props {
  features: string[]
  onBrandingChanged?: (next: BrandingResponse) => void
}

const HEX_RE = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/

export default function BrandingPage({ features, onBrandingChanged }: Props) {
  const hasBranding = features.includes('custom_branding')

  const [state, setState] = useState<BrandingResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [removing, setRemoving] = useState(false)

  const [form, setForm] = useState({
    product_name: '',
    primary_color: '',
    logo_url: '',
  })

  const syncForm = (s: BrandingResponse) => {
    setForm({
      product_name: s.product_name,
      primary_color: s.primary_color,
      logo_url: s.logo_url,
    })
  }

  const load = async () => {
    setLoading(true)
    try {
      const s = await api.getBranding()
      setState(s)
      syncForm(s)
    } catch (e: unknown) {
      setError(extractError(e, 'Failed to load branding'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    if (form.primary_color !== '' && !HEX_RE.test(form.primary_color)) {
      setError('Primary color must be a hex string like #3b82f6')
      return
    }
    if (form.logo_url !== '' && !form.logo_url.startsWith('https://') && !form.logo_url.startsWith('/assets/')) {
      setError('Logo URL must be an https:// URL or /assets/ path')
      return
    }
    setSubmitting(true)
    try {
      const next = await api.setBranding(form)
      setState(next)
      syncForm(next)
      setSuccess('Branding updated.')
      onBrandingChanged?.(next)
    } catch (e: unknown) {
      setError(extractError(e, 'Failed to save branding'))
    } finally {
      setSubmitting(false)
    }
  }

  const handleClear = async () => {
    if (!confirm('Reset branding to Vectis defaults? Your saved values will be removed.')) return
    setError('')
    setSuccess('')
    setRemoving(true)
    try {
      const next = await api.removeBranding()
      setState(next)
      syncForm(next)
      setSuccess('Branding reset to Vectis defaults.')
      onBrandingChanged?.(next)
    } catch (e: unknown) {
      setError(extractError(e, 'Failed to reset branding'))
    } finally {
      setRemoving(false)
    }
  }

  if (loading) return <div><h2 className="page-title">Branding</h2><p className="text-muted">Loading...</p></div>

  const eff = state?.effective ?? { product_name: 'Vectis Mail', primary_color: '#3b82f6', logo_url: '' }
  const previewColor = HEX_RE.test(form.primary_color) ? form.primary_color : eff.primary_color
  const previewName = form.product_name || eff.product_name
  const previewLogo = form.logo_url || eff.logo_url

  return (
    <div>
      <h2 className="page-title">Branding</h2>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      {!hasBranding && (
        <div className="card">
          <h3 className="mb-1">Custom Branding is a Pro feature</h3>
          <p className="text-muted">
            Replace the "Vectis Mail" wordmark and accent colour with your own
            product name, brand colour, and logo across the admin UI. Activate
            a Pro license on the{' '}
            <a href="/admin/license">License page</a>{' '}
            to unlock.
          </p>
        </div>
      )}

      <div className="card">
        <h3 className="mb-1">Preview</h3>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          padding: '0.75rem 1rem',
          background: previewColor,
          color: '#fff',
          borderRadius: '6px',
        }}>
          {previewLogo
            ? <img src={previewLogo} alt="" style={{ height: '28px', width: 'auto' }} />
            : null}
          <strong>{previewName}</strong>
        </div>
        <p className="text-muted mt-1">
          This is how your sidebar header will render. Save to apply.
        </p>
      </div>

      <div className="card">
        <h3 className="mb-1">{hasBranding ? 'Edit branding' : 'Current branding'}</h3>
        <form onSubmit={handleSave} autoComplete="off">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <label>
              <div>Product name <span className="text-muted">(replaces "Vectis Mail" in sidebar; leave blank for default)</span></div>
              <input
                value={form.product_name}
                onChange={e => setForm({ ...form, product_name: e.target.value })}
                placeholder="Vectis Mail"
                maxLength={64}
                disabled={!hasBranding}
              />
            </label>
            <label>
              <div>Primary color <span className="text-muted">(hex like #3b82f6; leave blank for default)</span></div>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <input
                  type="text"
                  value={form.primary_color}
                  onChange={e => setForm({ ...form, primary_color: e.target.value })}
                  placeholder="#3b82f6"
                  maxLength={9}
                  disabled={!hasBranding}
                  style={{ flex: 1 }}
                />
                <input
                  type="color"
                  value={HEX_RE.test(form.primary_color) ? form.primary_color : (eff.primary_color || '#3b82f6')}
                  onChange={e => setForm({ ...form, primary_color: e.target.value })}
                  disabled={!hasBranding}
                  aria-label="Color picker"
                  style={{ width: '40px', height: '36px', padding: '2px' }}
                />
              </div>
            </label>
            <label>
              <div>Logo URL <span className="text-muted">(https:// URL or /assets/ path; leave blank for text wordmark)</span></div>
              <input
                type="url"
                value={form.logo_url}
                onChange={e => setForm({ ...form, logo_url: e.target.value })}
                placeholder="https://example.com/logo.svg"
                maxLength={2048}
                disabled={!hasBranding}
              />
            </label>
          </div>
          {hasBranding && (
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
              <button type="submit" className="btn btn-primary" disabled={submitting || removing}>
                {submitting ? 'Saving...' : 'Save branding'}
              </button>
              {state?.from_db && (
                <button type="button" className="btn btn-danger" onClick={handleClear} disabled={submitting || removing}>
                  {removing ? 'Resetting...' : 'Reset to Vectis defaults'}
                </button>
              )}
            </div>
          )}
        </form>
      </div>
    </div>
  )
}
