import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SSOPage from './SSO'

vi.mock('../api/client', () => ({
  api: {
    me: vi.fn(),
    samlProviders: vi.fn().mockResolvedValue([]),
    samlMetadataUrl: (p: string) => `/api/v1/auth/saml/metadata/${p}`,
    samlDisconnect: vi.fn(),
    oidcDisconnect: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

const profile = (over: Record<string, unknown> = {}) => ({
  id: '1', email: 'a@b.com', role: 'super_admin', totp_enabled: false,
  tier: 'enterprise' as const, features: ['saml_sso'], ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.me.mockResolvedValue(profile())
  mockApi.samlProviders.mockResolvedValue([])
  vi.spyOn(window, 'confirm').mockReturnValue(true)
})

describe('SSOPage', () => {
  it('shows the no-identity state when nothing is linked', async () => {
    render(<SSOPage />)
    await waitFor(() =>
      expect(screen.getByText(/No single sign-on identity is linked/i)).toBeInTheDocument()
    )
  })

  it('shows linked SAML identity and disconnects it', async () => {
    mockApi.me.mockResolvedValue(profile({ saml_provider: 'okta' }))
    mockApi.samlDisconnect.mockResolvedValue({ message: 'SAML provider disconnected' })

    render(<SSOPage />)
    const user = userEvent.setup()

    await waitFor(() => expect(screen.getByText('okta')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Disconnect' }))

    await waitFor(() => expect(mockApi.samlDisconnect).toHaveBeenCalled())
  })

  it('lists SAML providers with metadata download links for super_admin', async () => {
    mockApi.samlProviders.mockResolvedValue(['okta'])

    render(<SSOPage />)
    await waitFor(() => {
      const link = screen.getByRole('link', { name: 'Download SP metadata' })
      expect(link).toHaveAttribute('href', '/api/v1/auth/saml/metadata/okta')
    })
  })

  it('shows the configure-providers empty-state when entitled but none configured', async () => {
    // Default profile is Enterprise-entitled (features include saml_sso).
    mockApi.samlProviders.mockResolvedValue([])

    render(<SSOPage />)
    await waitFor(() =>
      expect(screen.getByText(/No SAML providers are configured yet/i)).toBeInTheDocument()
    )
    expect(screen.queryByText(/Enterprise feature/i)).not.toBeInTheDocument()
  })

  it('shows the Enterprise upsell empty-state when not entitled', async () => {
    mockApi.me.mockResolvedValue(profile({ tier: 'free', features: [] }))
    mockApi.samlProviders.mockResolvedValue([])

    render(<SSOPage />)
    await waitFor(() =>
      expect(screen.getByText(/SAML 2\.0 SSO is an Enterprise feature/i)).toBeInTheDocument()
    )
    expect(screen.getByRole('link', { name: 'View plans' })).toBeInTheDocument()
  })

  it('hides the SP metadata section from non-super_admins', async () => {
    mockApi.me.mockResolvedValue(profile({ role: 'admin' }))
    mockApi.samlProviders.mockResolvedValue(['okta'])

    render(<SSOPage />)
    await waitFor(() => expect(mockApi.me).toHaveBeenCalled())
    expect(screen.queryByText(/Service Provider \(SP\) metadata/i)).not.toBeInTheDocument()
  })
})
