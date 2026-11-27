import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import LoginPage from './Login'

vi.mock('../api/client', () => ({
  api: {
    login: vi.fn(),
    requestPasswordReset: vi.fn(),
    oidcProviders: vi.fn().mockResolvedValue([]),
    samlProviders: vi.fn().mockResolvedValue([]),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.oidcProviders.mockResolvedValue([])
  mockApi.samlProviders.mockResolvedValue([])
})

describe('LoginPage', () => {
  it('renders email and password fields', () => {
    render(<LoginPage onLogin={() => {}} />)
    expect(screen.getByPlaceholderText('admin@example.com')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Password')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument()
  })

  it('shows Vectis Mail Admin heading', () => {
    render(<LoginPage onLogin={() => {}} />)
    expect(screen.getByText('Vectis Mail Admin')).toBeInTheDocument()
  })

  it('calls onLogin after successful login', async () => {
    const onLogin = vi.fn()
    mockApi.login.mockResolvedValue({ admin: { id: '1', email: 'a@b.com', role: 'admin', totp_enabled: false } })

    render(<LoginPage onLogin={onLogin} />)
    const user = userEvent.setup()

    await user.type(screen.getByPlaceholderText('admin@example.com'), 'a@b.com')
    await user.type(screen.getByPlaceholderText('Password'), 'secret')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    await waitFor(() => expect(onLogin).toHaveBeenCalled())
  })

  it('shows error on failed login', async () => {
    mockApi.login.mockRejectedValue(new Error('Invalid credentials'))

    render(<LoginPage onLogin={() => {}} />)
    const user = userEvent.setup()

    await user.type(screen.getByPlaceholderText('admin@example.com'), 'a@b.com')
    await user.type(screen.getByPlaceholderText('Password'), 'wrong')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    await waitFor(() => expect(screen.getByText('Invalid credentials')).toBeInTheDocument())
  })

  it('shows TOTP field when MFA is required', async () => {
    mockApi.login.mockResolvedValue({ requires_totp: true, totp_session: 'sess-abc' })

    render(<LoginPage onLogin={() => {}} />)
    const user = userEvent.setup()

    await user.type(screen.getByPlaceholderText('admin@example.com'), 'a@b.com')
    await user.type(screen.getByPlaceholderText('Password'), 'pass')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    await waitFor(() => {
      expect(screen.getByPlaceholderText('6-digit code')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Verify' })).toBeInTheDocument()
    })
  })

  it('submits TOTP code and completes login', async () => {
    const onLogin = vi.fn()
    mockApi.login
      .mockResolvedValueOnce({ requires_totp: true, totp_session: 'sess-abc' })
      .mockResolvedValueOnce({ admin: { id: '1', email: 'a@b.com', role: 'admin', totp_enabled: true } })

    render(<LoginPage onLogin={onLogin} />)
    const user = userEvent.setup()

    await user.type(screen.getByPlaceholderText('admin@example.com'), 'a@b.com')
    await user.type(screen.getByPlaceholderText('Password'), 'pass')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    await waitFor(() => expect(screen.getByPlaceholderText('6-digit code')).toBeInTheDocument())

    await user.type(screen.getByPlaceholderText('6-digit code'), '123456')
    await user.click(screen.getByRole('button', { name: 'Verify' }))

    await waitFor(() => expect(onLogin).toHaveBeenCalled())
  })

  it('shows OIDC provider buttons when available', async () => {
    mockApi.oidcProviders.mockResolvedValue(['google', 'azure'])

    render(<LoginPage onLogin={() => {}} />)

    await waitFor(() => {
      expect(screen.getByText('Google')).toBeInTheDocument()
      expect(screen.getByText('Microsoft')).toBeInTheDocument()
    })
  })

  it('shows SAML provider buttons linking to the SP-initiated login', async () => {
    mockApi.samlProviders.mockResolvedValue(['okta'])

    render(<LoginPage onLogin={() => {}} />)

    await waitFor(() => {
      const link = screen.getByRole('link', { name: 'okta' })
      expect(link).toBeInTheDocument()
      expect(link).toHaveAttribute('href', '/api/v1/auth/saml/login/okta')
    })
  })

  it('has back to login button during TOTP step', async () => {
    mockApi.login.mockResolvedValue({ requires_totp: true, totp_session: 'sess-abc' })

    render(<LoginPage onLogin={() => {}} />)
    const user = userEvent.setup()

    await user.type(screen.getByPlaceholderText('admin@example.com'), 'a@b.com')
    await user.type(screen.getByPlaceholderText('Password'), 'pass')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    await waitFor(() => expect(screen.getByText('Back to login')).toBeInTheDocument())

    await user.click(screen.getByText('Back to login'))

    await waitFor(() => expect(screen.getByPlaceholderText('admin@example.com')).toBeInTheDocument())
  })
})

describe('LoginPage: forgot password', () => {
  it('sends a reset request and shows the same neutral answer', async () => {
    mockApi.requestPasswordReset.mockResolvedValue({ message: 'ok' })
    render(<LoginPage onLogin={() => {}} />)
    const user = userEvent.setup()

    await user.type(screen.getByPlaceholderText('admin@example.com'), 'a@b.com')
    await user.click(screen.getByRole('button', { name: 'Forgot password?' }))
    expect(screen.getByRole('heading', { name: 'Reset your password' })).toBeInTheDocument()
    // the address typed on the sign-in form carries over
    expect(screen.getByLabelText('Email')).toHaveValue('a@b.com')

    await user.click(screen.getByRole('button', { name: 'Send reset link' }))
    await waitFor(() => expect(mockApi.requestPasswordReset).toHaveBeenCalledWith('a@b.com'))
    expect(await screen.findByRole('status')).toHaveTextContent('If that address belongs to an admin account')
  })

  it('shows an error when the request fails, and goes back to sign in', async () => {
    mockApi.requestPasswordReset.mockRejectedValue(new Error('Too many requests'))
    render(<LoginPage onLogin={() => {}} />)
    const user = userEvent.setup()

    await user.click(screen.getByRole('button', { name: 'Forgot password?' }))
    await user.type(screen.getByLabelText('Email'), 'a@b.com')
    await user.click(screen.getByRole('button', { name: 'Send reset link' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Too many requests')

    await user.click(screen.getByRole('button', { name: 'Back to sign in' }))
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('hides the link during the authenticator-code step', async () => {
    mockApi.login.mockResolvedValue({ requires_totp: true, totp_session: 's1' })
    render(<LoginPage onLogin={() => {}} />)
    const user = userEvent.setup()

    await user.type(screen.getByPlaceholderText('admin@example.com'), 'a@b.com')
    await user.type(screen.getByPlaceholderText('Password'), 'secret')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))
    await screen.findByPlaceholderText('6-digit code')
    expect(screen.queryByRole('button', { name: 'Forgot password?' })).not.toBeInTheDocument()
  })
})
