import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import AdminsPage from './Admins'

vi.mock('../api/client', () => ({
  api: {
    listAdmins: vi.fn(),
    createAdmin: vi.fn(),
    updateAdmin: vi.fn(),
    deleteAdmin: vi.fn(),
    me: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.me.mockResolvedValue({ id: 'self', email: 'me@test.com', role: 'super_admin', totp_enabled: false })
})

describe('AdminsPage', () => {
  it('renders page title', () => {
    mockApi.listAdmins.mockResolvedValue([])
    render(<AdminsPage />)
    expect(screen.getByText('Admins')).toBeInTheDocument()
  })

  it('lists administrators', async () => {
    mockApi.listAdmins.mockResolvedValue([
      { id: '1', email: 'admin@test.com', role: 'super_admin', totp_enabled: true, created_at: '2026-01-01', last_login_at: '2026-04-01' },
      { id: '2', email: 'user@test.com', role: 'domain_admin', totp_enabled: false, created_at: '2026-02-01' },
    ])

    render(<AdminsPage />)

    await waitFor(() => {
      expect(screen.getByText('admin@test.com')).toBeInTheDocument()
      expect(screen.getByText('user@test.com')).toBeInTheDocument()
      expect(screen.getByText('super_admin')).toBeInTheDocument()
      expect(screen.getByText('domain_admin')).toBeInTheDocument()
    })
  })

  it('edits an admin email without password', async () => {
    mockApi.listAdmins.mockResolvedValue([
      { id: '42', email: 'old@test.com', role: 'admin', totp_enabled: false, created_at: '2026-01-01' },
    ])
    mockApi.updateAdmin.mockResolvedValue({
      id: '42', email: 'new@test.com', role: 'admin', totp_enabled: false, created_at: '2026-01-01',
    })

    const { container } = render(<AdminsPage />)
    await waitFor(() => expect(screen.getByText('old@test.com')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /^Edit$/ }))

    const emailInput = container.querySelector('input[type="email"]') as HTMLInputElement
    fireEvent.change(emailInput, { target: { value: 'new@test.com' } })

    fireEvent.click(screen.getByRole('button', { name: /Save Changes/ }))

    await waitFor(() => {
      expect(mockApi.updateAdmin).toHaveBeenCalledWith('42', { email: 'new@test.com' })
    })
  })

  it('edits admin password without changing email or role', async () => {
    mockApi.listAdmins.mockResolvedValue([
      { id: '42', email: 'admin@test.com', role: 'admin', totp_enabled: false, created_at: '2026-01-01' },
    ])
    mockApi.updateAdmin.mockResolvedValue({
      id: '42', email: 'admin@test.com', role: 'admin', totp_enabled: false, created_at: '2026-01-01',
    })

    const { container } = render(<AdminsPage />)
    await waitFor(() => expect(screen.getByText('admin@test.com')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /^Edit$/ }))

    const pwInput = container.querySelector('input[placeholder*="Leave blank"]') as HTMLInputElement
    fireEvent.change(pwInput, { target: { value: 'brand-new-password-123' } })

    fireEvent.click(screen.getByRole('button', { name: /Save Changes/ }))

    await waitFor(() => {
      expect(mockApi.updateAdmin).toHaveBeenCalledWith('42', { password: 'brand-new-password-123' })
    })
  })

  it('requires TOTP code when acting admin has TOTP enabled', async () => {
    mockApi.me.mockResolvedValue({ id: 'self', email: 'me@test.com', role: 'super_admin', totp_enabled: true })
    mockApi.listAdmins.mockResolvedValue([
      { id: '42', email: 'other@test.com', role: 'admin', totp_enabled: false, created_at: '2026-01-01' },
    ])

    render(<AdminsPage />)
    await waitFor(() => expect(screen.getByText('other@test.com')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /^Edit$/ }))

    await waitFor(() => {
      expect(screen.getByText(/Your TOTP code/i)).toBeInTheDocument()
    })
  })
})
