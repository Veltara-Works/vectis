import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import AdminsPage from './Admins'

vi.mock('../api/client', () => ({
  api: {
    listAdmins: vi.fn(),
    createAdmin: vi.fn(),
    deleteAdmin: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => {
  vi.clearAllMocks()
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
})
