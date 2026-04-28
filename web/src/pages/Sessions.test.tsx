import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import SessionsPage from './Sessions'

vi.mock('../api/client', () => ({
  api: {
    sessions: vi.fn(),
    deleteSession: vi.fn(),
    logoutAll: vi.fn(),
    totpSetup: vi.fn(),
    totpVerify: vi.fn(),
    totpDisable: vi.fn(),
    me: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => {
  vi.clearAllMocks()
})

describe('SessionsPage', () => {
  it('renders page title', () => {
    mockApi.sessions.mockResolvedValue([])
    mockApi.me.mockResolvedValue({ id: '1', email: 'admin@test.com', role: 'super_admin', totp_enabled: false, tier: 'free', features: [] })
    render(<SessionsPage />)
    expect(screen.getByText('Sessions')).toBeInTheDocument()
  })

  it('lists active sessions', async () => {
    mockApi.sessions.mockResolvedValue([
      { id: 's1', ip_address: '1.2.3.4', user_agent: 'Mozilla/5.0', created_at: '2026-01-01T00:00:00Z' },
      { id: 's2', ip_address: '5.6.7.8', user_agent: 'Chrome/120', created_at: '2026-01-02T00:00:00Z' },
    ])
    mockApi.me.mockResolvedValue({ id: '1', email: 'admin@test.com', role: 'super_admin', totp_enabled: false, tier: 'free', features: [] })

    render(<SessionsPage />)

    await waitFor(() => {
      expect(screen.getByText('1.2.3.4')).toBeInTheDocument()
      expect(screen.getByText('5.6.7.8')).toBeInTheDocument()
    })
  })
})
