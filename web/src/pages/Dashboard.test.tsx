import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import DashboardPage from './Dashboard'

vi.mock('../api/client', () => ({
  api: {
    health: vi.fn(),
    listDomains: vi.fn(),
    applyConfig: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => {
  vi.clearAllMocks()
})

describe('DashboardPage', () => {
  it('renders page title', () => {
    mockApi.health.mockResolvedValue({ status: 'healthy', services: {} })
    mockApi.listDomains.mockResolvedValue([])

    render(<DashboardPage />)
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
  })

  it('displays health status', async () => {
    mockApi.health.mockResolvedValue({
      status: 'healthy',
      services: {
        postfix: { status: 'healthy', response_ms: 5 },
        dovecot: { status: 'healthy', response_ms: 3 },
      },
    })
    mockApi.listDomains.mockResolvedValue([])

    render(<DashboardPage />)

    await waitFor(() => {
      expect(screen.getAllByText('healthy')).toHaveLength(3) // system + postfix + dovecot
      expect(screen.getByText('postfix')).toBeInTheDocument()
      expect(screen.getByText('dovecot')).toBeInTheDocument()
    })
  })

  it('shows domain count', async () => {
    mockApi.health.mockResolvedValue({ status: 'healthy', services: {} })
    mockApi.listDomains.mockResolvedValue([
      { id: '1', name: 'a.com', active: true },
      { id: '2', name: 'b.com', active: false },
    ] as never)

    render(<DashboardPage />)

    await waitFor(() => {
      expect(screen.getByText('2')).toBeInTheDocument() // total domains
      expect(screen.getByText('1')).toBeInTheDocument() // active domains
    })
  })

  it('shows error when health check fails', async () => {
    mockApi.health.mockRejectedValue(new Error('timeout'))
    mockApi.listDomains.mockResolvedValue([])

    render(<DashboardPage />)

    await waitFor(() => {
      expect(screen.getByText('Failed to load health')).toBeInTheDocument()
    })
  })

  it('applies config on button click', async () => {
    mockApi.health.mockResolvedValue({ status: 'healthy', services: {} })
    mockApi.listDomains.mockResolvedValue([])
    mockApi.applyConfig.mockResolvedValue({ message: 'Configuration applied successfully' })

    render(<DashboardPage />)
    const user = userEvent.setup()

    await user.click(screen.getByText('Reload Config'))

    await waitFor(() => {
      expect(screen.getByText('Configuration applied successfully')).toBeInTheDocument()
    })
  })
})
