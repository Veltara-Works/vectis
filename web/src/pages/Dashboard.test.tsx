import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import DashboardPage from './Dashboard'

vi.mock('../api/client', () => ({
  api: {
    health: vi.fn(),
    listDomains: vi.fn(),
    listMailboxes: vi.fn(),
    applyConfig: vi.fn(),
    orchestratorStatus: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

const renderWithRouter = (ui: React.ReactElement) =>
  render(<MemoryRouter>{ui}</MemoryRouter>)

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.listMailboxes.mockResolvedValue([])
  // Dashboard polls orchestrator status on mount + every 5s to surface the
  // rc36+ self-replace countdown banner. Tests aren't exercising that path,
  // so a plain idle response is fine — but the mock must exist or mount fails.
  mockApi.orchestratorStatus.mockResolvedValue({ state: 'idle' })
})

describe('DashboardPage', () => {
  it('renders page title', () => {
    mockApi.health.mockResolvedValue({ status: 'healthy', services: {} })
    mockApi.listDomains.mockResolvedValue([])

    renderWithRouter(<DashboardPage />)
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

    renderWithRouter(<DashboardPage />)

    await waitFor(() => {
      expect(screen.getAllByText('healthy')).toHaveLength(3)
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

    renderWithRouter(<DashboardPage />)

    await waitFor(() => {
      // Check that the stats section contains the domain counts
      const statValues = document.querySelectorAll('.stat-value')
      const texts = Array.from(statValues).map(el => el.textContent)
      expect(texts).toContain('2')  // total domains
      expect(texts).toContain('1')  // active domains
    })
  })

  it('shows error when health check fails', async () => {
    mockApi.health.mockRejectedValue(new Error('timeout'))
    mockApi.listDomains.mockResolvedValue([])

    renderWithRouter(<DashboardPage />)

    await waitFor(() => {
      expect(screen.getByText('Failed to load health')).toBeInTheDocument()
    })
  })

  it('applies config on button click', async () => {
    mockApi.health.mockResolvedValue({ status: 'healthy', services: {} })
    mockApi.listDomains.mockResolvedValue([])
    mockApi.applyConfig.mockResolvedValue({ message: 'Configuration applied successfully' })

    renderWithRouter(<DashboardPage />)
    const user = userEvent.setup()

    await user.click(screen.getByText('Reload Config'))

    await waitFor(() => {
      expect(screen.getByText('Configuration applied successfully')).toBeInTheDocument()
    })
  })

  it('shows setup checklist when no domains exist', async () => {
    mockApi.health.mockResolvedValue({ status: 'healthy', services: {} })
    mockApi.listDomains.mockResolvedValue([])

    renderWithRouter(<DashboardPage />)

    await waitFor(() => {
      expect(screen.getByText('Getting Started')).toBeInTheDocument()
      expect(screen.getByText('Start Setup')).toBeInTheDocument()
    })
  })

  it('shows resume setup when domain exists but unverified', async () => {
    mockApi.health.mockResolvedValue({ status: 'healthy', services: {} })
    mockApi.listDomains.mockResolvedValue([
      { id: '1', name: 'test.com', active: true, verification_status: 'pending' },
    ] as never)

    renderWithRouter(<DashboardPage />)

    await waitFor(() => {
      expect(screen.getByText('Resume Setup')).toBeInTheDocument()
    })
  })

  it('hides setup checklist when domain verified and mailbox exists', async () => {
    mockApi.health.mockResolvedValue({ status: 'healthy', services: {} })
    mockApi.listDomains.mockResolvedValue([
      { id: '1', name: 'test.com', active: true, verification_status: 'verified' },
    ] as never)
    mockApi.listMailboxes.mockResolvedValue([
      { id: 'mb1', domain_id: '1', local_part: 'admin', quota_mb: 1024, active: true, created_at: '2026-01-01' },
    ] as never)

    renderWithRouter(<DashboardPage />)

    await waitFor(() => {
      expect(screen.queryByText('Getting Started')).not.toBeInTheDocument()
    })
  })
})
