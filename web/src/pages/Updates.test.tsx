import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import UpdatesPage from './Updates'
import type { UpdateStatus } from '../api/client'

vi.mock('../api/client', async () => ({
  ApiError: (await vi.importActual<typeof import('../api/client')>('../api/client')).ApiError,
  api: {
    orchestratorStatus: vi.fn(),
    orchestratorHistory: vi.fn(),
    updateStatus: vi.fn(),
    updateCheckSettings: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

const status = (over: Partial<NonNullable<UpdateStatus['settings']>> = {}): UpdateStatus => {
  const settings = {
    check_enabled: true, email_enabled: true, check_locked: false, email_locked: false, switchable: true, ...over,
  }
  return {
    enabled: settings.check_enabled, email_enabled: settings.email_enabled, settings, running: 'v0.1.66',
    last: { checked_at: new Date().toISOString(), latest: 'v0.1.66', update_available: false },
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.orchestratorStatus.mockResolvedValue({ state: 'idle' })
  mockApi.orchestratorHistory.mockResolvedValue([])
})

describe('Updates page release-check switches', () => {
  it('turns the daily check off with the switch', async () => {
    mockApi.updateStatus.mockResolvedValue(status())
    mockApi.updateCheckSettings.mockResolvedValue(status({ check_enabled: false, email_enabled: false }))
    render(<UpdatesPage />)

    const sw = await screen.findByRole('switch', { name: 'Check daily for new releases' })
    expect(sw).toHaveAttribute('aria-checked', 'true')
    await userEvent.click(sw)

    expect(mockApi.updateCheckSettings).toHaveBeenCalledWith({ check_enabled: false })
    await waitFor(() => expect(sw).toHaveAttribute('aria-checked', 'false'))
    // email can't be on without the check
    expect(screen.getByRole('switch', { name: 'Email me about new releases' })).toBeDisabled()
  })

  it('turns only the email off', async () => {
    mockApi.updateStatus.mockResolvedValue(status())
    mockApi.updateCheckSettings.mockResolvedValue(status({ email_enabled: false }))
    render(<UpdatesPage />)

    await userEvent.click(await screen.findByRole('switch', { name: 'Email me about new releases' }))
    expect(mockApi.updateCheckSettings).toHaveBeenCalledWith({ email_enabled: false })
  })

  it('shows a switch locked by config.yaml as disabled, with the reason', async () => {
    mockApi.updateStatus.mockResolvedValue(status({ check_enabled: false, email_enabled: false, check_locked: true, email_locked: true }))
    render(<UpdatesPage />)

    const sw = await screen.findByRole('switch', { name: 'Check daily for new releases' })
    expect(sw).toBeDisabled()
    expect(screen.getByText(/Locked off in \/etc\/vectis\/config\.yaml/)).toBeInTheDocument()
  })

  it('hides the switches until the migration has run', async () => {
    mockApi.updateStatus.mockResolvedValue(status({ switchable: false }))
    render(<UpdatesPage />)

    await screen.findByText('Release Check')
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
  })
})
