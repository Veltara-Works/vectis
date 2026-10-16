import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import WarmupCard, { usage } from './WarmupCard'
import type { WarmupEntry } from '../api/client'

vi.mock('../api/client', async () => ({
  ApiError: (await vi.importActual<typeof import('../api/client')>('../api/client')).ApiError,
  api: { warmupList: vi.fn(), warmupStart: vi.fn(), warmupCancel: vi.fn() },
}))

import { api, ApiError } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => vi.clearAllMocks())

const entry = (over: Partial<WarmupEntry> = {}): WarmupEntry => ({
  id: 'w1', ip_address: '203.0.113.7', warmup_started: '2026-10-14T06:00:00Z', warmup_day: 3, days_total: 30,
  daily_limit: 100, daily_sent: 40, next_reset_at: '2026-10-17T06:00:00Z', active: true, ...over,
})

describe('usage', () => {
  it('under the limit', () => {
    expect(usage({ daily_sent: 40, daily_limit: 100 })).toEqual({ badge: 'badge-success', text: '40 of 100 external recipients today' })
  })
  it('at the limit is called out', () => {
    const u = usage({ daily_sent: 100, daily_limit: 100 })
    expect(u.badge).toBe('badge-warning')
    expect(u.text).toContain('limit reached')
  })
})

describe('WarmupCard', () => {
  it('shows the active warmup day and today\'s count, and cancels after confirming', async () => {
    mockApi.warmupList.mockResolvedValue([entry()])
    mockApi.warmupCancel.mockResolvedValue({ status: 'deleted' })
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    render(<WarmupCard />)
    await waitFor(() => expect(screen.getByText('day 3 of 30')).toBeInTheDocument())
    expect(screen.getByText('40 of 100 external recipients today')).toBeInTheDocument()
    expect(screen.queryByLabelText('Sending IP')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Cancel warmup' }))
    await waitFor(() => expect(mockApi.warmupCancel).toHaveBeenCalledWith('w1'))
  })

  it('offers to start a warmup when none is running', async () => {
    mockApi.warmupList.mockResolvedValue([])
    mockApi.warmupStart.mockResolvedValue(entry())
    render(<WarmupCard />)
    const input = await screen.findByLabelText('Sending IP')
    fireEvent.change(input, { target: { value: ' 203.0.113.7 ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Start warmup' }))
    await waitFor(() => expect(mockApi.warmupStart).toHaveBeenCalledWith('203.0.113.7', undefined))
  })

  it('shows the API error when a warmup is already running', async () => {
    mockApi.warmupList.mockResolvedValue([])
    mockApi.warmupStart.mockRejectedValue(new ApiError('WARMUP_ACTIVE', 'A warmup is already running for 198.51.100.9; cancel it before starting another', 409))
    render(<WarmupCard />)
    fireEvent.change(await screen.findByLabelText('Sending IP'), { target: { value: '203.0.113.7' } })
    fireEvent.click(screen.getByRole('button', { name: 'Start warmup' }))
    await waitFor(() => expect(screen.getByText(/already running/)).toBeInTheDocument())
  })

  it('lists finished warmups', async () => {
    mockApi.warmupList.mockResolvedValue([entry({ active: false, warmup_day: 30 })])
    render(<WarmupCard />)
    await waitFor(() => expect(screen.getByText(/warmup complete/)).toBeInTheDocument())
  })

  it('is hidden for admins without access', async () => {
    mockApi.warmupList.mockRejectedValue(new ApiError('FORBIDDEN', 'forbidden', 403))
    const { container } = render(<WarmupCard />)
    await waitFor(() => expect(mockApi.warmupList).toHaveBeenCalled())
    await waitFor(() => expect(container).toBeEmptyDOMElement())
  })
})
