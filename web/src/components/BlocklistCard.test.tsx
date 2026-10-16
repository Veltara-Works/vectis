import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import BlocklistCard, { summarizeIP } from './BlocklistCard'

vi.mock('../api/client', async () => ({
  ApiError: (await vi.importActual<typeof import('../api/client')>('../api/client')).ApiError,
  api: { rblStatus: vi.fn(), rblCheckNow: vi.fn() },
}))

import { api, ApiError } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => vi.clearAllMocks())

describe('summarizeIP', () => {
  it('a listing wins', () => {
    expect(summarizeIP(1, 2, 6)).toEqual({ badge: 'badge-danger', text: 'listed on 1 of 6' })
  })
  it('unknown results are called out, not counted as clean', () => {
    const s = summarizeIP(0, 1, 6)
    expect(s.badge).toBe('badge-warning')
    expect(s.text).toContain('1 could not be checked')
  })
  it('all clean', () => {
    expect(summarizeIP(0, 0, 6)).toEqual({ badge: 'badge-success', text: 'not listed on any of 6' })
  })
})

describe('BlocklistCard', () => {
  it('shows each list, links delisting for a listing, and explains unknowns', async () => {
    mockApi.rblStatus.mockResolvedValue({
      ips: [{
        ip_address: '203.0.113.7', listed_count: 1, unknown_count: 1, clean: false,
        checks: [
          { rbl_name: 'zen.spamhaus.org', list_name: 'Spamhaus ZEN', delist_url: 'https://check.spamhaus.org/', status: 'listed', response: '127.0.0.4', checked_at: '2026-10-16T00:00:00Z' },
          { rbl_name: 'bl.spamcop.net', list_name: 'SpamCop', status: 'clean', checked_at: '2026-10-16T00:00:00Z' },
          { rbl_name: 'b.barracudacentral.org', list_name: 'Barracuda BRBL', status: 'unknown', response: 'list unavailable: list did not answer its test address', checked_at: '2026-10-16T00:00:00Z' },
        ],
      }],
    })
    render(<BlocklistCard />)
    await waitFor(() => expect(screen.getByText('Spamhaus ZEN')).toBeInTheDocument())
    expect(screen.getByText('listed on 1 of 3')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Request delisting' })).toHaveAttribute('href', 'https://check.spamhaus.org/')
    expect(screen.getByText('not listed')).toBeInTheDocument()
    expect(screen.getByText(/did not answer its test address/)).toBeInTheDocument()
  })

  it('is hidden for admins without access', async () => {
    mockApi.rblStatus.mockRejectedValue(new ApiError('FORBIDDEN', 'forbidden', 403))
    const { container } = render(<BlocklistCard />)
    await waitFor(() => expect(mockApi.rblStatus).toHaveBeenCalled())
    await waitFor(() => expect(container).toBeEmptyDOMElement())
  })

  it('says when there are no results yet', async () => {
    mockApi.rblStatus.mockResolvedValue({ status: 'no_ips_yet', ips: [] })
    render(<BlocklistCard />)
    await waitFor(() => expect(screen.getByText(/No results yet/)).toBeInTheDocument())
  })
})
