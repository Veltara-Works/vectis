import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import DeliverabilityPage from './Deliverability'

vi.mock('../api/client', () => ({
  api: {
    listDomains: vi.fn(),
    deliverability: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => {
  vi.clearAllMocks()
})

describe('DeliverabilityPage', () => {
  it('renders page title', () => {
    mockApi.listDomains.mockResolvedValue([])
    render(<DeliverabilityPage />)
    expect(screen.getByText('Deliverability')).toBeInTheDocument()
  })

  it('auto-runs checks when domain is selected', async () => {
    mockApi.listDomains.mockResolvedValue([{ id: '1', name: 'test.com' }] as never)
    mockApi.deliverability.mockResolvedValue({
      domain: 'test.com',
      checks: [
        { name: 'mx', status: 'pass', value: 'mail.test.com' },
        { name: 'spf', status: 'pass', value: 'v=spf1 mx ~all' },
        { name: 'dkim', status: 'fail', hint: 'No DKIM record found' },
      ],
    })

    render(<DeliverabilityPage />)

    await waitFor(() => {
      expect(screen.getByText('MX Record')).toBeInTheDocument()
      expect(screen.getByText('SPF Record')).toBeInTheDocument()
      expect(screen.getByText('DKIM Record')).toBeInTheDocument()
      expect(screen.getByText('2/3 checks passed')).toBeInTheDocument()
      expect(screen.getByText('No DKIM record found')).toBeInTheDocument()
    })
  })

  it('shows all-pass badge when everything passes', async () => {
    mockApi.listDomains.mockResolvedValue([{ id: '1', name: 'test.com' }] as never)
    mockApi.deliverability.mockResolvedValue({
      domain: 'test.com',
      checks: [
        { name: 'mx', status: 'pass' },
        { name: 'spf', status: 'pass' },
      ],
    })

    render(<DeliverabilityPage />)

    await waitFor(() => {
      expect(screen.getByText('2/2 checks passed')).toBeInTheDocument()
    })
  })

  it('shows error on check failure', async () => {
    mockApi.listDomains.mockResolvedValue([{ id: '1', name: 'test.com' }] as never)
    mockApi.deliverability.mockRejectedValue(new Error('Service unavailable'))

    render(<DeliverabilityPage />)

    await waitFor(() => {
      expect(screen.getByText('Service unavailable')).toBeInTheDocument()
    })
  })
})
