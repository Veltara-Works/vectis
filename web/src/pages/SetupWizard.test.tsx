import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SetupWizard from './SetupWizard'

vi.mock('../api/client', () => ({
  api: {
    listDomains: vi.fn(),
    listMailboxes: vi.fn(),
    createDomain: vi.fn(),
    getDKIM: vi.fn(),
    verifyDomain: vi.fn(),
    createMailbox: vi.fn(),
    deliverability: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => {
  vi.clearAllMocks()
})

describe('SetupWizard', () => {
  it('renders wizard title', async () => {
    mockApi.listDomains.mockResolvedValue([])

    render(<SetupWizard />)

    await waitFor(() => {
      expect(screen.getByText('Setup Wizard')).toBeInTheDocument()
    })
  })

  it('starts at step 1 when no domains exist', async () => {
    mockApi.listDomains.mockResolvedValue([])

    render(<SetupWizard />)

    await waitFor(() => {
      expect(screen.getByText('Add Your Domain')).toBeInTheDocument()
      expect(screen.getByPlaceholderText('example.com')).toBeInTheDocument()
    })
  })

  it('creates domain and advances to step 2', async () => {
    mockApi.listDomains
      .mockResolvedValueOnce([])
      .mockResolvedValue([{ id: '1', name: 'test.com', active: true, dkim_enabled: true, dkim_selector: 'vectis', verification_status: 'pending', verification_token: 'tok123', created_at: '2026-01-01', spam_threshold: 5 }] as never)
    mockApi.createDomain.mockResolvedValue({
      domain: { id: '1', name: 'test.com' },
      dkim: { dns_name: 'vectis._domainkey.test.com', dns_value: 'v=DKIM1; k=rsa; p=...' },
    })
    mockApi.getDKIM.mockResolvedValue({ dns_name: 'vectis._domainkey.test.com', dns_value: 'v=DKIM1; k=rsa; p=...', selector: 'vectis' })

    render(<SetupWizard />)

    await waitFor(() => expect(screen.getByPlaceholderText('example.com')).toBeInTheDocument())

    const user = userEvent.setup()
    await user.type(screen.getByPlaceholderText('example.com'), 'test.com')
    await user.click(screen.getByText('Create Domain'))

    await waitFor(() => {
      expect(screen.getByText('Configure DNS Records')).toBeInTheDocument()
      expect(screen.getByText('MX Record')).toBeInTheDocument()
      expect(screen.getByText('SPF Record')).toBeInTheDocument()
    })
  })

  it('resumes at step 3 when domain exists but is unverified', async () => {
    mockApi.listDomains.mockResolvedValue([
      { id: '1', name: 'test.com', active: true, dkim_enabled: true, dkim_selector: 'vectis', verification_status: 'pending', verification_token: 'tok123', created_at: '2026-01-01', spam_threshold: 5 },
    ] as never)
    mockApi.getDKIM.mockResolvedValue({ dns_name: 'vectis._domainkey.test.com', dns_value: 'v=DKIM1', selector: 'vectis' })

    render(<SetupWizard />)

    await waitFor(() => {
      expect(screen.getByText('Verify Domain Ownership')).toBeInTheDocument()
      expect(screen.getByText('Verify Now')).toBeInTheDocument()
    })
  })

  it('resumes at step 4 when domain is verified but no mailbox', async () => {
    mockApi.listDomains.mockResolvedValue([
      { id: '1', name: 'test.com', active: true, dkim_enabled: true, dkim_selector: 'vectis', verification_status: 'verified', created_at: '2026-01-01', spam_threshold: 5 },
    ] as never)
    mockApi.getDKIM.mockResolvedValue({ dns_name: 'vectis._domainkey.test.com', dns_value: 'v=DKIM1', selector: 'vectis' })
    mockApi.listMailboxes.mockResolvedValue([])

    render(<SetupWizard />)

    await waitFor(() => {
      expect(screen.getByText('Create Your First Mailbox')).toBeInTheDocument()
    })
  })

  it('resumes at step 5 when domain verified and mailbox exists', async () => {
    mockApi.listDomains.mockResolvedValue([
      { id: '1', name: 'test.com', active: true, dkim_enabled: true, dkim_selector: 'vectis', verification_status: 'verified', created_at: '2026-01-01', spam_threshold: 5 },
    ] as never)
    mockApi.getDKIM.mockResolvedValue({ dns_name: 'vectis._domainkey.test.com', dns_value: 'v=DKIM1', selector: 'vectis' })
    mockApi.listMailboxes.mockResolvedValue([
      { id: 'mb1', domain_id: '1', local_part: 'admin', quota_mb: 1024, active: true, created_at: '2026-01-01' },
    ] as never)
    mockApi.deliverability.mockResolvedValue({ domain: 'test.com', checks: [
      { name: 'mx', status: 'pass', value: 'mail.test.com' },
      { name: 'spf', status: 'pass', value: 'v=spf1 mx a ~all' },
    ] })

    render(<SetupWizard />)

    await waitFor(() => {
      expect(screen.getByText('Deliverability Review')).toBeInTheDocument()
      expect(screen.getByText('2/2 checks passed')).toBeInTheDocument()
    })
  })

  it('shows setup complete when all checks pass', async () => {
    mockApi.listDomains.mockResolvedValue([
      { id: '1', name: 'test.com', active: true, dkim_enabled: true, dkim_selector: 'vectis', verification_status: 'verified', created_at: '2026-01-01', spam_threshold: 5 },
    ] as never)
    mockApi.getDKIM.mockResolvedValue({ dns_name: 'vectis._domainkey.test.com', dns_value: 'v=DKIM1', selector: 'vectis' })
    mockApi.listMailboxes.mockResolvedValue([
      { id: 'mb1', domain_id: '1', local_part: 'admin', quota_mb: 1024, active: true, created_at: '2026-01-01' },
    ] as never)
    mockApi.deliverability.mockResolvedValue({ domain: 'test.com', checks: [
      { name: 'mx', status: 'pass' },
      { name: 'spf', status: 'pass' },
      { name: 'dkim', status: 'pass' },
      { name: 'dmarc', status: 'pass' },
    ] })

    render(<SetupWizard />)

    await waitFor(() => {
      expect(screen.getByText('Setup Complete!')).toBeInTheDocument()
      expect(screen.getByText('4/4 checks passed')).toBeInTheDocument()
    })
  })

  it('shows error on domain creation failure', async () => {
    mockApi.listDomains.mockResolvedValue([])
    mockApi.createDomain.mockRejectedValue(new Error('Invalid domain name'))

    render(<SetupWizard />)

    await waitFor(() => expect(screen.getByPlaceholderText('example.com')).toBeInTheDocument())

    const user = userEvent.setup()
    await user.type(screen.getByPlaceholderText('example.com'), 'bad')
    await user.click(screen.getByText('Create Domain'))

    await waitFor(() => {
      expect(screen.getByText('Invalid domain name')).toBeInTheDocument()
    })
  })
})
