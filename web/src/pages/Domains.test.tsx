import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import DomainsPage from './Domains'

vi.mock('../api/client', () => ({
  api: {
    listDomains: vi.fn(),
    createDomain: vi.fn(),
    updateDomain: vi.fn(),
    deleteDomain: vi.fn(),
    verifyDomain: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => {
  vi.clearAllMocks()
})

describe('DomainsPage', () => {
  it('renders page title and add button', () => {
    mockApi.listDomains.mockResolvedValue([])
    render(<DomainsPage />)
    expect(screen.getByText('Domains')).toBeInTheDocument()
    expect(screen.getByText('Add Domain')).toBeInTheDocument()
  })

  it('lists domains with verification badges', async () => {
    mockApi.listDomains.mockResolvedValue([
      { id: '1', name: 'example.com', active: true, dkim_enabled: true, dkim_selector: 'vectis', dkim_key_path: '/keys/example', verification_status: 'verified', created_at: '2026-01-01', spam_threshold: 5 },
      { id: '2', name: 'test.com', active: false, dkim_enabled: false, dkim_selector: 'vectis', verification_status: 'pending', created_at: '2026-02-01', spam_threshold: 5 },
    ] as never)

    render(<DomainsPage />)

    await waitFor(() => {
      expect(screen.getByText('example.com')).toBeInTheDocument()
      expect(screen.getByText('test.com')).toBeInTheDocument()
      expect(screen.getByText('verified')).toBeInTheDocument()
      expect(screen.getByText('pending')).toBeInTheDocument()
    })
  })

  it('shows empty state when no domains', async () => {
    mockApi.listDomains.mockResolvedValue([])
    render(<DomainsPage />)

    await waitFor(() => {
      expect(screen.getByText('No domains yet')).toBeInTheDocument()
    })
  })

  it('toggles add domain form', async () => {
    mockApi.listDomains.mockResolvedValue([])
    render(<DomainsPage />)

    const user = userEvent.setup()
    await user.click(screen.getByText('Add Domain'))

    expect(screen.getByPlaceholderText('example.com')).toBeInTheDocument()
    expect(screen.getByText('Create Domain')).toBeInTheDocument()

    await user.click(screen.getByText('Cancel'))
    expect(screen.queryByPlaceholderText('example.com')).not.toBeInTheDocument()
  })

  it('creates domain and shows DKIM info', async () => {
    mockApi.listDomains
      .mockResolvedValueOnce([])
      .mockResolvedValue([{ id: '1', name: 'new.com', active: true, dkim_enabled: true, dkim_selector: 'vectis', dkim_key_path: '/keys/new', verification_status: 'pending', created_at: '2026-01-01', spam_threshold: 5 }] as never)
    mockApi.createDomain.mockResolvedValue({
      domain: { id: '1', name: 'new.com' },
      dkim: { dns_name: 'vectis._domainkey.new.com', dns_value: 'v=DKIM1; k=rsa; p=MIIBIjAN...' },
    })

    render(<DomainsPage />)
    const user = userEvent.setup()

    await user.click(screen.getByText('Add Domain'))
    await user.type(screen.getByPlaceholderText('example.com'), 'new.com')
    await user.click(screen.getByText('Create Domain'))

    await waitFor(() => {
      expect(screen.getByText('Domain new.com created')).toBeInTheDocument()
      expect(screen.getByText('DKIM DNS Record')).toBeInTheDocument()
    })
  })

  it('shows error on create failure', async () => {
    mockApi.listDomains.mockResolvedValue([])
    mockApi.createDomain.mockRejectedValue(new Error('Domain already exists'))

    render(<DomainsPage />)
    const user = userEvent.setup()

    await user.click(screen.getByText('Add Domain'))
    await user.type(screen.getByPlaceholderText('example.com'), 'dup.com')
    await user.click(screen.getByText('Create Domain'))

    await waitFor(() => {
      expect(screen.getByText('Domain already exists')).toBeInTheDocument()
    })
  })

  it('verifies domain and shows success', async () => {
    mockApi.listDomains
      .mockResolvedValueOnce([{ id: '1', name: 'test.com', active: true, dkim_enabled: true, dkim_selector: 'vectis', verification_status: 'pending', created_at: '2026-01-01', spam_threshold: 5 }] as never)
      .mockResolvedValue([{ id: '1', name: 'test.com', active: true, dkim_enabled: true, dkim_selector: 'vectis', verification_status: 'verified', created_at: '2026-01-01', spam_threshold: 5 }] as never)
    mockApi.verifyDomain.mockResolvedValue({
      domain: 'test.com', verification_status: 'verified', verification_token: 'tok123',
      txt_record_name: 'test.com', txt_record_value: 'tok123', found: true,
    })

    render(<DomainsPage />)

    await waitFor(() => expect(screen.getByText('Verify')).toBeInTheDocument())

    const user = userEvent.setup()
    await user.click(screen.getByText('Verify'))

    await waitFor(() => {
      expect(screen.getByText('Domain test.com verified successfully')).toBeInTheDocument()
    })
  })

  it('shows TXT record hint when verification fails', async () => {
    mockApi.listDomains.mockResolvedValue([{ id: '1', name: 'test.com', active: true, dkim_enabled: true, dkim_selector: 'vectis', verification_status: 'pending', created_at: '2026-01-01', spam_threshold: 5 }] as never)
    mockApi.verifyDomain.mockResolvedValue({
      domain: 'test.com', verification_status: 'pending', verification_token: 'tok123',
      txt_record_name: '_vectis.test.com', txt_record_value: 'vectis-verify=tok123', found: false,
    })

    render(<DomainsPage />)

    await waitFor(() => expect(screen.getByText('Verify')).toBeInTheDocument())

    const user = userEvent.setup()
    await user.click(screen.getByText('Verify'))

    await waitFor(() => {
      expect(screen.getByText('Domain Verification Required')).toBeInTheDocument()
      expect(screen.getByText('_vectis.test.com')).toBeInTheDocument()
    })
  })

  describe('per-domain spam overrides (Pro)', () => {
    const pro = ['advanced_spam']
    const domain = (over: Record<string, unknown>) => ({
      id: '1', name: 'test.com', active: true, dkim_enabled: true, dkim_selector: 'vectis',
      verification_status: 'verified', created_at: '2026-01-01', ...over,
    })

    it('shows unset overrides as the system default', async () => {
      mockApi.listDomains.mockResolvedValue([domain({ reject_threshold: 12 })] as never)
      render(<DomainsPage features={pro} />)
      await waitFor(() => expect(screen.getByText('12.0')).toBeInTheDocument())
      expect(screen.getByText('Spam')).toBeInTheDocument()
      expect(screen.getAllByText('default')).toHaveLength(2) // spam threshold + greylisting
    })

    it('saves a spam threshold without pinning the other overrides', async () => {
      mockApi.listDomains.mockResolvedValue([domain({})] as never)
      mockApi.updateDomain.mockResolvedValue({ id: '1', name: 'test.com' } as never)
      render(<DomainsPage features={pro} />)
      const user = userEvent.setup()
      await user.click(await screen.findByText('Edit spam'))
      await user.type(screen.getByLabelText('Spam threshold for test.com'), '5.5')
      await user.click(screen.getByText('Save'))
      await waitFor(() => expect(mockApi.updateDomain).toHaveBeenCalledWith('1', {
        spam_threshold: 5.5, reject_threshold: null, greylist_enabled: null,
      }))
    })

    it('clears an override back to the default with an empty field', async () => {
      mockApi.listDomains.mockResolvedValue([domain({ spam_threshold: 4, greylist_enabled: false })] as never)
      mockApi.updateDomain.mockResolvedValue({ id: '1', name: 'test.com' } as never)
      render(<DomainsPage features={pro} />)
      const user = userEvent.setup()
      await user.click(await screen.findByText('Edit spam'))
      await user.clear(screen.getByLabelText('Spam threshold for test.com'))
      await user.click(screen.getByText('Save'))
      await waitFor(() => expect(mockApi.updateDomain).toHaveBeenCalledWith('1', {
        spam_threshold: null, reject_threshold: null, greylist_enabled: false,
      }))
    })

    it('hides the spam columns without the Pro feature', async () => {
      mockApi.listDomains.mockResolvedValue([domain({ spam_threshold: 4 })] as never)
      render(<DomainsPage />)
      await waitFor(() => expect(screen.getByText('test.com')).toBeInTheDocument())
      expect(screen.queryByText('Spam')).not.toBeInTheDocument()
      expect(screen.queryByText('Edit spam')).not.toBeInTheDocument()
    })
  })
})
