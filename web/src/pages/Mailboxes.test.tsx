import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import MailboxesPage from './Mailboxes'

vi.mock('../api/client', () => ({
  api: {
    listDomains: vi.fn(),
    listMailboxes: vi.fn(),
    createMailbox: vi.fn(),
    updateMailbox: vi.fn(),
    deleteMailbox: vi.fn(),
    impersonate: vi.fn(),
    suspendMailboxSend: vi.fn(),
    resumeMailboxSend: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => {
  vi.clearAllMocks()
})

const domain = { id: 'd1', name: 'test.com' }
const mailbox = { id: 'mb1', domain_id: 'd1', local_part: 'admin', display_name: 'Admin User', quota_mb: 1024, active: true, created_at: '2026-01-01' }

describe('MailboxesPage', () => {
  it('renders page title', () => {
    mockApi.listDomains.mockResolvedValue([domain] as never)
    mockApi.listMailboxes.mockResolvedValue([])
    render(<MailboxesPage />)
    expect(screen.getByText('Mailboxes')).toBeInTheDocument()
  })

  it('lists mailboxes for selected domain', async () => {
    mockApi.listDomains.mockResolvedValue([domain] as never)
    mockApi.listMailboxes.mockResolvedValue([mailbox] as never)

    render(<MailboxesPage />)

    await waitFor(() => {
      expect(screen.getByText('admin@test.com')).toBeInTheDocument()
      expect(screen.getByText('Admin User')).toBeInTheDocument()
      expect(screen.getByText('1024 MB')).toBeInTheDocument()
    })
  })

  it('shows empty state when no mailboxes', async () => {
    mockApi.listDomains.mockResolvedValue([domain] as never)
    mockApi.listMailboxes.mockResolvedValue([])

    render(<MailboxesPage />)

    await waitFor(() => {
      expect(screen.getByText('No mailboxes in this domain')).toBeInTheDocument()
    })
  })

  it('toggles add mailbox form', async () => {
    mockApi.listDomains.mockResolvedValue([domain] as never)
    mockApi.listMailboxes.mockResolvedValue([])

    render(<MailboxesPage />)
    const user = userEvent.setup()

    await waitFor(() => expect(screen.getByText('Add Mailbox')).toBeEnabled())
    await user.click(screen.getByText('Add Mailbox'))

    expect(screen.getByPlaceholderText('e.g. john')).toBeInTheDocument()
    expect(screen.getByText('@test.com')).toBeInTheDocument()
  })

  it('validates password on mailbox creation', async () => {
    mockApi.listDomains.mockResolvedValue([domain] as never)
    mockApi.listMailboxes.mockResolvedValue([])

    render(<MailboxesPage />)
    const user = userEvent.setup()

    await waitFor(() => expect(screen.getByText('Add Mailbox')).toBeEnabled())
    await user.click(screen.getByText('Add Mailbox'))

    await user.type(screen.getByPlaceholderText('e.g. john'), 'user')
    await user.type(screen.getByPlaceholderText('Min 12 characters, letters + numbers'), 'short')
    await user.click(screen.getByText('Create Mailbox'))

    await waitFor(() => {
      expect(screen.getByText('Password must be at least 12 characters')).toBeInTheDocument()
    })
  })

  it('creates mailbox successfully', async () => {
    mockApi.listDomains.mockResolvedValue([domain] as never)
    mockApi.listMailboxes
      .mockResolvedValueOnce([])
      .mockResolvedValue([mailbox] as never)
    mockApi.createMailbox.mockResolvedValue({ id: 'mb1' })

    render(<MailboxesPage />)
    const user = userEvent.setup()

    await waitFor(() => expect(screen.getByText('Add Mailbox')).toBeEnabled())
    await user.click(screen.getByText('Add Mailbox'))

    await user.type(screen.getByPlaceholderText('e.g. john'), 'admin')
    await user.type(screen.getByPlaceholderText('Min 12 characters, letters + numbers'), 'SecurePass123!')
    await user.click(screen.getByText('Create Mailbox'))

    await waitFor(() => {
      expect(screen.getByText('Mailbox admin@test.com created')).toBeInTheDocument()
    })
  })

  it('suspends sending for an active mailbox', async () => {
    mockApi.listDomains.mockResolvedValue([domain] as never)
    mockApi.listMailboxes.mockResolvedValue([mailbox] as never)
    mockApi.suspendMailboxSend.mockResolvedValue({ message: 'ok' } as never)
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)

    render(<MailboxesPage />)
    const user = userEvent.setup()

    await waitFor(() => expect(screen.getByText('admin@test.com')).toBeInTheDocument())
    // An allowed mailbox shows the "allowed" badge and a "Suspend Sending" action.
    expect(screen.getByText('allowed')).toBeInTheDocument()
    await user.click(screen.getByText('Suspend Sending'))

    await waitFor(() => {
      expect(mockApi.suspendMailboxSend).toHaveBeenCalledWith('mb1', expect.any(String))
    })
    confirmSpy.mockRestore()
  })

  it('resumes sending for a suspended mailbox', async () => {
    const suspended = { ...mailbox, send_suspended: true, send_suspended_reason: 'abuse' }
    mockApi.listDomains.mockResolvedValue([domain] as never)
    mockApi.listMailboxes.mockResolvedValue([suspended] as never)
    mockApi.resumeMailboxSend.mockResolvedValue({ message: 'ok' } as never)

    render(<MailboxesPage />)
    const user = userEvent.setup()

    await waitFor(() => expect(screen.getByText('suspended')).toBeInTheDocument())
    await user.click(screen.getByText('Resume Sending'))

    await waitFor(() => {
      expect(mockApi.resumeMailboxSend).toHaveBeenCalledWith('mb1')
    })
  })

  it('generates password with the Generate button', async () => {
    mockApi.listDomains.mockResolvedValue([domain] as never)
    mockApi.listMailboxes.mockResolvedValue([])

    render(<MailboxesPage />)
    const user = userEvent.setup()

    await waitFor(() => expect(screen.getByText('Add Mailbox')).toBeEnabled())
    await user.click(screen.getByText('Add Mailbox'))
    await user.click(screen.getByText('Generate'))

    const pwInput = screen.getByPlaceholderText('Min 12 characters, letters + numbers') as HTMLInputElement
    expect(pwInput.value.length).toBeGreaterThanOrEqual(12)
  })
})
