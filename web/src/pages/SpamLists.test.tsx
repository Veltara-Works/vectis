import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import SpamListsPage from './SpamLists'

vi.mock('../api/client', () => ({
  api: {
    listDomains: vi.fn(),
    listSpamListEntries: vi.fn(),
    createSpamListEntry: vi.fn(),
    deleteSpamListEntry: vi.fn(),
    dmarcRejections: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={['/admin/domains/d1/spam-lists']}>
      <Routes>
        <Route path="/admin/domains/:domainID/spam-lists" element={<SpamListsPage features={['advanced_spam']} />} />
      </Routes>
    </MemoryRouter>,
  )

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.listDomains.mockResolvedValue([{ id: 'd1', name: 'example.com' }] as never)
  mockApi.listSpamListEntries.mockResolvedValue([
    { id: 'e1', domain_id: 'd1', kind: 'block', scope: 'domain', pattern: 'spam.example', created_at: '2026-10-17T00:00:00Z' },
    { id: 'e2', domain_id: 'd1', kind: 'dmarc_exception', scope: 'domain', pattern: 'registrar.example', network: '27.111.95.31', created_at: '2026-10-17T00:00:00Z' },
  ])
  mockApi.createSpamListEntry.mockResolvedValue({ entry: {} } as never)
  mockApi.dmarcRejections.mockResolvedValue({
    domain: 'example.com', days: 7, total: 3,
    senders: [{
      from_domain: 'registrar.example', count: 3, first_seen: '2026-10-16T00:00:00Z', last_seen: '2026-10-17T00:00:00Z',
      example_from: 'notices@registrar.example', envelope_from_domains: ['registrar.example'], spf: 'R_SPF_FAIL', dkim: 'none',
      sources: [{ ip: '198.51.100.20', hostname: 'mail.platform.example', count: 3, last_seen: '2026-10-17T00:00:00Z' }],
    }],
  })
})

describe('SpamListsPage — DMARC exceptions (#265)', () => {
  it('lists exceptions with their network, only on their own tab', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('spam.example')).toBeInTheDocument())
    expect(screen.queryByText('registrar.example')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'DMARC exceptions' }))
    expect(screen.getByText('registrar.example')).toBeInTheDocument()
    expect(screen.getByText('27.111.95.31')).toBeInTheDocument()
    expect(screen.getByText(/only from the\s+network you name/)).toBeInTheDocument()
  })

  it('creates an exception with its network', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('spam.example')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'DMARC exceptions' }))
    fireEvent.change(screen.getByLabelText('Sender domain (header From)'), { target: { value: 'registrar.example' } })
    const add = screen.getByRole('button', { name: 'Add exception' })
    expect(add).toBeDisabled() // no network yet
    fireEvent.change(screen.getByLabelText('Sends from (IP, range or hostname)'), { target: { value: ' mail.example.net ' } })
    fireEvent.click(add)
    await waitFor(() => expect(mockApi.createSpamListEntry).toHaveBeenCalledWith('d1', 'dmarc_exception', 'domain', 'registrar.example', 'mail.example.net'))
  })

  it('creates allow and block entries without a network', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('spam.example')).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Pattern'), { target: { value: 'junk.example' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add block' }))
    await waitFor(() => expect(mockApi.createSpamListEntry).toHaveBeenCalledWith('d1', 'block', 'domain', 'junk.example'))
  })
})

describe('SpamListsPage — rejected by DMARC (#265 follow-up)', () => {
  it('shows rejections on the DMARC tab and fills the exception form from one', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('spam.example')).toBeInTheDocument())
    expect(screen.queryByText('Rejected by DMARC')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'DMARC exceptions' }))
    await waitFor(() => expect(screen.getByText('notices@registrar.example')).toBeInTheDocument())
    expect(mockApi.dmarcRejections).toHaveBeenCalledWith('d1', 7)
    expect(screen.getByText('mail.platform.example')).toBeInTheDocument()
    expect(screen.getByText('fail / none')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Use 198.51.100.20 for registrar.example' }))
    expect(screen.getByLabelText('Sender domain (header From)')).toHaveValue('registrar.example')
    expect(screen.getByLabelText('Sends from (IP, range or hostname)')).toHaveValue('198.51.100.20')
    expect(mockApi.createSpamListEntry).not.toHaveBeenCalled() // the operator still confirms

    fireEvent.change(screen.getByLabelText('Period'), { target: { value: '30' } })
    await waitFor(() => expect(mockApi.dmarcRejections).toHaveBeenCalledWith('d1', 30))
  })

  it('shows rejections without Pro, with no way to add an exception', async () => {
    render(
      <MemoryRouter initialEntries={['/admin/domains/d1/spam-lists']}>
        <Routes>
          <Route path="/admin/domains/:domainID/spam-lists" element={<SpamListsPage features={[]} />} />
        </Routes>
      </MemoryRouter>,
    )
    await waitFor(() => expect(screen.getByText('notices@registrar.example')).toBeInTheDocument())
    expect(screen.getByText(/DMARC exceptions are part of Vectis Mail Pro/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Use / })).not.toBeInTheDocument()
  })

  it('says so when nothing was rejected', async () => {
    mockApi.dmarcRejections.mockResolvedValue({ domain: 'example.com', days: 7, total: 0, senders: [] })
    renderPage()
    await waitFor(() => expect(screen.getByText('spam.example')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'DMARC exceptions' }))
    await waitFor(() => expect(screen.getByText('No mail to this domain was rejected by DMARC in the last 7 days.')).toBeInTheDocument())
  })
})
