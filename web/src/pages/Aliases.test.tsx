import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import AliasesPage from './Aliases'

vi.mock('../api/client', () => ({
  api: {
    listDomains: vi.fn(),
    listAliases: vi.fn(),
    createAlias: vi.fn(),
    deleteAlias: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => {
  vi.clearAllMocks()
})

describe('AliasesPage', () => {
  it('renders page title', () => {
    mockApi.listDomains.mockResolvedValue([])
    mockApi.listAliases.mockResolvedValue([])
    render(<AliasesPage />)
    expect(screen.getByText('Aliases')).toBeInTheDocument()
  })

  it('lists aliases for selected domain', async () => {
    mockApi.listDomains.mockResolvedValue([{ id: '1', name: 'test.com' }] as never)
    mockApi.listAliases.mockResolvedValue([
      { id: 'a1', domain_id: '1', source_local_part: 'info', destination: 'admin@test.com', active: true, created_at: '2026-01-01' },
    ] as never)

    render(<AliasesPage />)

    await waitFor(() => {
      expect(screen.getByText('info@test.com')).toBeInTheDocument()
      expect(screen.getByText('admin@test.com')).toBeInTheDocument()
    })
  })

  it('shows empty state', async () => {
    mockApi.listDomains.mockResolvedValue([{ id: '1', name: 'test.com' }] as never)
    mockApi.listAliases.mockResolvedValue([])

    render(<AliasesPage />)

    await waitFor(() => {
      expect(screen.getByText('No aliases in this domain')).toBeInTheDocument()
    })
  })

  it('creates alias successfully', async () => {
    mockApi.listDomains.mockResolvedValue([{ id: '1', name: 'test.com' }] as never)
    mockApi.listAliases
      .mockResolvedValueOnce([])
      .mockResolvedValue([{ id: 'a1', domain_id: '1', source_local_part: 'support', destination: 'admin@test.com', active: true, created_at: '2026-01-01' }] as never)
    mockApi.createAlias.mockResolvedValue({ id: 'a1' })

    render(<AliasesPage />)
    const user = userEvent.setup()

    await waitFor(() => expect(screen.getByText('Add Alias')).toBeEnabled())
    await user.click(screen.getByText('Add Alias'))
    await user.type(screen.getByPlaceholderText('e.g. info'), 'support')
    await user.type(screen.getByPlaceholderText('e.g. john@example.com'), 'admin@test.com')
    await user.click(screen.getByText('Create Alias'))

    await waitFor(() => {
      expect(screen.getByText(/Alias.*created/)).toBeInTheDocument()
    })
  })
})
