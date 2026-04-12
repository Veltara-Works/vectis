import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import AuditLogPage from './AuditLog'

vi.mock('../api/client', () => ({
  api: {
    listAudit: vi.fn(),
    auditExportUrl: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

beforeEach(() => {
  vi.clearAllMocks()
})

describe('AuditLogPage', () => {
  it('renders page title', () => {
    mockApi.listAudit.mockResolvedValue({ data: [], meta: {} })
    render(<AuditLogPage />)
    expect(screen.getByText('Audit Log')).toBeInTheDocument()
  })

  it('lists audit entries', async () => {
    mockApi.listAudit.mockResolvedValue({
      data: [
        { id: '1', action: 'domain.create', resource_type: 'domain', resource_id: 'd1', admin_email: 'admin@test.com', timestamp: '2026-01-01T12:00:00Z', details: {} },
        { id: '2', action: 'mailbox.create', resource_type: 'mailbox', resource_id: 'mb1', admin_email: 'admin@test.com', timestamp: '2026-01-01T13:00:00Z', details: {} },
      ],
      meta: {},
    })

    render(<AuditLogPage />)

    await waitFor(() => {
      expect(screen.getByText('domain.create')).toBeInTheDocument()
      expect(screen.getByText('mailbox.create')).toBeInTheDocument()
    })
  })
})
