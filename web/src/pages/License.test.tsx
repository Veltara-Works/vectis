import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LicensePage from './License'

vi.mock('../api/client', () => ({
  api: {
    getLicense: vi.fn(),
    setLicense: vi.fn(),
    removeLicense: vi.fn(),
    createUpgradeCheckoutSession: vi.fn(),
  },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

// Default free-tier state — what a fresh install returns from /api/v1/license.
const freeState = {
  configured: false,
  from_db: false,
  tier: 'free' as const,
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.getLicense.mockResolvedValue(freeState)
})

function renderAt(initialEntry: string) {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <LicensePage />
    </MemoryRouter>,
  )
}

describe('LicensePage — in-product Buy Pro flow (v0.1.14)', () => {
  it('renders primary "Subscribe to Vectis Mail Pro" CTA in Free tier', async () => {
    renderAt('/admin/license')
    expect(await screen.findByRole('button', {
      name: /Subscribe to Vectis Mail Pro.*\$29 USD\/mo/i,
    })).toBeInTheDocument()
  })

  it('renders the "Already purchased? Paste credentials" secondary button', async () => {
    renderAt('/admin/license')
    expect(await screen.findByRole('button', {
      name: /Already purchased\? Paste credentials/i,
    })).toBeInTheDocument()
  })

  it('does NOT render the Subscribe button when license is already configured', async () => {
    mockApi.getLicense.mockResolvedValue({
      ...freeState,
      configured: true,
      tier: 'pro',
      status: 'active',
      subscription_id_masked: 'sub_••••1234',
    })
    renderAt('/admin/license')
    await screen.findByText(/PRO/)
    expect(screen.queryByRole('button', { name: /Subscribe to Vectis Mail Pro/i })).not.toBeInTheDocument()
  })

  it('renders success banner when ?checkout=success is in the URL', async () => {
    renderAt('/admin/license?checkout=success')
    await waitFor(() => {
      expect(screen.getByText(/Thanks for subscribing to Vectis Mail Pro!/i)).toBeInTheDocument()
    })
    expect(screen.getByText(/Check your email for your License Key, Service Key, and Tenant ID/i))
      .toBeInTheDocument()
  })

  it('auto-opens the paste-credentials form when returning from a successful checkout', async () => {
    // ?checkout=success means the buyer just paid and their credentials are in
    // their inbox — the activation form should already be visible so the
    // "paste them below" banner has something below it (no extra click).
    renderAt('/admin/license?checkout=success')
    expect(await screen.findByPlaceholderText('VLDX-...')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('vx_...')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('your-tenant-code')).toBeInTheDocument()
  })

  it('keeps the optional fields behind an "Advanced (optional)" disclosure', async () => {
    renderAt('/admin/license')
    fireEvent.click(await screen.findByRole('button', { name: /Already purchased\? Paste credentials/i }))
    await screen.findByPlaceholderText('VLDX-...')
    // The three required keys are surfaced directly; the rest live under a
    // collapsible <summary> so the default view matches the activation email.
    expect(screen.getByText(/Advanced \(optional\)/i)).toBeInTheDocument()
  })

  it('renders cancel banner when ?checkout=cancel is in the URL', async () => {
    renderAt('/admin/license?checkout=cancel')
    await waitFor(() => {
      expect(screen.getByText(/Checkout cancelled — no charge was made/i)).toBeInTheDocument()
    })
  })

  it('does NOT render any checkout banner on the default Free-tier view', async () => {
    renderAt('/admin/license')
    await screen.findByRole('button', { name: /Subscribe to Vectis Mail Pro/i })
    expect(screen.queryByText(/Thanks for subscribing to Vectis Mail Pro!/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/Checkout cancelled — no charge was made/i)).not.toBeInTheDocument()
  })

  it('clicking Subscribe calls createUpgradeCheckoutSession and navigates to the returned URL', async () => {
    mockApi.createUpgradeCheckoutSession.mockResolvedValue({
      url: 'https://checkout.stripe.com/c/pay/cs_live_xyz',
      session_id: 'cs_live_xyz',
    })
    // window.location.assign would navigate in jsdom too — stub it.
    const assign = vi.fn()
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...window.location, assign },
    })

    renderAt('/admin/license')
    const btn = await screen.findByRole('button', { name: /Subscribe to Vectis Mail Pro/i })
    fireEvent.click(btn)

    await waitFor(() => {
      expect(mockApi.createUpgradeCheckoutSession).toHaveBeenCalledWith({})
    })
    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith('https://checkout.stripe.com/c/pay/cs_live_xyz')
    })
  })

  it('Subscribe button shows loading state while in-flight', async () => {
    let resolve: ((v: { url: string }) => void) = () => {}
    mockApi.createUpgradeCheckoutSession.mockReturnValue(new Promise(r => { resolve = r }))

    renderAt('/admin/license')
    const btn = await screen.findByRole('button', { name: /Subscribe to Vectis Mail Pro/i }) as HTMLButtonElement
    fireEvent.click(btn)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Starting checkout\.\.\./i })).toBeDisabled()
    })

    resolve({ url: 'https://checkout.stripe.com/c/pay/cs_live_xyz' })
  })

  it('surfaces an error message when createUpgradeCheckoutSession fails', async () => {
    mockApi.createUpgradeCheckoutSession.mockRejectedValue(
      new Error('Could not mint checkout session: INSTALL_NOT_PROVISIONED'),
    )

    renderAt('/admin/license')
    const btn = await screen.findByRole('button', { name: /Subscribe to Vectis Mail Pro/i })
    fireEvent.click(btn)

    await waitFor(() => {
      expect(screen.getByText(/INSTALL_NOT_PROVISIONED/)).toBeInTheDocument()
    })
    // Button returns to clickable state after failure (so the user can retry).
    expect(screen.getByRole('button', { name: /Subscribe to Vectis Mail Pro/i })).not.toBeDisabled()
  })

  it('clicking "Already purchased?" reveals the paste-credentials form', async () => {
    renderAt('/admin/license')
    const togglerBtn = await screen.findByRole('button', { name: /Already purchased\? Paste credentials/i })

    // Form fields are not in the DOM before toggle.
    expect(screen.queryByPlaceholderText('VLDX-...')).not.toBeInTheDocument()

    fireEvent.click(togglerBtn)
    expect(await screen.findByPlaceholderText('VLDX-...')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('vx_...')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('your-tenant-code')).toBeInTheDocument()
  })
})
