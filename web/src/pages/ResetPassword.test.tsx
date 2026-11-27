import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ResetPasswordPage from './ResetPassword'
import { passwordProblem } from '../lib/passwordReset'

vi.mock('../api/client', () => ({
  api: { resetPassword: vi.fn() },
}))

import { api } from '../api/client'
const mockApi = vi.mocked(api)

function openLink(search: string) {
  window.history.replaceState(null, '', '/admin/reset-password' + search)
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('passwordProblem', () => {
  it('matches the server limits and checks the confirmation', () => {
    expect(passwordProblem('short', 'short')).toMatch(/at least 8/)
    expect(passwordProblem('x'.repeat(129), 'x'.repeat(129))).toMatch(/at most 128/)
    expect(passwordProblem('longenough1', 'longenough2')).toMatch(/do not match/)
    expect(passwordProblem('longenough1', 'longenough1')).toBe('')
  })

  it('counts UTF-8 bytes like the server', () => {
    // 4 x "é" = 8 bytes: valid on the server, so valid here
    expect(passwordProblem('éééé', 'éééé')).toBe('')
    // 65 x "é" = 130 bytes: over the server's 128
    expect(passwordProblem('é'.repeat(65), 'é'.repeat(65))).toMatch(/at most 128/)
  })
})

describe('ResetPasswordPage', () => {
  it('takes the token out of the address bar, then resets with it', async () => {
    openLink('?token=abc123')
    mockApi.resetPassword.mockResolvedValue({ message: 'ok' })
    render(<ResetPasswordPage />)
    await waitFor(() => expect(window.location.search).toBe(''))
    expect(window.location.pathname).toBe('/admin/reset-password')

    const user = userEvent.setup()
    await user.type(screen.getByLabelText('New password'), 'new-password-1')
    await user.type(screen.getByLabelText('Confirm new password'), 'new-password-1')
    await user.click(screen.getByRole('button', { name: 'Set new password' }))

    await waitFor(() => expect(mockApi.resetPassword).toHaveBeenCalledWith('abc123', 'new-password-1'))
    expect(await screen.findByRole('status')).toHaveTextContent('Your password has been changed')
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/admin')
  })

  it('refuses mismatched passwords without calling the server', async () => {
    openLink('?token=abc123')
    render(<ResetPasswordPage />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('New password'), 'new-password-1')
    await user.type(screen.getByLabelText('Confirm new password'), 'new-password-2')
    await user.click(screen.getByRole('button', { name: 'Set new password' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('do not match')
    expect(mockApi.resetPassword).not.toHaveBeenCalled()
  })

  it("shows the server's answer for a used or expired link", async () => {
    openLink('?token=old')
    mockApi.resetPassword.mockRejectedValue(new Error('This reset link is invalid, expired or already used. Request a new one.'))
    render(<ResetPasswordPage />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('New password'), 'new-password-1')
    await user.type(screen.getByLabelText('Confirm new password'), 'new-password-1')
    await user.click(screen.getByRole('button', { name: 'Set new password' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('already used')
    // the form stays, so the person can go back and request a new link
    expect(screen.getByRole('link', { name: 'Back to sign in' })).toHaveAttribute('href', '/admin')
  })

  it('explains a link without a token', () => {
    openLink('')
    render(<ResetPasswordPage />)
    expect(screen.getByText(/This reset link is incomplete/)).toBeInTheDocument()
    expect(screen.queryByLabelText('New password')).not.toBeInTheDocument()
  })
})
