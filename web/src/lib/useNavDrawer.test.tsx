import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useNavDrawer } from './useNavDrawer'

function Shell({ pathname }: { pathname: string }) {
  const d = useNavDrawer(pathname)
  return (
    <div>
      {d.open && <div data-testid="backdrop" onClick={d.close} />}
      <nav id="nav" aria-label="Main" ref={d.navRef} className={d.open ? 'open' : ''}>
        <a href="#a" onClick={(e) => { e.preventDefault(); d.close() }}>First link</a>
        <a href="#b">Second link</a>
      </nav>
      <div data-testid="background" ref={d.backgroundRef}>
        <button ref={d.toggleRef} aria-controls="nav" aria-expanded={d.open} onClick={d.toggle}>Menu</button>
      </div>
    </div>
  )
}

afterEach(() => { vi.unstubAllGlobals() })

describe('useNavDrawer', () => {
  it('opens with focus on the first link, and Escape closes it with focus back on the toggle', async () => {
    render(<Shell pathname="/admin" />)
    const toggle = screen.getByRole('button', { name: 'Menu' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')

    await userEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('link', { name: 'First link' })).toHaveFocus()
    expect(document.body.style.overflow).toBe('hidden')

    await userEvent.keyboard('{Escape}')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveFocus()
    expect(document.body.style.overflow).toBe('')
  })

  it('closes when the backdrop is tapped', async () => {
    render(<Shell pathname="/admin" />)
    await userEvent.click(screen.getByRole('button', { name: 'Menu' }))
    await userEvent.click(screen.getByTestId('backdrop'))
    expect(screen.getByRole('button', { name: 'Menu' })).toHaveAttribute('aria-expanded', 'false')
  })

  it('closes on navigation (route change)', async () => {
    const { rerender } = render(<Shell pathname="/admin" />)
    await userEvent.click(screen.getByRole('button', { name: 'Menu' }))
    expect(screen.getByRole('button', { name: 'Menu' })).toHaveAttribute('aria-expanded', 'true')
    act(() => { rerender(<Shell pathname="/admin/domains" />) })
    expect(screen.getByRole('button', { name: 'Menu' })).toHaveAttribute('aria-expanded', 'false')
    expect(document.body.style.overflow).toBe('')
  })

  it('makes the page behind the open drawer inert, and restores it on close', async () => {
    render(<Shell pathname="/admin" />)
    const bg = screen.getByTestId('background')
    expect(bg).not.toHaveAttribute('inert')
    await userEvent.click(screen.getByRole('button', { name: 'Menu' }))
    expect(bg).toHaveAttribute('inert')
    await userEvent.keyboard('{Escape}')
    expect(bg).not.toHaveAttribute('inert')
    expect(screen.getByRole('button', { name: 'Menu' })).toHaveFocus()
  })

  it('closes when the current page link is chosen (no route change)', async () => {
    render(<Shell pathname="/admin" />)
    await userEvent.click(screen.getByRole('button', { name: 'Menu' }))
    await userEvent.click(screen.getByRole('link', { name: 'First link' }))
    expect(screen.getByRole('button', { name: 'Menu' })).toHaveAttribute('aria-expanded', 'false')
    expect(document.body.style.overflow).toBe('')
  })

  it('closes and releases the scroll lock when the window widens to desktop', async () => {
    let listener: ((e: { matches: boolean }) => void) | undefined
    vi.stubGlobal('matchMedia', (q: string) => ({
      matches: false, media: q,
      addEventListener: (_: string, fn: (e: { matches: boolean }) => void) => { listener = fn },
      removeEventListener: () => { listener = undefined },
    }))
    render(<Shell pathname="/admin" />)
    await userEvent.click(screen.getByRole('button', { name: 'Menu' }))
    expect(document.body.style.overflow).toBe('hidden')
    act(() => { listener?.({ matches: true }) })
    expect(screen.getByRole('button', { name: 'Menu' })).toHaveAttribute('aria-expanded', 'false')
    expect(document.body.style.overflow).toBe('')
  })
})
