import { describe, it, expect } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useNavDrawer } from './useNavDrawer'

function Shell({ pathname }: { pathname: string }) {
  const d = useNavDrawer(pathname)
  return (
    <div>
      {d.open && <div data-testid="backdrop" onClick={d.close} />}
      <nav id="nav" aria-label="Main" ref={d.navRef} className={d.open ? 'open' : ''}>
        <a href="#a">First link</a>
        <a href="#b">Second link</a>
      </nav>
      <button ref={d.toggleRef} aria-controls="nav" aria-expanded={d.open} onClick={d.toggle}>Menu</button>
    </div>
  )
}

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
})
