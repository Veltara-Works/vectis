import { useCallback, useEffect, useRef, useState } from 'react'

// useNavDrawer drives the off-canvas navigation on phones and tablets (below the
// 1024px breakpoint in index.css; on desktop the drawer markup is just the
// always-visible sidebar and this state is ignored by the CSS).
//
// It handles what makes a drawer usable and accessible:
//  - closes on Escape, on a route change (tapping a nav link), and via close();
//  - locks page scrolling behind the open drawer;
//  - moves focus into the drawer when it opens, and back to the toggle button
//    when it closes (so keyboard and screen-reader users aren't stranded);
//  - makes everything behind the open drawer inert (backgroundRef), so focus
//    and assistive tech stay inside the drawer;
//  - resets when the window widens to the desktop layout (>= 1024px), where
//    the drawer is just the always-visible sidebar.
export const DESKTOP_QUERY = '(min-width: 1024px)'

export function useNavDrawer(pathname: string) {
  const [open, setOpen] = useState(false)
  const toggleRef = useRef<HTMLButtonElement | null>(null)
  const navRef = useRef<HTMLElement | null>(null)
  const backgroundRef = useRef<HTMLDivElement | null>(null)
  const wasOpen = useRef(false)

  const close = useCallback(() => setOpen(false), [])
  const toggle = useCallback(() => setOpen(o => !o), [])

  // Navigating (e.g. tapping a link in the drawer) closes it.
  useEffect(() => { setOpen(false) }, [pathname])

  // Widening to the desktop layout closes the drawer (and so releases the
  // scroll lock and the inert background).
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return
    const mq = window.matchMedia(DESKTOP_QUERY)
    const onChange = (e: MediaQueryListEvent) => { if (e.matches) setOpen(false) }
    mq.addEventListener?.('change', onChange)
    return () => mq.removeEventListener?.('change', onChange)
  }, [])

  // Escape closes; scroll lock while open.
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('keydown', onKey)
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = prevOverflow
    }
  }, [open])

  // Everything behind the open drawer is inert: not focusable, not clickable,
  // hidden from assistive tech. (The toggle lives there too; the drawer has
  // its own close button.) Runs before the focus effect so the toggle is
  // focusable again by the time focus returns to it.
  useEffect(() => {
    const bg = backgroundRef.current
    if (!bg) return
    if (open) bg.setAttribute('inert', '')
    else bg.removeAttribute('inert')
    return () => bg.removeAttribute('inert')
  }, [open])

  // Focus: into the drawer on open, back to the toggle on close.
  useEffect(() => {
    if (open) {
      navRef.current?.querySelector<HTMLElement>('a, button')?.focus()
    } else if (wasOpen.current) {
      toggleRef.current?.focus()
    }
    wasOpen.current = open
  }, [open])

  return { open, toggle, close, toggleRef, navRef, backgroundRef }
}
