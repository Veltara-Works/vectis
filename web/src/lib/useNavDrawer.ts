import { useCallback, useEffect, useRef, useState } from 'react'

// useNavDrawer drives the off-canvas navigation on phones and tablets (below the
// 1024px breakpoint in index.css; on desktop the drawer markup is just the
// always-visible sidebar and this state is ignored by the CSS).
//
// It handles what makes a drawer usable and accessible:
//  - closes on Escape, on a route change (tapping a nav link), and via close();
//  - locks page scrolling behind the open drawer;
//  - moves focus into the drawer when it opens, and back to the toggle button
//    when it closes (so keyboard and screen-reader users aren't stranded).
export function useNavDrawer(pathname: string) {
  const [open, setOpen] = useState(false)
  const toggleRef = useRef<HTMLButtonElement | null>(null)
  const navRef = useRef<HTMLElement | null>(null)
  const wasOpen = useRef(false)

  const close = useCallback(() => setOpen(false), [])
  const toggle = useCallback(() => setOpen(o => !o), [])

  // Navigating (e.g. tapping a link in the drawer) closes it.
  useEffect(() => { setOpen(false) }, [pathname])

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

  // Focus: into the drawer on open, back to the toggle on close.
  useEffect(() => {
    if (open) {
      navRef.current?.querySelector<HTMLElement>('a, button')?.focus()
    } else if (wasOpen.current) {
      toggleRef.current?.focus()
    }
    wasOpen.current = open
  }, [open])

  return { open, toggle, close, toggleRef, navRef }
}
