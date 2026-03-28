import { useState, useEffect } from 'react'
import { Routes, Route, Navigate, Link, useLocation } from 'react-router-dom'
import { api } from './api/client.ts'
import LoginPage from './pages/Login.tsx'
import DashboardPage from './pages/Dashboard.tsx'
import DomainsPage from './pages/Domains.tsx'
import MailboxesPage from './pages/Mailboxes.tsx'

export default function App() {
  const [loggedIn, setLoggedIn] = useState<boolean | null>(null)
  const location = useLocation()

  useEffect(() => {
    api.health()
      .then(() => api.sessions())
      .then(() => setLoggedIn(true))
      .catch(() => setLoggedIn(false))
  }, [])

  if (loggedIn === null) return null

  if (!loggedIn) {
    return <LoginPage onLogin={() => setLoggedIn(true)} />
  }

  const nav = [
    { path: '/admin', label: 'Dashboard' },
    { path: '/admin/domains', label: 'Domains' },
    { path: '/admin/mailboxes', label: 'Mailboxes' },
  ]

  return (
    <div className="app">
      <nav className="sidebar">
        <h1>Vectis Mail</h1>
        {nav.map(n => (
          <Link key={n.path} to={n.path}
            className={location.pathname === n.path ? 'active' : ''}>
            {n.label}
          </Link>
        ))}
        <a href="#" onClick={e => { e.preventDefault(); api.logout().then(() => setLoggedIn(false)) }}
          style={{ marginTop: 'auto', position: 'absolute', bottom: '1rem', left: 0, right: 0 }}>
          Logout
        </a>
      </nav>
      <main className="main">
        <Routes>
          <Route path="/admin" element={<DashboardPage />} />
          <Route path="/admin/domains" element={<DomainsPage />} />
          <Route path="/admin/mailboxes" element={<MailboxesPage />} />
          <Route path="*" element={<Navigate to="/admin" />} />
        </Routes>
      </main>
    </div>
  )
}
