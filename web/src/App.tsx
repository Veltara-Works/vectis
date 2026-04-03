import { useState, useEffect } from 'react'
import { Routes, Route, Navigate, Link, useLocation } from 'react-router-dom'
import { api } from './api/client.ts'
import LoginPage from './pages/Login.tsx'
import DashboardPage from './pages/Dashboard.tsx'
import DomainsPage from './pages/Domains.tsx'
import MailboxesPage from './pages/Mailboxes.tsx'
import AliasesPage from './pages/Aliases.tsx'
import DeliverabilityPage from './pages/Deliverability.tsx'
import AdminsPage from './pages/Admins.tsx'
import AuditLogPage from './pages/AuditLog.tsx'
import UpdatesPage from './pages/Updates.tsx'
import BackupsPage from './pages/Backups.tsx'
import SessionsPage from './pages/Sessions.tsx'

export default function App() {
  const [loggedIn, setLoggedIn] = useState<boolean | null>(null)
  const location = useLocation()

  useEffect(() => {
    api.sessions()
      .then(() => setLoggedIn(true))
      .catch(() => setLoggedIn(false))
  }, [])

  if (loggedIn === null) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', color: '#94a3b8' }}>Loading...</div>

  if (!loggedIn) {
    return <LoginPage onLogin={() => setLoggedIn(true)} />
  }

  const nav = [
    { path: '/admin', label: 'Dashboard' },
    { path: '/admin/domains', label: 'Domains' },
    { path: '/admin/mailboxes', label: 'Mailboxes' },
    { path: '/admin/aliases', label: 'Aliases' },
    { path: '/admin/deliverability', label: 'Deliverability' },
    { path: '/admin/admins', label: 'Admins' },
    { path: '/admin/audit', label: 'Audit Log' },
    { path: '/admin/updates', label: 'Updates' },
    { path: '/admin/backups', label: 'Backups' },
    { path: '/admin/sessions', label: 'Sessions' },
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
          <Route path="/admin/aliases" element={<AliasesPage />} />
          <Route path="/admin/deliverability" element={<DeliverabilityPage />} />
          <Route path="/admin/admins" element={<AdminsPage />} />
          <Route path="/admin/audit" element={<AuditLogPage />} />
          <Route path="/admin/updates" element={<UpdatesPage />} />
          <Route path="/admin/backups" element={<BackupsPage />} />
          <Route path="/admin/sessions" element={<SessionsPage />} />
          <Route path="*" element={<Navigate to="/admin" />} />
        </Routes>
      </main>
    </div>
  )
}
