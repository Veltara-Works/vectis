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

interface AdminProfile {
  id: string
  email: string
  role: string
  totp_enabled: boolean
}

export default function App() {
  const [loggedIn, setLoggedIn] = useState<boolean | null>(null)
  const [admin, setAdmin] = useState<AdminProfile | null>(null)
  const location = useLocation()

  useEffect(() => {
    api.me()
      .then(profile => { setAdmin(profile); setLoggedIn(true) })
      .catch(() => setLoggedIn(false))
  }, [])

  if (loggedIn === null) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', color: '#94a3b8' }}>Loading...</div>

  if (!loggedIn) {
    return <LoginPage onLogin={() => {
      api.me().then(profile => { setAdmin(profile); setLoggedIn(true) })
    }} />
  }

  const role = admin?.role ?? 'domain_admin'
  const isSuperAdmin = role === 'super_admin'
  const isAdminOrAbove = role === 'super_admin' || role === 'admin'

  const nav = [
    { path: '/admin', label: 'Dashboard', show: true },
    { path: '/admin/domains', label: 'Domains', show: true },
    { path: '/admin/mailboxes', label: 'Mailboxes', show: true },
    { path: '/admin/aliases', label: 'Aliases', show: true },
    { path: '/admin/deliverability', label: 'Deliverability', show: true },
    { path: '/admin/admins', label: 'Admins', show: isAdminOrAbove },
    { path: '/admin/audit', label: 'Audit Log', show: isAdminOrAbove },
    { path: '/admin/updates', label: 'Updates', show: isSuperAdmin },
    { path: '/admin/backups', label: 'Backups', show: isSuperAdmin },
    { path: '/admin/sessions', label: 'Sessions', show: true },
  ]

  return (
    <div className="app">
      <nav className="sidebar">
        <h1>Vectis Mail</h1>
        {nav.filter(n => n.show).map(n => (
          <Link key={n.path} to={n.path}
            className={location.pathname === n.path ? 'active' : ''}>
            {n.label}
          </Link>
        ))}
        <a href="#" onClick={e => { e.preventDefault(); api.logout().then(() => { setLoggedIn(false); setAdmin(null) }) }}
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
          {isAdminOrAbove && <Route path="/admin/admins" element={<AdminsPage />} />}
          {isAdminOrAbove && <Route path="/admin/audit" element={<AuditLogPage />} />}
          {isSuperAdmin && <Route path="/admin/updates" element={<UpdatesPage />} />}
          {isSuperAdmin && <Route path="/admin/backups" element={<BackupsPage />} />}
          <Route path="/admin/sessions" element={<SessionsPage />} />
          <Route path="*" element={<Navigate to="/admin" />} />
        </Routes>
      </main>
    </div>
  )
}
