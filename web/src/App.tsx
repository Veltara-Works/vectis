import { useState, useEffect } from 'react'
import { Routes, Route, Navigate, Link, useLocation } from 'react-router-dom'
import { api } from './api/client.ts'
import LoginPage from './pages/Login.tsx'
import DashboardPage from './pages/Dashboard.tsx'
import DomainsPage from './pages/Domains.tsx'
import MailboxesPage from './pages/Mailboxes.tsx'
import AliasesPage from './pages/Aliases.tsx'
import MessagesPage from './pages/Messages.tsx'
import DeliverabilityPage from './pages/Deliverability.tsx'
import AdminsPage from './pages/Admins.tsx'
import AuditLogPage from './pages/AuditLog.tsx'
import UpdatesPage from './pages/Updates.tsx'
import BackupsPage from './pages/Backups.tsx'
import LicensePage from './pages/License.tsx'
import SessionsPage from './pages/Sessions.tsx'
import FilterRulesPage from './pages/FilterRules.tsx'
import LogSearchPage from './pages/LogSearch.tsx'
import SetupWizardPage from './pages/SetupWizard.tsx'

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
    { path: '/admin/setup', label: 'Setup Wizard', show: true },
    { path: '/admin/domains', label: 'Domains', show: true },
    { path: '/admin/mailboxes', label: 'Mailboxes', show: true },
    { path: '/admin/aliases', label: 'Aliases', show: true },
    { path: '/admin/messages', label: 'Messages', show: true },
    { path: '/admin/deliverability', label: 'Deliverability', show: true },
    { path: '/admin/filters', label: 'Filter Rules', show: true },
    { path: '/admin/admins', label: 'Admins', show: isAdminOrAbove },
    { path: '/admin/audit', label: 'Audit Log', show: isAdminOrAbove },
    { path: '/admin/logs', label: 'Log Search', show: isSuperAdmin },
    { path: '/admin/updates', label: 'Updates', show: isSuperAdmin },
    { path: '/admin/backups', label: 'Backups', show: isSuperAdmin },
    { path: '/admin/license', label: 'License', show: isSuperAdmin },
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
      </nav>
      <div className="main-wrap">
        <header className="topbar">
          <AccountMenu
            email={admin?.email ?? ''}
            role={admin?.role ?? ''}
            onLogout={() => api.logout().then(() => { setLoggedIn(false); setAdmin(null) })}
          />
        </header>
        <main className="main">
          <Routes>
            <Route path="/admin" element={<DashboardPage />} />
            <Route path="/admin/setup" element={<SetupWizardPage />} />
            <Route path="/admin/domains" element={<DomainsPage />} />
            <Route path="/admin/mailboxes" element={<MailboxesPage />} />
            <Route path="/admin/aliases" element={<AliasesPage />} />
            <Route path="/admin/messages" element={<MessagesPage />} />
            <Route path="/admin/deliverability" element={<DeliverabilityPage />} />
            <Route path="/admin/filters" element={<FilterRulesPage />} />
            {isAdminOrAbove && <Route path="/admin/admins" element={<AdminsPage />} />}
            {isAdminOrAbove && <Route path="/admin/audit" element={<AuditLogPage />} />}
            {isSuperAdmin && <Route path="/admin/logs" element={<LogSearchPage />} />}
            {isSuperAdmin && <Route path="/admin/updates" element={<UpdatesPage />} />}
            {isSuperAdmin && <Route path="/admin/backups" element={<BackupsPage />} />}
            {isSuperAdmin && <Route path="/admin/license" element={<LicensePage />} />}
            <Route path="/admin/sessions" element={<SessionsPage />} />
            <Route path="*" element={<Navigate to="/admin" />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

function AccountMenu({ email, role, onLogout }: { email: string; role: string; onLogout: () => void }) {
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (!open) return
    const close = () => setOpen(false)
    document.addEventListener('click', close)
    return () => document.removeEventListener('click', close)
  }, [open])
  return (
    <div className="account-menu" onClick={e => e.stopPropagation()}>
      <button className="account-menu-trigger" onClick={() => setOpen(o => !o)} aria-haspopup="menu" aria-expanded={open}>
        <span className="account-menu-email-text">{email || 'Account'}</span>
        <span className="account-menu-caret" aria-hidden>▾</span>
      </button>
      {open && (
        <div className="account-menu-dropdown" role="menu">
          <div className="account-menu-header">
            <div className="account-menu-label">Signed in as</div>
            <div className="account-menu-email">{email}</div>
            {role && <div className="account-menu-role">{role}</div>}
          </div>
          <button className="account-menu-item" role="menuitem" onClick={() => { setOpen(false); onLogout() }}>
            Logout
          </button>
        </div>
      )}
    </div>
  )
}
