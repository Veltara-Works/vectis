import { useState, useEffect } from 'react'
import { Routes, Route, Navigate, Link, useLocation } from 'react-router-dom'
import { api, type BrandingResponse } from './api/client.ts'
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
import BillingPage from './pages/Billing.tsx'
import BrandingPage from './pages/Branding.tsx'
import SessionsPage from './pages/Sessions.tsx'
import FilterRulesPage from './pages/FilterRules.tsx'
import LogSearchPage from './pages/LogSearch.tsx'
import SetupWizardPage from './pages/SetupWizard.tsx'
import SpamListsPage from './pages/SpamLists.tsx'

interface AdminProfile {
  id: string
  email: string
  role: string
  totp_enabled: boolean
  tier: 'free' | 'pro' | 'enterprise'
  features: string[]
}

const defaultFaviconDataURI =
  'data:image/svg+xml,' +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
    '<rect width="32" height="32" rx="4" fill="#3b82f6"/>' +
    '<text x="16" y="22" text-anchor="middle" font-family="sans-serif" font-size="20" font-weight="700" fill="white">V</text>' +
    '</svg>'
  )

export default function App() {
  const [loggedIn, setLoggedIn] = useState<boolean | null>(null)
  const [admin, setAdmin] = useState<AdminProfile | null>(null)
  const [branding, setBranding] = useState<BrandingResponse | null>(null)
  const location = useLocation()

  useEffect(() => {
    api.me()
      .then(profile => { setAdmin(profile); setLoggedIn(true) })
      .catch(() => setLoggedIn(false))
  }, [])

  // Branding is independent of /me — every authenticated load fetches it.
  // Free installs get the built-in defaults; the chrome renders them
  // identically to a Pro install with no overrides set.
  useEffect(() => {
    if (loggedIn !== true) return
    api.getBranding()
      .then(setBranding)
      .catch(() => { /* defaults render fine without it */ })
  }, [loggedIn])

  useEffect(() => {
    const eff = branding?.effective ?? { product_name: 'Vectis Mail', logo_url: '' }
    document.title = `${eff.product_name || 'Vectis Mail'} Admin`
    let link = document.querySelector("link[rel='icon']") as HTMLLinkElement | null
    if (!link) {
      link = document.createElement('link')
      link.rel = 'icon'
      document.head.appendChild(link)
    }
    if (eff.logo_url) {
      link.href = eff.logo_url
      link.removeAttribute('type')
    } else {
      link.href = defaultFaviconDataURI
      link.type = 'image/svg+xml'
    }
  }, [branding])

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
    { path: '/admin/branding', label: 'Branding', show: isSuperAdmin },
    { path: '/admin/sessions', label: 'Sessions', show: true },
  ]

  const brand = branding?.effective ?? { product_name: 'Vectis Mail', primary_color: '#3b82f6', logo_url: '' }

  return (
    <div className="app" style={{ ['--brand-primary' as string]: brand.primary_color } as React.CSSProperties}>
      <nav className="sidebar">
        <h1 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {brand.logo_url
            ? <img src={brand.logo_url} alt="" style={{ height: '24px', width: 'auto' }} />
            : null}
          <span>{brand.product_name}</span>
        </h1>
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
            tier={admin?.tier ?? 'free'}
            features={admin?.features ?? []}
            onLogout={() => api.logout().then(() => { setLoggedIn(false); setAdmin(null) })}
          />
        </header>
        <main className="main">
          <Routes>
            <Route path="/admin" element={<DashboardPage />} />
            <Route path="/admin/setup" element={<SetupWizardPage />} />
            <Route path="/admin/domains" element={<DomainsPage features={admin?.features ?? []} />} />
            <Route path="/admin/domains/:domainID/spam-lists" element={<SpamListsPage features={admin?.features ?? []} />} />
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
            {isSuperAdmin && <Route path="/admin/branding" element={<BrandingPage features={admin?.features ?? []} onBrandingChanged={setBranding} />} />}
            <Route path="/admin/sessions" element={<SessionsPage />} />
            {/* Customer billing portal — auto-redirects to Stripe via ValidonX. */}
            {/* super_admin only on the API; gated here to match. */}
            {isSuperAdmin && <Route path="/account/billing" element={<BillingPage />} />}
            <Route path="*" element={<Navigate to="/admin" />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

function AccountMenu({ email, role, tier, features, onLogout }: { email: string; role: string; tier: 'free' | 'pro' | 'enterprise'; features: string[]; onLogout: () => void }) {
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (!open) return
    const close = () => setOpen(false)
    document.addEventListener('click', close)
    return () => document.removeEventListener('click', close)
  }, [open])
  // Priority Support is gated by the priority_support feature flag on the
  // active license (Pro+ only). Free tier sees a community-support link
  // pointing to the public docs + GitHub Discussions instead — never a dead
  // end. Server is the source of truth: it sends the features array via
  // /auth/me, the UI just renders accordingly.
  const hasPrioritySupport = features.includes('priority_support')
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
            {tier && <div className="account-menu-tier">{tier.toUpperCase()} tier</div>}
          </div>
          {hasPrioritySupport ? (
            <a className="account-menu-item" role="menuitem" href="mailto:support@vectismail.com?subject=Vectis%20Pro%20support%20request" onClick={() => setOpen(false)}>
              Priority support →
            </a>
          ) : (
            <a className="account-menu-item" role="menuitem" href="https://vectismail.com/docs" target="_blank" rel="noopener noreferrer" onClick={() => setOpen(false)}>
              Community support →
            </a>
          )}
          <button className="account-menu-item" role="menuitem" onClick={() => { setOpen(false); onLogout() }}>
            Logout
          </button>
        </div>
      )}
    </div>
  )
}
