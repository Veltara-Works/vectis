const BASE = '/api/v1'

interface ApiResponse<T> {
  data?: T
  error?: { code: string; message: string; details?: unknown }
  meta: { request_id: string; timestamp: string }
}

export interface BrandingResponse {
  product_name: string
  primary_color: string
  logo_url: string
  from_db: boolean
  effective: {
    product_name: string
    primary_color: string
    logo_url: string
  }
}

// ApiError carries the structured error code + HTTP status alongside the
// message, so callers can branch on the code (e.g. BILLING_PORTAL_UNAVAILABLE)
// rather than string-matching the message. Extends Error, so existing
// `e instanceof Error` / `e.message` handling keeps working unchanged.
export class ApiError extends Error {
  code: string
  status: number
  constructor(code: string, message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.status = status
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const opts: RequestInit = {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
  }
  if (body) opts.body = JSON.stringify(body)

  const res = await fetch(`${BASE}${path}`, opts)
  const json: ApiResponse<T> = await res.json()

  if (json.error) throw new ApiError(json.error.code, json.error.message, res.status)
  return json.data as T
}

export const api = {
  // Auth
  login: (email: string, password: string, totp_session?: string, totp_code?: string) =>
    request<{ admin?: { id: string; email: string; role: string; totp_enabled: boolean }; session_id?: string; requires_totp?: boolean; totp_session?: string }>(
      'POST', '/auth/login',
      totp_session ? { totp_session, totp_code } : { email, password }
    ),
  me: () => request<{ id: string; email: string; role: string; totp_enabled: boolean; oidc_provider?: string; saml_provider?: string; tier: 'free' | 'pro' | 'enterprise'; features: string[] }>('GET', '/auth/me'),
  oidcProviders: () => request<{ providers: string[] }>('GET', '/auth/oidc/providers').then(r => r.providers),
  oidcDisconnect: () => request<{ message: string }>('DELETE', '/auth/oidc/disconnect'),
  // SAML 2.0 SSO (Enterprise — saml_sso feature). The providers endpoint
  // returns an empty list on installs not entitled to SAML, so the Login page
  // and the SSO settings page render no SAML affordances there. The SP
  // metadata is plain XML (not the JSON envelope), so it is fetched by direct
  // browser navigation to samlMetadataUrl rather than through request().
  // Disconnect is POST (mirrors the backend route; OIDC disconnect is DELETE).
  samlProviders: () => request<{ providers: string[] }>('GET', '/auth/saml/providers').then(r => r.providers),
  samlMetadataUrl: (provider: string) => `${BASE}/auth/saml/metadata/${encodeURIComponent(provider)}`,
  samlDisconnect: () => request<{ message: string }>('POST', '/auth/saml/disconnect'),

  // SCIM 2.0 provisioning tokens (Enterprise — scim feature; super_admin only).
  // The IdP (Okta/Entra) uses the Bearer token against /scim/v2. The raw token
  // is returned by create exactly once; list only ever returns hashes' metadata.
  // Create rotates: it revokes any prior active token (single active token per
  // install in Phase 1). All three endpoints 403 on non-Enterprise installs.
  listSCIMTokens: () =>
    request<Array<{
      id: string;
      token_prefix: string;
      active: boolean;
      expires_at?: string;
      last_used_at?: string;
      created_at: string;
    }>>('GET', '/scim-tokens'),
  createSCIMToken: (body: { expires_in_days?: number } = {}) =>
    request<{
      token: string;
      endpoint_url: string;
      scim_token: { id: string; token_prefix: string; active: boolean; expires_at?: string; created_at: string };
    }>('POST', '/scim-tokens', body),
  revokeSCIMToken: (id: string) =>
    request<{ message: string }>('DELETE', `/scim-tokens/${encodeURIComponent(id)}`),

  logout: () => request<void>('POST', '/auth/logout'),
  logoutAll: () => request<void>('POST', '/auth/logout-all'),
  sessions: () => request<Array<{ id: string; ip_address: string; user_agent: string; created_at: string }>>('GET', '/auth/sessions'),
  deleteSession: (id: string) => request<void>('DELETE', `/auth/sessions/${id}`),

  // TOTP MFA
  totpSetup: () => request<{ provisioning_uri: string }>('POST', '/auth/totp/setup'),
  totpVerify: (code: string) => request<{ message: string }>('POST', '/auth/totp/verify', { code }),
  totpDisable: (code: string) => request<{ message: string }>('DELETE', '/auth/totp', { code }),

  // Health
  health: () => request<{ status: string; services: Record<string, { status: string; response_ms: number }> }>('GET', '/health'),

  // Domains
  listDomains: () => request<Array<{
    id: string; name: string; active: boolean; dkim_enabled: boolean;
    dkim_selector: string; dkim_key_path?: string; spam_threshold: number;
    reject_threshold?: number; greylist_enabled?: boolean;
    max_mailboxes?: number; verification_status?: string; verification_token?: string; created_at: string
  }>>('GET', '/domains'),
  createDomain: (name: string, advanced?: { reject_threshold?: number | null; greylist_enabled?: boolean | null }) =>
    request<{ domain: { id: string; name: string }; dkim?: { dns_name: string; dns_value: string } }>('POST', '/domains', { name, ...(advanced || {}) }),
  updateDomain: (id: string, patch: { active?: boolean; spam_threshold?: number | null; reject_threshold?: number | null; greylist_enabled?: boolean | null }) =>
    request<{ id: string; name: string; spam_threshold: number; reject_threshold?: number; greylist_enabled?: boolean }>('PATCH', `/domains/${id}`, patch),
  deleteDomain: (id: string) => request<void>('DELETE', `/domains/${id}`),

  // Spam lists (Pro — advanced_spam feature)
  listSpamListEntries: (domainId: string, kind?: 'allow' | 'block') =>
    request<Array<{ id: string; domain_id: string; kind: 'allow' | 'block'; scope: 'email' | 'domain'; pattern: string; created_at: string }>>(
      'GET', `/domains/${domainId}/spam-lists${kind ? `?kind=${kind}` : ''}`
    ),
  createSpamListEntry: (domainId: string, kind: 'allow' | 'block', scope: 'email' | 'domain', pattern: string) =>
    request<{ entry: { id: string; domain_id: string; kind: 'allow' | 'block'; scope: 'email' | 'domain'; pattern: string; created_at: string } }>(
      'POST', `/domains/${domainId}/spam-lists`, { kind, scope, pattern }
    ),
  deleteSpamListEntry: (domainId: string, entryId: string) =>
    request<void>('DELETE', `/domains/${domainId}/spam-lists/${entryId}`),
  getDKIM: (id: string) =>
    request<{ dns_name: string; dns_value: string; selector: string }>('GET', `/domains/${id}/dkim`),
  generateDKIM: (id: string) =>
    request<{ dns_name: string; dns_value: string; selector: string }>('POST', `/domains/${id}/dkim/generate`),
  deliverability: (id: string) =>
    request<{ domain: string; checks: Array<{ name: string; status: string; value?: string; hint?: string }> }>('GET', `/domains/${id}/deliverability`),
  verifyDomain: (id: string) =>
    request<{ domain: string; verification_status: string; verification_token: string; txt_record_name: string; txt_record_value: string; found: boolean }>('POST', `/domains/${id}/verify`),

  // Mailboxes
  listMailboxes: (domainId: string) =>
    request<Array<{
      id: string; domain_id: string; local_part: string; display_name?: string;
      quota_mb: number; active: boolean; created_at: string
    }>>('GET', `/mailboxes?domain_id=${domainId}`),
  createMailbox: (domain_id: string, local_part: string, password: string, display_name?: string, quota_mb?: number) =>
    request<{ id: string }>('POST', '/mailboxes', { domain_id, local_part, password, display_name, quota_mb }),
  updateMailbox: (id: string, updates: { password?: string; display_name?: string; quota_mb?: number; active?: boolean }) =>
    request<{ id: string }>('PATCH', `/mailboxes/${id}`, updates),
  deleteMailbox: (id: string) =>
    request<void>('DELETE', `/mailboxes/${id}`, undefined),

  // Aliases
  listAliases: (domainId: string) =>
    request<Array<{
      id: string; domain_id: string; source_local_part: string;
      destination: string; active: boolean; created_at: string
    }>>('GET', `/aliases?domain_id=${domainId}`),
  createAlias: (domain_id: string, source_local_part: string, destination: string) =>
    request<{ id: string }>('POST', '/aliases', { domain_id, source_local_part, destination }),
  deleteAlias: (id: string) => request<void>('DELETE', `/aliases/${id}`),

  // Config
  applyConfig: () => request<{ message: string }>('POST', '/config/apply'),
  getConfig: () =>
    request<{
      config: { hostname: string; tls?: { provider?: string; email?: string } }
    }>('GET', '/config'),

  // Admins
  listAdmins: () =>
    request<Array<{
      id: string; email: string; role: string; totp_enabled: boolean;
      created_at: string; last_login_at?: string
    }>>('GET', '/admins'),
  createAdmin: (email: string, password: string, role?: string) =>
    request<{ id: string; email: string; role: string }>('POST', '/admins', { email, password, role }),
  updateAdmin: (id: string, patch: { email?: string; password?: string; role?: string; domain_ids?: string[]; totp_code?: string }) =>
    request<{ id: string; email: string; role: string; totp_enabled: boolean; created_at: string; last_login_at?: string }>('PATCH', `/admins/${id}`, patch),
  deleteAdmin: (id: string) => {
    return fetch(`${BASE}/admins/${id}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json', 'X-Confirm-Delete': 'true' },
      credentials: 'include',
    }).then(async res => {
      const json = await res.json()
      if (json.error) throw new Error(json.error.message)
      return json.data
    })
  },

  // Audit log
  listAudit: (params?: { action?: string; resource_type?: string; admin_id?: string; cursor?: string; limit?: number }) => {
    const q = new URLSearchParams()
    if (params?.action) q.set('action', params.action)
    if (params?.resource_type) q.set('resource_type', params.resource_type)
    if (params?.admin_id) q.set('admin_id', params.admin_id)
    if (params?.cursor) q.set('cursor', params.cursor)
    if (params?.limit) q.set('limit', String(params.limit))
    const qs = q.toString()
    return fetch(`${BASE}/audit${qs ? '?' + qs : ''}`, {
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
    }).then(async res => {
      const json = await res.json()
      if (json.error) throw new Error(json.error.message)
      return { data: json.data || [], meta: json.meta }
    })
  },

  // Orchestrator
  orchestratorStatus: () =>
    request<{
      state: string;
      current_operation?: string;
      last_operation?: string;
      current_step?: string;
      // Set during rc36+ orchestrator self-replace window — RFC3339 timestamp
      // of when the helper container is expected to have finished recreating
      // the orchestrator. UI renders a countdown banner while this is in the
      // future. Absent/past = no banner.
      self_upgrade_until?: string;
    }>('GET', '/orchestrator/status'),
  orchestratorPlan: () =>
    request<{
      id: string;
      created_at: string;
      config_hash: string;
      baseline_versions?: Record<string, string>;
      changes: Array<{
        service: string;
        type: string;
        old_image?: string;
        new_image?: string;
        detail?: string;
      }>;
      migrations_up: number;
      release_tag?: string;
      warnings?: string[];
    }>('POST', '/orchestrator/plan'),
  orchestratorApply: (force?: boolean) =>
    request<{ message: string; steps?: Array<{ service: string; status: string }> }>('POST', `/orchestrator/apply${force ? '?force=true' : ''}`),
  orchestratorRollback: () =>
    request<{ message: string }>('POST', '/orchestrator/rollback'),
  orchestratorHistory: () =>
    request<Array<{
      id: string; action: string; status: string; plan_summary?: string;
      error?: string; started_at: string; completed_at?: string; admin_id?: string
    }>>('GET', '/orchestrator/history'),

  // License (super_admin only). Customers paste their ValidonX subscription
  // details on the License page; setLicense validates against the live
  // ValidonX API and atomically swaps the running gate client (no api
  // restart required). When unconfigured, the install runs in Free tier.
  getLicense: () =>
    request<{
      configured: boolean;
      from_db: boolean;
      tier: 'free' | 'pro' | 'enterprise';
      status?: string;
      subscription_id_masked?: string;
      tenant_id?: string;
      server_id?: string;
      base_url?: string;
      last_check_at?: string;
      expires_at?: string;
      grace_remaining_days?: number;
      offline?: {
        configured: boolean;
        active: boolean;
        accepted: boolean;
        tier?: string;
        grace_state?: string;
        jwks_source?: string;
        reason?: string;
      };
    }>('GET', '/license'),
  setLicense: (body: {
    license_key?: string;
    subscription_id?: string;
    tenant_id?: string;
    service_key?: string;
    base_url?: string;
    server_id?: string;
  }) =>
    request<{
      configured: boolean;
      tier: 'free' | 'pro' | 'enterprise';
      status?: string;
      subscription_id_masked?: string;
    }>('POST', '/license', body),
  removeLicense: () =>
    request<{ configured: boolean; tier: string }>('DELETE', '/license'),

  // Customer billing portal (super_admin only). Mints a Stripe Customer
  // Portal session via ValidonX and returns the URL to navigate to. The
  // /account/billing page calls this, then window.location.assign(url) so
  // the customer never sees the ValidonX brand in their URL bar.
  // return_url is optional but recommended; it is validated server-side
  // to be same-host (open-redirect guard).
  createBillingPortalSession: (return_url?: string) =>
    request<{ url: string; expires_at?: string }>(
      'POST', '/account/billing-portal-session',
      return_url ? { return_url } : {}
    ),

  // In-product "Buy Pro" checkout (super_admin only). Mints a Stripe
  // Checkout session via ValidonX's Customer #1 partner-key endpoint so a
  // Free install can subscribe without leaving the admin UI. owner_email
  // and owner_name are optional — when omitted Stripe collects them. The
  // License page calls this and navigates to the returned url; after
  // payment Stripe redirects back to /admin/license?checkout=success.
  createUpgradeCheckoutSession: (body: { owner_email?: string; owner_name?: string }) =>
    request<{ url: string; session_id?: string; expires_at?: string }>(
      'POST', '/account/upgrade-checkout-session', body
    ),

  // Branding (Pro feature: custom_branding). GET is always callable;
  // PUT/DELETE require the Pro feature gate at the API layer (the page
  // hides the form when `tier !== 'pro' && tier !== 'enterprise'`).
  getBranding: () =>
    request<BrandingResponse>('GET', '/branding'),
  setBranding: (body: {
    product_name: string;
    primary_color: string;
    logo_url: string;
  }) =>
    request<BrandingResponse>('PUT', '/branding', body),
  removeBranding: () =>
    request<BrandingResponse>('DELETE', '/branding'),

  // Backups
  backupCreate: () =>
    request<{ job_id: string; message: string }>('POST', '/backup/create'),
  backupList: () =>
    request<Array<{ path: string; name: string; size: number; created_at: string }>>('GET', '/backup/list'),
  backupStatus: (jobId: string) =>
    request<{ id: string; status: string; error?: string; started_at: string; completed_at?: string }>('GET', `/backup/status/${jobId}`),
  backupRestore: (id: string) => {
    return fetch(`${BASE}/backup/restore/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Confirm-Restore': 'true' },
      credentials: 'include',
    }).then(async res => {
      const json = await res.json()
      if (json.error) throw new Error(json.error.message)
      return json.data
    })
  },
  backupGetSettings: () =>
    request<{ enabled: boolean; schedule: string; timezone: string; retain_days: number; from_db: boolean; next_run?: string }>('GET', '/backup/settings'),
  backupUpdateSettings: (s: { enabled: boolean; schedule: string; timezone: string; retain_days: number }) =>
    request<{ enabled: boolean; schedule: string; timezone: string; retain_days: number; from_db: boolean; next_run?: string }>('PUT', '/backup/settings', s),

  // Sieve filter management
  listSieveScripts: (mailboxId: string) =>
    request<Array<{ name: string; active: boolean }>>('GET', `/mailboxes/${mailboxId}/sieve`),
  getSieveScript: (mailboxId: string, name: string) =>
    request<{ name: string; content: string }>('GET', `/mailboxes/${mailboxId}/sieve/${name}`),
  putSieveScript: (mailboxId: string, name: string, content: string, active?: boolean) =>
    request<{ status: string; name: string }>('PUT', `/mailboxes/${mailboxId}/sieve`, { name, content, active }),
  deleteSieveScript: (mailboxId: string, name: string) =>
    request<void>('DELETE', `/mailboxes/${mailboxId}/sieve/${name}`),

  // Audit export
  auditExportUrl: (format: string, from?: string, to?: string) => {
    const q = new URLSearchParams({ format })
    if (from) q.set('from', from)
    if (to) q.set('to', to)
    return `${BASE}/audit/export?${q.toString()}`
  },

  // Log search
  searchLogs: (params: { service?: string; pattern?: string; query?: string; limit?: number }) => {
    const q = new URLSearchParams()
    if (params.service) q.set('service', params.service)
    if (params.pattern) q.set('pattern', params.pattern)
    if (params.query) q.set('query', params.query)
    if (params.limit) q.set('limit', String(params.limit))
    return request<unknown>('GET', `/logs/search?${q.toString()}`)
  },

  // Analytics
  analytics: (params?: { domain_id?: string; period?: string; granularity?: string }) => {
    const q = new URLSearchParams()
    if (params?.domain_id) q.set('domain_id', params.domain_id)
    if (params?.period) q.set('period', params.period)
    if (params?.granularity) q.set('granularity', params.granularity)
    return request<unknown>('GET', `/analytics?${q.toString()}`)
  },

  // Messages (metadata)
  listMessages: (params: {
    domain_id?: string; direction?: string; status?: string;
    search?: string; sender?: string; cursor?: string; limit?: number
  }) => {
    const q = new URLSearchParams()
    if (params.domain_id) q.set('domain_id', params.domain_id)
    if (params.direction) q.set('direction', params.direction)
    if (params.status) q.set('status', params.status)
    if (params.search) q.set('search', params.search)
    if (params.sender) q.set('sender', params.sender)
    if (params.cursor) q.set('cursor', params.cursor)
    if (params.limit) q.set('limit', String(params.limit))
    return fetch(`${BASE}/messages${q.toString() ? '?' + q : ''}`, {
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
    }).then(async res => {
      const json = await res.json()
      if (json.error) throw new Error(json.error.message)
      return { data: (json.data || []) as Array<{
        id: string; domain_id: string; mailbox_id?: string; message_id: string;
        direction: string; sender: string; recipients: string[]; subject?: string;
        size_bytes: number; status: string; spam_score?: number; spam_action?: string;
        queue_id?: string; created_at: string
      }>, meta: json.meta }
    })
  },
  getMessage: (id: string) =>
    request<{
      id: string; domain_id: string; mailbox_id?: string; message_id: string;
      direction: string; sender: string; recipients: string[]; subject?: string;
      size_bytes: number; status: string; spam_score?: number; spam_action?: string;
      queue_id?: string; headers?: Record<string, unknown>; created_at: string
    }>('GET', `/messages/${id}`),

  // Engagement tracking
  trackingStats: (domain_id: string, period: '1h' | '24h' | '7d' | '30d' = '24h') =>
    request<{
      domain_id: string; period: string; from: string; to: string;
      opens: number; clicks: number; messages_opened: number; messages_clicked: number
    }>('GET', `/tracking/stats?domain_id=${domain_id}&period=${period}`),
  messageEngagement: (messageID: string) =>
    request<{
      message_id: string; opens: number; unique_opens: number;
      clicks: number; unique_clicks: number;
      first_open_at?: string; last_open_at?: string;
      first_click_at?: string; last_click_at?: string
    }>('GET', `/tracking/messages/${encodeURIComponent(messageID)}`),
  messageEngagementEvents: (messageID: string) =>
    request<{
      message_id: string;
      events: Array<{
        id: string; domain_id: string; message_id: string; event_type: string;
        target_url?: string; user_agent?: string; ip_address?: string; created_at: string
      }>
    }>('GET', `/tracking/messages/${encodeURIComponent(messageID)}/events`),

  // Impersonation
  impersonate: (mailboxId: string) =>
    request<{ imap_host: string; imap_port: number; username: string; password: string; expires_at: string; expires_in_seconds: number }>(
      'POST', `/mailboxes/${mailboxId}/impersonate`
    ),
  revokeImpersonation: (mailboxId: string) =>
    request<{ status: string }>('DELETE', `/mailboxes/${mailboxId}/impersonate`),
}
