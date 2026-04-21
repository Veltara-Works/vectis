const BASE = '/api/v1'

interface ApiResponse<T> {
  data?: T
  error?: { code: string; message: string; details?: unknown }
  meta: { request_id: string; timestamp: string }
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

  if (json.error) throw new Error(json.error.message)
  return json.data as T
}

export const api = {
  // Auth
  login: (email: string, password: string, totp_session?: string, totp_code?: string) =>
    request<{ admin?: { id: string; email: string; role: string; totp_enabled: boolean }; session_id?: string; requires_totp?: boolean; totp_session?: string }>(
      'POST', '/auth/login',
      totp_session ? { totp_session, totp_code } : { email, password }
    ),
  me: () => request<{ id: string; email: string; role: string; totp_enabled: boolean; oidc_provider?: string }>('GET', '/auth/me'),
  oidcProviders: () => request<{ providers: string[] }>('GET', '/auth/oidc/providers').then(r => r.providers),
  oidcDisconnect: () => request<{ message: string }>('DELETE', '/auth/oidc/disconnect'),
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
    max_mailboxes?: number; verification_status?: string; verification_token?: string; created_at: string
  }>>('GET', '/domains'),
  createDomain: (name: string) =>
    request<{ domain: { id: string; name: string }; dkim?: { dns_name: string; dns_value: string } }>('POST', '/domains', { name }),
  deleteDomain: (id: string) => request<void>('DELETE', `/domains/${id}`),
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
    request<{ state: string; current_operation?: string; last_operation?: string }>('GET', '/orchestrator/status'),
  orchestratorPlan: () =>
    request<{ plan: string; changes: Array<{ service: string; action: string; detail?: string }> }>('POST', '/orchestrator/plan'),
  orchestratorApply: (force?: boolean) =>
    request<{ message: string; steps?: Array<{ service: string; status: string }> }>('POST', `/orchestrator/apply${force ? '?force=true' : ''}`),
  orchestratorRollback: () =>
    request<{ message: string }>('POST', '/orchestrator/rollback'),
  orchestratorHistory: () =>
    request<Array<{
      id: string; action: string; status: string; plan_summary?: string;
      error?: string; started_at: string; completed_at?: string; admin_id?: string
    }>>('GET', '/orchestrator/history'),

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
