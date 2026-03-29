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
  login: (email: string, password: string) =>
    request<{ admin: { id: string; email: string; role: string }; session_id: string }>('POST', '/auth/login', { email, password }),
  logout: () => request<void>('POST', '/auth/logout'),
  sessions: () => request<Array<{ id: string; ip_address: string; user_agent: string; created_at: string }>>('GET', '/auth/sessions'),

  // Health
  health: () => request<{ status: string; services: Record<string, { status: string; response_ms: number }> }>('GET', '/health'),

  // Domains
  listDomains: () => request<Array<{
    id: string; name: string; active: boolean; dkim_enabled: boolean;
    dkim_selector: string; dkim_key_path?: string; spam_threshold: number;
    max_mailboxes?: number; created_at: string
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

  // Admins
  listAdmins: () =>
    request<Array<{
      id: string; email: string; role: string; totp_enabled: boolean;
      created_at: string; last_login_at?: string
    }>>('GET', '/admins'),
  createAdmin: (email: string, password: string, role?: string) =>
    request<{ id: string; email: string; role: string }>('POST', '/admins', { email, password, role }),
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
}
