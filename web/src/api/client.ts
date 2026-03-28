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
  health: () => request<{ status: string; services: Record<string, string> }>('GET', '/health'),

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
}
