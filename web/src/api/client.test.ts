import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from './client'

const mockResponse = (data: unknown, ok = true) =>
  Promise.resolve({
    ok,
    json: () =>
      Promise.resolve(
        ok
          ? { data, meta: { request_id: 'test', timestamp: new Date().toISOString() } }
          : { error: { code: 'ERR', message: 'fail' }, meta: { request_id: 'test', timestamp: new Date().toISOString() } }
      ),
  } as Response)

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('api client', () => {
  it('sends login request with credentials', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockReturnValue(
      mockResponse({ admin: { id: '1', email: 'a@b.com', role: 'super_admin', totp_enabled: false } })
    )

    const result = await api.login('a@b.com', 'pass')
    expect(spy).toHaveBeenCalledWith(
      '/api/v1/auth/login',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify({ email: 'a@b.com', password: 'pass' }),
      })
    )
    expect(result.admin?.email).toBe('a@b.com')
  })

  it('sends TOTP login when totp_session provided', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockReturnValue(
      mockResponse({ admin: { id: '1', email: 'a@b.com', role: 'admin', totp_enabled: true } })
    )

    await api.login('', '', 'sess123', '654321')
    expect(spy).toHaveBeenCalledWith(
      '/api/v1/auth/login',
      expect.objectContaining({
        body: JSON.stringify({ totp_session: 'sess123', totp_code: '654321' }),
      })
    )
  })

  it('throws on API error response', async () => {
    vi.spyOn(globalThis, 'fetch').mockReturnValue(
      Promise.resolve({
        json: () =>
          Promise.resolve({
            error: { code: 'AUTH_REQUIRED', message: 'Authentication required' },
            meta: { request_id: 'test', timestamp: new Date().toISOString() },
          }),
      } as Response)
    )

    await expect(api.me()).rejects.toThrow('Authentication required')
  })

  it('fetches health status', async () => {
    const healthData = { status: 'healthy', services: { postfix: { status: 'healthy', response_ms: 5 } } }
    vi.spyOn(globalThis, 'fetch').mockReturnValue(mockResponse(healthData))

    const result = await api.health()
    expect(result.status).toBe('healthy')
    expect(result.services.postfix.status).toBe('healthy')
  })

  it('lists domains', async () => {
    const domains = [{ id: '1', name: 'example.com', active: true }]
    vi.spyOn(globalThis, 'fetch').mockReturnValue(mockResponse(domains))

    const result = await api.listDomains()
    expect(result).toHaveLength(1)
    expect(result[0].name).toBe('example.com')
  })

  it('creates a domain', async () => {
    const domain = { domain: { id: '1', name: 'new.com' }, dkim: { dns_name: 'sel._domainkey', dns_value: 'v=DKIM1' } }
    vi.spyOn(globalThis, 'fetch').mockReturnValue(mockResponse(domain))

    const result = await api.createDomain('new.com')
    expect(result.domain.name).toBe('new.com')
  })

  it('creates a mailbox', async () => {
    vi.spyOn(globalThis, 'fetch').mockReturnValue(mockResponse({ id: 'mb-1' }))

    const result = await api.createMailbox('d1', 'user', 'pass123')
    expect(result.id).toBe('mb-1')
  })

  it('calls logout', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockReturnValue(mockResponse(undefined))

    await api.logout()
    expect(spy).toHaveBeenCalledWith(
      '/api/v1/auth/logout',
      expect.objectContaining({ method: 'POST' })
    )
  })

  it('lists SAML providers', async () => {
    vi.spyOn(globalThis, 'fetch').mockReturnValue(mockResponse({ providers: ['okta', 'entra'] }))

    const result = await api.samlProviders()
    expect(result).toEqual(['okta', 'entra'])
  })

  it('builds the SAML SP metadata URL with encoding', () => {
    expect(api.samlMetadataUrl('okta')).toBe('/api/v1/auth/saml/metadata/okta')
    expect(api.samlMetadataUrl('my idp')).toBe('/api/v1/auth/saml/metadata/my%20idp')
  })

  it('disconnects SAML via POST', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockReturnValue(mockResponse({ message: 'SAML provider disconnected' }))

    const result = await api.samlDisconnect()
    expect(spy).toHaveBeenCalledWith(
      '/api/v1/auth/saml/disconnect',
      expect.objectContaining({ method: 'POST', credentials: 'include' })
    )
    expect(result.message).toBe('SAML provider disconnected')
  })

  it('includes credentials on all requests', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockReturnValue(mockResponse([]))

    await api.listDomains()
    expect(spy).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ credentials: 'include' })
    )
  })
})
