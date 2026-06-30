import { useState, useEffect } from 'react'
import { api } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'
import { formatSize } from '../lib/format.ts'
import DomainSelect from '../components/DomainSelect.tsx'

interface Domain { id: string; name: string }
interface MessageRow {
  id: string; domain_id: string; mailbox_id?: string; message_id: string;
  direction: string; sender: string; recipients: string[]; subject?: string;
  size_bytes: number; status: string; spam_score?: number; spam_action?: string;
  queue_id?: string; created_at: string
}
interface Engagement {
  message_id: string; opens: number; unique_opens: number;
  clicks: number; unique_clicks: number;
  first_open_at?: string; last_open_at?: string;
  first_click_at?: string; last_click_at?: string
}
interface EngagementEvent {
  id: string; domain_id: string; message_id: string; event_type: string;
  target_url?: string; user_agent?: string; ip_address?: string; created_at: string
}
interface DomainStats {
  domain_id: string; period: string; from: string; to: string;
  opens: number; clicks: number; messages_opened: number; messages_clicked: number
}

type Period = '1h' | '24h' | '7d' | '30d'

const STATUS_OPTIONS = ['', 'queued', 'sent', 'delivered', 'bounced', 'failed', 'spam']
const DIRECTION_OPTIONS = ['', 'outbound', 'inbound']

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'delivered':
    case 'sent':
      return 'badge badge-success'
    case 'bounced':
    case 'failed':
      return 'badge badge-danger'
    case 'spam':
    case 'queued':
      return 'badge badge-warning'
    default:
      return 'badge'
  }
}

export default function MessagesPage() {
  const [domains, setDomains] = useState<Domain[]>([])
  const [selectedDomain, setSelectedDomain] = useState('')
  const [direction, setDirection] = useState('outbound')
  const [status, setStatus] = useState('')
  const [search, setSearch] = useState('')
  const [messages, setMessages] = useState<MessageRow[]>([])
  const [engagement, setEngagement] = useState<Record<string, Engagement | null>>({})
  const [domainStats, setDomainStats] = useState<DomainStats | null>(null)
  const [statsPeriod, setStatsPeriod] = useState<Period>('24h')
  const [cursor, setCursor] = useState<string | undefined>(undefined)
  const [hasMore, setHasMore] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const [drawer, setDrawer] = useState<MessageRow | null>(null)
  const [drawerEvents, setDrawerEvents] = useState<EngagementEvent[]>([])
  const [drawerEngagement, setDrawerEngagement] = useState<Engagement | null>(null)
  const [drawerLoading, setDrawerLoading] = useState(false)

  useEffect(() => {
    api.listDomains().then(d => setDomains(d || [])).catch(() => setDomains([]))
  }, [])

  useEffect(() => {
    if (domains.length > 0 && !selectedDomain) setSelectedDomain(domains[0].id)
  }, [domains])

  const load = async (nextCursor?: string) => {
    if (!selectedDomain) return
    setLoading(true)
    setError('')
    try {
      const result = await api.listMessages({
        domain_id: selectedDomain,
        direction: direction || undefined,
        status: status || undefined,
        search: search || undefined,
        cursor: nextCursor,
        limit: 25,
      })
      const data = result.data
      if (nextCursor) setMessages(prev => [...prev, ...data])
      else setMessages(data)
      const pagination = result.meta?.pagination
      setCursor(pagination?.next_cursor || undefined)
      setHasMore(pagination?.has_more || false)
      // Lazy-fetch engagement for outbound rows.
      const outbound = data.filter(m => m.direction === 'outbound' && m.message_id)
      await Promise.all(outbound.map(async m => {
        try {
          const eng = await api.messageEngagement(m.message_id)
          setEngagement(prev => ({ ...prev, [m.message_id]: eng }))
        } catch {
          setEngagement(prev => ({ ...prev, [m.message_id]: null }))
        }
      }))
    } catch (e) {
      setError(extractError(e, 'Failed to load messages'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    setMessages([])
    setEngagement({})
    setCursor(undefined)
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedDomain, direction, status])

  useEffect(() => {
    if (!selectedDomain) { setDomainStats(null); return }
    api.trackingStats(selectedDomain, statsPeriod)
      .then(setDomainStats)
      .catch(() => setDomainStats(null))
  }, [selectedDomain, statsPeriod])

  const openDrawer = async (m: MessageRow) => {
    setDrawer(m)
    setDrawerEvents([])
    setDrawerEngagement(null)
    if (!m.message_id) return
    setDrawerLoading(true)
    try {
      const [eng, evs] = await Promise.all([
        api.messageEngagement(m.message_id).catch(() => null),
        api.messageEngagementEvents(m.message_id).catch(() => null),
      ])
      setDrawerEngagement(eng)
      setDrawerEvents(evs?.events || [])
    } finally {
      setDrawerLoading(false)
    }
  }

  const closeDrawer = () => {
    setDrawer(null)
    setDrawerEvents([])
    setDrawerEngagement(null)
  }

  const onSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setCursor(undefined)
    setMessages([])
    setEngagement({})
    load()
  }

  const openRate = domainStats?.messages_opened ?? 0

  return (
    <div>
      <h2 className="page-title">Messages</h2>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="card">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
          <div className="form-group" style={{ margin: 0 }}>
            <label>Domain</label>
            <DomainSelect value={selectedDomain} onChange={setSelectedDomain} domains={domains} emptyLabel="No domains" />
          </div>
          <div className="form-group" style={{ margin: 0 }}>
            <label>Direction</label>
            <select value={direction} onChange={e => setDirection(e.target.value)}>
              {DIRECTION_OPTIONS.map(d => <option key={d} value={d}>{d || 'all'}</option>)}
            </select>
          </div>
          <div className="form-group" style={{ margin: 0 }}>
            <label>Status</label>
            <select value={status} onChange={e => setStatus(e.target.value)}>
              {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s || 'all'}</option>)}
            </select>
          </div>
          <form onSubmit={onSearchSubmit} className="form-group" style={{ margin: 0 }}>
            <label>Search (subject/sender)</label>
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Press Enter to search"
            />
          </form>
        </div>
      </div>

      {domainStats && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Engagement — last {statsPeriod}</h3>
            <select value={statsPeriod} onChange={e => setStatsPeriod(e.target.value as Period)} style={{ width: 'auto' }}>
              <option value="1h">1h</option>
              <option value="24h">24h</option>
              <option value="7d">7d</option>
              <option value="30d">30d</option>
            </select>
          </div>
          <div className="stats" style={{ marginBottom: 0 }}>
            <div className="stat">
              <div className="stat-label">Opens</div>
              <div className="stat-value">{domainStats.opens}</div>
            </div>
            <div className="stat">
              <div className="stat-label">Clicks</div>
              <div className="stat-value">{domainStats.clicks}</div>
            </div>
            <div className="stat">
              <div className="stat-label">Messages Opened</div>
              <div className="stat-value">{openRate}</div>
            </div>
            <div className="stat">
              <div className="stat-label">Messages Clicked</div>
              <div className="stat-value">{domainStats.messages_clicked}</div>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Dir</th>
              <th>Sender</th>
              <th>Recipients</th>
              <th>Subject</th>
              <th>Status</th>
              <th style={{ textAlign: 'right' }}>Opens</th>
              <th style={{ textAlign: 'right' }}>Clicks</th>
            </tr>
          </thead>
          <tbody>
            {messages.map(m => {
              const eng = engagement[m.message_id]
              const isOutbound = m.direction === 'outbound'
              return (
                <tr key={m.id} onClick={() => openDrawer(m)} style={{ cursor: 'pointer' }}>
                  <td className="mono" style={{ whiteSpace: 'nowrap' }}>{new Date(m.created_at).toLocaleString()}</td>
                  <td className="text-muted">{m.direction}</td>
                  <td className="mono" style={{ maxWidth: '14rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {m.sender}
                  </td>
                  <td className="mono text-muted" style={{ maxWidth: '16rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {m.recipients.join(', ')}
                  </td>
                  <td style={{ maxWidth: '18rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {m.subject || <span className="text-muted">(no subject)</span>}
                  </td>
                  <td><span className={statusBadgeClass(m.status)}>{m.status}</span></td>
                  <td className="mono" style={{ textAlign: 'right' }}>
                    {isOutbound ? (eng ? eng.opens : <span className="text-muted">–</span>) : <span className="text-muted">–</span>}
                  </td>
                  <td className="mono" style={{ textAlign: 'right' }}>
                    {isOutbound ? (eng ? eng.clicks : <span className="text-muted">–</span>) : <span className="text-muted">–</span>}
                  </td>
                </tr>
              )
            })}
            {messages.length === 0 && !loading && (
              <tr><td colSpan={8} className="text-muted">No messages found</td></tr>
            )}
          </tbody>
        </table>

        {hasMore && (
          <div style={{ marginTop: '1rem', textAlign: 'center' }}>
            <button className="btn btn-sm" onClick={() => load(cursor)} disabled={loading}>
              {loading ? 'Loading...' : 'Load More'}
            </button>
          </div>
        )}
      </div>

      {drawer && (
        <>
          <div
            onClick={closeDrawer}
            style={{
              position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 40,
            }}
          />
          <aside
            style={{
              position: 'fixed', top: 0, right: 0, bottom: 0, width: 'min(540px, 100vw)',
              background: 'var(--bg-card)', borderLeft: '1px solid var(--border)',
              zIndex: 50, padding: '1.5rem', overflowY: 'auto',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Message details</h3>
              <button className="btn btn-sm" onClick={closeDrawer}>Close</button>
            </div>

            <dl style={{ display: 'grid', gridTemplateColumns: '8rem 1fr', gap: '0.4rem 1rem', fontSize: '0.85rem', marginBottom: '1.25rem' }}>
              <dt className="text-muted">Sent</dt>
              <dd>{new Date(drawer.created_at).toLocaleString()}</dd>
              <dt className="text-muted">Direction</dt>
              <dd>{drawer.direction}</dd>
              <dt className="text-muted">Status</dt>
              <dd><span className={statusBadgeClass(drawer.status)}>{drawer.status}</span></dd>
              <dt className="text-muted">From</dt>
              <dd className="mono" style={{ wordBreak: 'break-all' }}>{drawer.sender}</dd>
              <dt className="text-muted">To</dt>
              <dd className="mono" style={{ wordBreak: 'break-all' }}>{drawer.recipients.join(', ')}</dd>
              <dt className="text-muted">Subject</dt>
              <dd>{drawer.subject || <span className="text-muted">(no subject)</span>}</dd>
              <dt className="text-muted">Size</dt>
              <dd>{formatSize(drawer.size_bytes)}</dd>
              <dt className="text-muted">Message-ID</dt>
              <dd className="mono" style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>{drawer.message_id || '-'}</dd>
              {drawer.queue_id && <><dt className="text-muted">Queue ID</dt><dd className="mono">{drawer.queue_id}</dd></>}
              {drawer.spam_score != null && <>
                <dt className="text-muted">Spam score</dt>
                <dd>{drawer.spam_score.toFixed(2)} {drawer.spam_action ? `(${drawer.spam_action})` : ''}</dd>
              </>}
            </dl>

            <h4 style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '0.5rem' }}>Engagement</h4>
            {drawer.direction !== 'outbound' ? (
              <div className="text-muted" style={{ fontSize: '0.85rem' }}>Engagement tracking applies to outbound messages only.</div>
            ) : drawerLoading ? (
              <div className="text-muted" style={{ fontSize: '0.85rem' }}>Loading...</div>
            ) : (
              <>
                <div className="stats" style={{ marginBottom: '0.75rem' }}>
                  <div className="stat">
                    <div className="stat-label">Opens</div>
                    <div className="stat-value">{drawerEngagement?.opens ?? 0}</div>
                    <div className="text-muted" style={{ fontSize: '0.75rem' }}>
                      {drawerEngagement?.unique_opens ?? 0} unique
                    </div>
                  </div>
                  <div className="stat">
                    <div className="stat-label">Clicks</div>
                    <div className="stat-value">{drawerEngagement?.clicks ?? 0}</div>
                    <div className="text-muted" style={{ fontSize: '0.75rem' }}>
                      {drawerEngagement?.unique_clicks ?? 0} unique
                    </div>
                  </div>
                </div>

                <h4 style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                  Events ({drawerEvents.length})
                </h4>
                {drawerEvents.length === 0 ? (
                  <div className="text-muted" style={{ fontSize: '0.85rem' }}>No events recorded.</div>
                ) : (
                  <table>
                    <thead>
                      <tr>
                        <th>When</th>
                        <th>Type</th>
                        <th>Detail</th>
                      </tr>
                    </thead>
                    <tbody>
                      {drawerEvents.map(ev => (
                        <tr key={ev.id}>
                          <td className="mono" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                            {new Date(ev.created_at).toLocaleString()}
                          </td>
                          <td><span className="badge">{ev.event_type}</span></td>
                          <td className="mono text-muted" style={{ fontSize: '0.75rem', maxWidth: '16rem', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {ev.target_url || ev.ip_address || ev.user_agent || '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </>
            )}
          </aside>
        </>
      )}
    </div>
  )
}
