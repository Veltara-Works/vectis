import { useState, useEffect, useMemo } from 'react'
import { api } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'
import { formatSize } from '../lib/format.ts'

interface BackupInfo {
  path: string; name: string; size: number; created_at: string;
}

// dailyCron matches a simple "every day at HH:MM" schedule (minute hour * * *),
// which is what the friendly time picker produces and reads back. Anything
// more complex flips the form into advanced (raw cron) mode.
const dailyCron = /^(\d{1,2}) (\d{1,2}) \* \* \*$/

export default function BackupsPage() {
  const [backups, setBackups] = useState<BackupInfo[]>([])
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [creating, setCreating] = useState(false)
  const [jobId, setJobId] = useState<string | null>(null)
  const [jobStatus, setJobStatus] = useState<string | null>(null)
  const [restoring, setRestoring] = useState<string | null>(null)

  // Schedule & retention settings (DB-backed, hot-reloaded server-side on save).
  const [enabled, setEnabled] = useState(false)
  const [dailyTime, setDailyTime] = useState('02:00')
  const [timezone, setTimezone] = useState('UTC')
  const [retainDays, setRetainDays] = useState(30)
  const [advanced, setAdvanced] = useState(false)
  const [cron, setCron] = useState('0 2 * * *')
  const [nextRun, setNextRun] = useState<string | null>(null)
  const [savingSettings, setSavingSettings] = useState(false)

  const tzOptions = useMemo(() => {
    let list: string[]
    try { list = (Intl as unknown as { supportedValuesOf(k: string): string[] }).supportedValuesOf('timeZone') }
    catch { list = ['Australia/Sydney', 'Australia/Perth', 'Asia/Singapore', 'Asia/Tokyo', 'Europe/London', 'Europe/Berlin', 'America/New_York', 'America/Los_Angeles'] }
    const set = new Set<string>(['UTC', ...list])
    if (timezone) set.add(timezone)
    return Array.from(set)
  }, [timezone])

  const load = () => api.backupList().then(d => setBackups(d || [])).catch(() => setError('Failed to load backups'))

  const loadSettings = () => api.backupGetSettings().then(s => {
    setEnabled(s.enabled)
    setTimezone(s.timezone || 'UTC')
    setRetainDays(s.retain_days ?? 30) // 0 is valid ("keep all"); only fall back when absent
    setCron(s.schedule || '0 2 * * *')
    setNextRun(s.next_run || null)
    const m = dailyCron.exec(s.schedule || '')
    if (m) {
      setAdvanced(false)
      setDailyTime(`${m[2].padStart(2, '0')}:${m[1].padStart(2, '0')}`)
    } else if (s.schedule) {
      setAdvanced(true)
    }
  }).catch(() => setError('Failed to load backup settings — values shown are defaults; saving may create an override row'))

  useEffect(() => { load(); loadSettings() }, [])

  const handleSaveSettings = async () => {
    setSavingSettings(true); setError(''); setSuccess('')
    let schedule = cron.trim()
    if (!advanced) {
      const [hh, mm] = dailyTime.split(':')
      schedule = `${parseInt(mm, 10)} ${parseInt(hh, 10)} * * *`
    }
    try {
      const s = await api.backupUpdateSettings({ enabled, schedule, timezone, retain_days: retainDays })
      setNextRun(s.next_run || null)
      if (dailyCron.exec(s.schedule)) setCron(s.schedule)
      setSuccess('Backup settings saved')
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to save settings'))
    } finally {
      setSavingSettings(false)
    }
  }

  // Poll for job status when a backup is in progress.
  useEffect(() => {
    if (!jobId) return
    const interval = setInterval(async () => {
      try {
        const status = await api.backupStatus(jobId)
        setJobStatus(status.status)
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(interval)
          setCreating(false)
          if (status.status === 'completed') {
            setSuccess('Backup created successfully')
            load()
          } else {
            setError(status.error || 'Backup failed')
          }
          setJobId(null)
          setJobStatus(null)
        }
      } catch {
        // Status endpoint might not be available yet, keep polling.
      }
    }, 2000)
    return () => clearInterval(interval)
  }, [jobId])

  const handleCreate = async () => {
    setCreating(true)
    setError(''); setSuccess(''); setJobStatus(null)
    try {
      const result = await api.backupCreate()
      setJobId(result.job_id)
      setJobStatus('running')
      setSuccess('Backup job started...')
    } catch (err: unknown) {
      setCreating(false)
      setError(extractError(err, 'Failed to create backup'))
    }
  }

  const handleRestore = async (name: string) => {
    if (!confirm(`Restore from backup "${name}"? This is a destructive operation that will replace the current database.`)) return
    setRestoring(name)
    setError(''); setSuccess('')
    try {
      const result = await api.backupRestore(name)
      setSuccess(result.message || 'Restore job started')
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to start restore'))
    } finally {
      setRestoring(null)
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 className="page-title" style={{ margin: 0 }}>Backups</h2>
        <button className="btn" onClick={handleCreate} disabled={creating}>
          {creating ? 'Creating...' : 'Create Backup'}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <div className="card mb-2">
        <h3 className="mb-1">Schedule &amp; retention</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxWidth: '30rem' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
            Automatic backups enabled
          </label>

          {!advanced ? (
            <label>Run daily at:{' '}
              <input type="time" value={dailyTime} onChange={e => setDailyTime(e.target.value)} disabled={!enabled} />
            </label>
          ) : (
            <label>Cron schedule:{' '}
              <input type="text" className="mono" value={cron} placeholder="0 2 * * *"
                onChange={e => setCron(e.target.value)} disabled={!enabled} style={{ width: '12rem' }} />
            </label>
          )}

          <label>Timezone:{' '}
            <select value={timezone} onChange={e => setTimezone(e.target.value)} disabled={!enabled}>
              {tzOptions.map(tz => <option key={tz} value={tz}>{tz}</option>)}
            </select>
          </label>

          <label>Keep backups for:{' '}
            <input type="number" min={0} value={retainDays} style={{ width: '5rem' }} disabled={!enabled}
              onChange={e => setRetainDays(parseInt(e.target.value, 10) || 0)} /> days{' '}
            <span className="text-muted">(0 = keep all)</span>
          </label>

          {enabled && nextRun && (
            <p className="text-muted" style={{ margin: 0 }}>
              Next run: {new Date(nextRun).toLocaleString(undefined, { timeZone: timezone })} ({timezone})
            </p>
          )}

          <div>
            <button type="button" onClick={() => setAdvanced(a => !a)}
              style={{ background: 'none', border: 'none', color: 'var(--color-primary, #3b82f6)', cursor: 'pointer', padding: 0, font: 'inherit' }}>
              {advanced ? '▾ Simple (daily time)' : '▸ Advanced (custom cron)'}
            </button>
          </div>

          <div>
            <button className="btn" onClick={handleSaveSettings} disabled={savingSettings}>
              {savingSettings ? 'Saving...' : 'Save settings'}
            </button>
          </div>
        </div>
      </div>

      {jobStatus && (
        <div className="card">
          <h3 className="mb-1">Backup in Progress</h3>
          <p>Status: <span className="badge badge-warning">{jobStatus}</span></p>
        </div>
      )}

      <div className="card">
        <table>
          <thead>
            <tr><th>Name</th><th>Size</th><th>Created</th><th></th></tr>
          </thead>
          <tbody>
            {backups.map(b => (
              <tr key={b.name}>
                <td><strong className="mono">{b.name}</strong></td>
                <td className="mono">{formatSize(b.size)}</td>
                <td className="text-muted" style={{ whiteSpace: 'nowrap' }}>{new Date(b.created_at).toLocaleString()}</td>
                <td>
                  <button
                    className="btn btn-sm btn-danger"
                    onClick={() => handleRestore(b.name)}
                    disabled={restoring === b.name}
                  >
                    {restoring === b.name ? 'Restoring...' : 'Restore'}
                  </button>
                </td>
              </tr>
            ))}
            {backups.length === 0 && <tr><td colSpan={4} className="text-muted">No backups available</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
