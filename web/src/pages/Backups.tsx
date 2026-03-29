import { useState, useEffect } from 'react'
import { api } from '../api/client.ts'

interface BackupInfo {
  path: string; name: string; size: number; created_at: string;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
}

export default function BackupsPage() {
  const [backups, setBackups] = useState<BackupInfo[]>([])
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [creating, setCreating] = useState(false)
  const [jobId, setJobId] = useState<string | null>(null)
  const [jobStatus, setJobStatus] = useState<string | null>(null)
  const [restoring, setRestoring] = useState<string | null>(null)

  const load = () => api.backupList().then(d => setBackups(d || [])).catch(() => setError('Failed to load backups'))
  useEffect(() => { load() }, [])

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
      setError(err instanceof Error ? err.message : 'Failed to create backup')
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
      setError(err instanceof Error ? err.message : 'Failed to start restore')
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
