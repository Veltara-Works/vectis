import { useState, useEffect, FormEvent } from 'react'
import { api } from '../api/client.ts'
import { extractError } from '../lib/errors.ts'
import DomainSelect from '../components/DomainSelect.tsx'

interface Domain { id: string; name: string }
interface Mailbox { id: string; domain_id: string; local_part: string; display_name?: string }
interface SieveScript { name: string; active: boolean }

export default function FilterRulesPage() {
  const [domains, setDomains] = useState<Domain[]>([])
  const [selectedDomain, setSelectedDomain] = useState('')
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([])
  const [selectedMailbox, setSelectedMailbox] = useState('')
  const [scripts, setScripts] = useState<SieveScript[]>([])
  const [editingScript, setEditingScript] = useState<{ name: string; content: string } | null>(null)
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ name: 'default', content: '', active: true })
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => { api.listDomains().then(d => setDomains(d || [])) }, [])
  useEffect(() => {
    if (domains.length > 0 && !selectedDomain) setSelectedDomain(domains[0].id)
  }, [domains])
  useEffect(() => {
    if (selectedDomain) api.listMailboxes(selectedDomain).then(m => setMailboxes(m || [])).catch(() => setMailboxes([]))
  }, [selectedDomain])

  useEffect(() => {
    if (selectedMailbox) {
      api.listSieveScripts(selectedMailbox)
        .then(s => setScripts(s || []))
        .catch(() => setScripts([]))
    }
  }, [selectedMailbox])

  const domainName = domains.find(d => d.id === selectedDomain)?.name || ''
  const mailbox = mailboxes.find(m => m.id === selectedMailbox)

  const handleSave = async (e: FormEvent) => {
    e.preventDefault()
    setError(''); setSuccess('')
    try {
      await api.putSieveScript(selectedMailbox, form.name, form.content, form.active)
      setSuccess(`Script "${form.name}" saved`)
      setShowAdd(false)
      setEditingScript(null)
      api.listSieveScripts(selectedMailbox).then(s => setScripts(s || []))
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to save script'))
    }
  }

  const handleEdit = async (name: string) => {
    try {
      const script = await api.getSieveScript(selectedMailbox, name)
      setEditingScript(script)
      setForm({ name: script.name, content: script.content, active: true })
      setShowAdd(true)
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to load script'))
    }
  }

  const handleDelete = async (name: string) => {
    if (!confirm(`Delete filter script "${name}"?`)) return
    try {
      await api.deleteSieveScript(selectedMailbox, name)
      api.listSieveScripts(selectedMailbox).then(s => setScripts(s || []))
    } catch (err: unknown) {
      setError(extractError(err, 'Failed to delete script'))
    }
  }

  return (
    <div>
      <h2>Filter Rules (Sieve)</h2>
      <p className="muted">Manage email filter rules for mailboxes. Rules are processed by Dovecot via the ManageSieve protocol.</p>

      {error && <div className="alert alert-danger">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <div className="form-row" style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
        <div className="form-group" style={{ flex: 1 }}>
          <label>Domain</label>
          <DomainSelect value={selectedDomain} onChange={id => { setSelectedDomain(id); setSelectedMailbox('') }} domains={domains} />
        </div>
        <div className="form-group" style={{ flex: 1 }}>
          <label>Mailbox</label>
          <select value={selectedMailbox} onChange={e => setSelectedMailbox(e.target.value)}>
            <option value="">Select mailbox...</option>
            {mailboxes.map(m => <option key={m.id} value={m.id}>{m.local_part}@{domainName}</option>)}
          </select>
        </div>
      </div>

      {selectedMailbox && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3>Scripts for {mailbox?.local_part}@{domainName}</h3>
            <button className="btn" onClick={() => { setShowAdd(true); setEditingScript(null); setForm({ name: 'default', content: vacationTemplate(mailbox?.local_part || '', domainName), active: true }) }}>
              Add Script
            </button>
          </div>

          {scripts.length === 0 && !showAdd && <p className="muted">No filter scripts configured.</p>}

          {scripts.map(s => (
            <div key={s.name} className="card" style={{ marginBottom: '0.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <strong>{s.name}</strong>
                {s.active && <span className="badge badge-success" style={{ marginLeft: '0.5rem' }}>Active</span>}
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn btn-sm" onClick={() => handleEdit(s.name)}>Edit</button>
                <button className="btn btn-sm btn-danger" onClick={() => handleDelete(s.name)}>Delete</button>
              </div>
            </div>
          ))}

          {showAdd && (
            <form onSubmit={handleSave} className="card" style={{ marginTop: '1rem' }}>
              <h4>{editingScript ? 'Edit Script' : 'New Filter Script'}</h4>
              <div className="form-group">
                <label>Script Name</label>
                <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                  disabled={!!editingScript} placeholder="default" />
              </div>
              <div className="form-group">
                <label>Sieve Script</label>
                <textarea value={form.content} onChange={e => setForm({ ...form, content: e.target.value })}
                  rows={12} style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                  placeholder='require "vacation";&#10;vacation "I am on vacation";' />
              </div>
              <div className="form-group">
                <label>
                  <input type="checkbox" checked={form.active} onChange={e => setForm({ ...form, active: e.target.checked })} />
                  {' '}Activate this script
                </label>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button type="submit" className="btn">Save</button>
                <button type="button" className="btn" onClick={() => { setShowAdd(false); setEditingScript(null) }}>Cancel</button>
              </div>
            </form>
          )}
        </>
      )}
    </div>
  )
}

function vacationTemplate(localPart: string, domain: string): string {
  return `require ["vacation", "fileinto"];

# Vacation auto-reply
vacation :days 7 :subject "Out of Office"
  "${localPart}@${domain} is currently out of the office.
I will respond to your email when I return.";

# File spam to Junk folder
if header :contains "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
`
}
