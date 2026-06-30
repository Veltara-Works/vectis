/**
 * DomainSelect renders the domain dropdown shared by the Aliases, Mailboxes,
 * Deliverability, FilterRules, and Messages pages — the
 * `<select>{domains.map(d => <option>)}</select>` boilerplate that was
 * copy-pasted across them. onChange receives the selected domain id; pass
 * emptyLabel to show a placeholder option when the domain list is empty.
 */
interface DomainOption {
  id: string
  name: string
}

export default function DomainSelect({
  value,
  onChange,
  domains,
  emptyLabel,
}: {
  value: string
  onChange: (id: string) => void
  domains: DomainOption[]
  emptyLabel?: string
}) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)}>
      {domains.length === 0 && emptyLabel && <option value="">{emptyLabel}</option>}
      {domains.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
    </select>
  )
}
