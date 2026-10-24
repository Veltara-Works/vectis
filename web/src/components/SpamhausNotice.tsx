// SpamhausNotice tells the operator whether Spamhaus is queried through their
// own DQS key (#260). Without one, spam filtering and the blocklist check use
// Spamhaus's public servers, which Spamhaus allows only for non-commercial use.
// Keep the wording in step with config.SpamhausDQSKeyNotice (Go).
export default function SpamhausNotice({ configured }: { configured: boolean }) {
  if (configured) {
    return (
      <p className="text-muted" style={{ fontSize: '0.85rem', marginTop: 0 }}>
        Spamhaus is queried through your own DQS key.
      </p>
    )
  }
  return (
    <div className="alert alert-warning" role="note">
      <strong>Using Spamhaus's public servers.</strong> Spam filtering and this check query
      Spamhaus without a key, which Spamhaus allows only for non-commercial use at modest
      volumes. If you run this server for a business, register your own{' '}
      <a href="https://www.spamhaus.com/data-access/free-data-query-service/" target="_blank" rel="noopener noreferrer">
        Spamhaus DQS key
      </a>{' '}
      (free or paid, depending on your eligibility with Spamhaus) and set{' '}
      <code>rspamd.spamhaus_dqs_key</code> in <code>/etc/vectis/secrets.yaml</code>.
    </div>
  )
}
