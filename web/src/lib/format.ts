/**
 * formatSize renders a byte count as a human-readable B/KB/MB/GB string.
 * Shared by the Backups and Messages pages, which previously carried slightly
 * divergent copies (this is the four-tier Backups version).
 */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB'
}
