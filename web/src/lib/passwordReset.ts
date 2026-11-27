// The page the password-reset email links to (internal/mail/notifications.go).
export const RESET_PATH = '/admin/reset-password'

// The same limits the server applies (auth.ValidatePasswordStrength), plus the
// confirmation match. Returns '' when the password is acceptable. Go's len()
// counts UTF-8 bytes, so count bytes here too (not UTF-16 units): "é" is 2.
export function passwordProblem(pw: string, confirm: string): string {
  const bytes = new TextEncoder().encode(pw).length
  if (bytes < 8) return 'Password must be at least 8 characters long'
  if (bytes > 128) return 'Password must be at most 128 characters long'
  if (pw !== confirm) return 'The two passwords do not match'
  return ''
}
