// The page the password-reset email links to (internal/mail/notifications.go).
export const RESET_PATH = '/admin/reset-password'

// The same limits the server applies (auth.ValidatePasswordStrength), plus the
// confirmation match. Returns '' when the password is acceptable.
export function passwordProblem(pw: string, confirm: string): string {
  if (pw.length < 8) return 'Password must be at least 8 characters long'
  if (pw.length > 128) return 'Password must be at most 128 characters long'
  if (pw !== confirm) return 'The two passwords do not match'
  return ''
}
