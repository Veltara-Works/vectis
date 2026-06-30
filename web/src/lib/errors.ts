/**
 * extractError returns the message from an unknown thrown value when it is an
 * Error, otherwise the supplied fallback. Replaces the
 * `err instanceof Error ? err.message : '...'` idiom repeated across the app.
 */
export function extractError(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback
}
