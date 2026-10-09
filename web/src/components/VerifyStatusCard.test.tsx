import { describe, it, expect } from 'vitest'
import { describeVerify } from './VerifyStatusCard'

const now = Date.parse('2026-10-09T12:00:00Z')

describe('describeVerify', () => {
  it('pass is green and names the version', () => {
    const d = describeVerify({ status: 'pass', version: 'v0.1.52', checked_at: '2026-10-09T06:00:00Z', stale: false }, now)
    expect(d.badge).toBe('badge-success')
    expect(d.detail).toContain('v0.1.52')
    expect(d.detail).toContain('6 h ago')
  })

  it('a stale pass warns that the timer may have stopped', () => {
    const d = describeVerify({ status: 'pass', version: 'v0.1.52', checked_at: '2026-10-06T06:00:00Z', stale: true }, now)
    expect(d.badge).toBe('badge-warning')
    expect(d.detail).toMatch(/timer may have stopped/)
  })

  it('fail is red, says since when, and lists the mismatches', () => {
    const d = describeVerify({
      status: 'fail', version: 'v0.1.52', checked_at: '2026-10-09T06:00:00Z',
      failing_since: '2026-10-08T12:00:00Z', failed_checks: ['image api', 'binary'], stale: false,
    }, now)
    expect(d.badge).toBe('badge-danger')
    expect(d.detail).toContain('failing since 24 h ago')
    expect(d.detail).toContain('image api, binary')
  })

  it('unverifiable is not presented as a tamper signal', () => {
    const d = describeVerify({ status: 'unverifiable', version: 'v0.1.52', checked_at: '2026-10-09T06:00:00Z', stale: false }, now)
    expect(d.badge).toBe('badge-muted')
    expect(d.detail).toContain('not a tamper signal')
  })

  it('never recorded points at the timer install command', () => {
    const d = describeVerify({ status: 'never', stale: false }, now)
    expect(d.detail).toContain('vectis verify install-timer')
  })
})
