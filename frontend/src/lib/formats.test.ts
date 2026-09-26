import { describe, expect, it } from 'vitest'
import { formatDateTime, formatTimestamp, formatTimeShort } from './formats'

describe('formats', () => {
  describe('formatDateTime', () => {
    it('renders a full, never-truncated UTC timestamp with seconds', () => {
      expect(formatDateTime('2027-10-23T04:00:52Z')).toBe('23 Oct 2027 04:00:52 UTC')
    })

    it('preserves sub-second precision inputs correctly', () => {
      expect(formatDateTime('2026-09-23T14:48:16.450454Z')).toBe('23 Sep 2026 14:48:16 UTC')
    })

    it('handles nullish and invalid input', () => {
      expect(formatDateTime(null)).toBe('—')
      expect(formatDateTime(undefined)).toBe('—')
      expect(formatDateTime('garbage')).toBe('—')
    })

    it('never truncates column timestamps', () => {
      const rendered = formatDateTime('2027-10-23T04:00:52Z')
      expect(rendered.length).toBeGreaterThanOrEqual(22)
      expect(rendered).not.toMatch(/^(2027|20271023|T04:)/)
      expect(rendered.endsWith('UTC')).toBe(true)
    })
  })

  it('formatTimeShort renders HH:MM in UTC', () => {
    expect(formatTimeShort('2026-01-01T09:30:00Z')).toBe('09:30')
    expect(formatTimeShort(null)).toBe('—')
  })

  it('keeps the legacy compact timestamp format unchanged', () => {
    expect(formatTimestamp('2027-10-23T04:00:52Z')).toBe('2027-10-23 04:00:52Z')
  })
})