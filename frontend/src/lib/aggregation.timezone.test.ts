import { afterAll, describe, expect, it, vi } from 'vitest'
import {
  BUCKET_MS,
  buildActivitySeries,
  buildDailyFallbackSeries,
} from './aggregation'

/**
 * Regression coverage for the Security Activity timezone bug.
 *
 * The backend transmits UTC instants (trailing `Z`). The chart must bucket and
 * label those instants in the browser's local timezone, never display the raw
 * UTC clock. These cases pin the process to Asia/Kolkata (UTC+05:30, the
 * operator's zone where the bug was observed) and assert the exact local
 * labels. Prior behaviour rendered `20:09 IST` as `14:39`.
 */
vi.stubEnv('TZ', 'Asia/Kolkata')
afterAll(() => {
  vi.unstubAllEnvs()
})

const parse = (iso: string) => new Date(iso).getTime()

describe('activity aggregation in Asia/Kolkata', () => {
  it('labels a 1H bucket in local time (20:09 IST is not 14:39 UTC)', () => {
    // Demo ran at 20:09:55 IST == 2026-11-07T14:39:55Z.
    const event = '2026-11-07T14:39:55Z'
    const now = parse('2026-11-07T14:45:00Z')
    const series = buildActivitySeries({ detections: [event] }, '1h', now)

    const bucket = series.find((item) => item.detections === 1)
    expect(bucket).toBeDefined()
    // 5-minute bucket [14:35Z, 14:40Z) == [20:05, 20:10) IST.
    expect(bucket!.key).toBe(parse('2026-11-07T14:35:00Z'))
    expect(bucket!.label).toBe('20:05')
  })

  it('aligns 2H buckets to local walls, not UTC walls', () => {
    const series = buildActivitySeries(
      {
        detections: ['2026-11-07T14:00:00Z', '2026-11-07T16:00:00Z'],
      },
      '24h',
      parse('2026-11-07T17:00:00Z'),
    )

    const populated = series.filter((item) => item.detections > 0)
    expect(populated.map((item) => item.label)).toEqual(['18:00', '20:00'])
    // 19:30 IST and 21:30 IST, respectively.
    expect(populated.map((item) => item.key)).toEqual([
      parse('2026-11-07T12:30:00Z'),
      parse('2026-11-07T14:30:00Z'),
    ])
  })

  it('uses local calendar days in the daily fallback', () => {
    const daily = buildDailyFallbackSeries({
      // 23:30 IST on 7 Nov and 00:30 IST on 8 Nov.
      detections: ['2026-11-07T18:00:00Z', '2026-11-07T19:00:00Z'],
    })

    expect(daily.map((item) => item.label)).toEqual(['7 Nov', '8 Nov'])
    expect(daily.map((item) => item.detections)).toEqual([1, 1])
  })

  it.each([
    ['1h', '20:05'],
    ['6h', '20:00'],
    ['24h', '20:00'],
    ['7d', '12:00'],
    ['30d', '7 Nov'],
  ] as const)('keeps %s buckets local and correctly spaced', (window, expectedLabel) => {
    const event = parse('2026-11-07T14:39:55Z')
    const series = buildActivitySeries(
      { detections: ['2026-11-07T14:39:55Z'] },
      window,
      parse('2026-11-07T15:00:00Z'),
    )

    const bucket = series.find((item) => item.detections === 1)
    expect(bucket).toBeDefined()
    expect(bucket!.label).toBe(expectedLabel)
    expect(bucket!.key).toBeLessThanOrEqual(event)
    expect(bucket!.key + BUCKET_MS[window]).toBeGreaterThan(event)
  })
})
