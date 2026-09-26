import { describe, expect, it } from 'vitest'
import {
  BUCKET_MS,
  buildActivitySeries,
  buildDailyFallbackSeries,
  hasSufficientSeries,
  nonEmptyBuckets,
  seriesTotals,
  toTimestamp,
} from './aggregation'

const parse = (iso: string) => new Date(iso).getTime()

describe('aggregation', () => {
  it('parses ISO-8601 strings and rejects garbage', () => {
    expect(toTimestamp('2026-09-01T09:00:00Z')).toBe(parse('2026-09-01T09:00:00Z'))
    expect(toTimestamp('not-a-date')).toBeNull()
    expect(toTimestamp(null)).toBeNull()
    expect(toTimestamp(undefined)).toBeNull()
    expect(toTimestamp(1234)).toBe(1234)
  })

  it('buckets timestamps by real time and returns buckets in chronological order', () => {
    const series = buildActivitySeries(
      {
        detections: [
          '2026-01-01T08:00:00Z',
          '2026-01-01T08:30:00Z',
          '2026-01-01T12:15:00Z',
        ],
      },
      '24h',
      parse('2026-01-02T00:00:00Z'),
    )

    const keys = series.map((b) => b.key)
    expect(keys).toEqual([...keys].sort((a, b) => a - b))

    const at8 = series.find((b) => b.label === '08:00')
    // 08:00 and 08:30 share one 2-hour UTC-aligned bucket.
    expect(at8?.detections).toBe(2)

    const at12 = series.find((b) => b.label === '12:00')
    expect(at12?.detections).toBe(1)
  })

  it('includes empty buckets so distant spikes are not connected into a slope', () => {
    const series = buildActivitySeries(
      { detections: ['2026-01-01T09:00:00Z'] },
      '24h',
      parse('2026-01-02T00:00:00Z'),
    )
    const zero = series.filter((b) => b.detections === 0)
    expect(zero.length).toBeGreaterThan(0)
  })

  it('excludes timestamps outside the trailing window', () => {
    const series = buildActivitySeries(
      {
        detections: [
          '2025-12-30T23:00:00Z', // before cutoff
          '2026-01-01T09:00:00Z', // inside window
          '2026-01-01T13:00:00Z', // after anchor "now"
        ],
      },
      '24h',
      parse('2026-01-01T12:00:00Z'),
    )
    const total = series.reduce((n, b) => n + b.detections, 0)
    expect(total).toBe(1)
  })

  it('reports sufficient data only when at least two non-empty buckets exist', () => {
    const single = buildActivitySeries(
      { detections: ['2026-01-01T09:00:00Z'] },
      '24h',
      parse('2026-01-02T00:00:00Z'),
    )
    expect(nonEmptyBuckets(single)).toBe(1)
    expect(hasSufficientSeries(single)).toBe(false)

    const multi = buildActivitySeries(
      { detections: ['2026-01-01T09:00:00Z', '2026-12-31T09:00:00Z'] },
      '30d',
      parse('2026-12-31T23:00:00Z'),
    )
    // second timestamp is inside the 30d window (bucket ~30 Dec), first is far outside.
    expect(hasSufficientSeries(multi)).toBe(false)
  })

  it('builds chronological daily fallback buckets with real gaps preserved', () => {
    const daily = buildDailyFallbackSeries({
      detections: ['2026-09-01T01:00:00Z', '2026-09-01T05:00:00Z', '2026-09-03T00:00:00Z'],
      correlations: ['2026-09-02T10:00:00Z'],
    })

    expect(daily.map((b) => b.label)).toEqual(['1 Sep', '2 Sep', '3 Sep'])
    const totals = seriesTotals(daily)
    expect(totals.detections).toBe(3)
    expect(totals.correlations).toBe(1)
    expect(daily[0]!.detections).toBe(2)
    expect(daily[1]!.correlations).toBe(1)
    expect(daily[2]!.detections).toBe(1)
  })

  it('returns an empty fallback when there is nothing to plot', () => {
    expect(buildDailyFallbackSeries({})).toEqual([])
  })

  it('exposes human bucket spans per window', () => {
    expect(BUCKET_MS['1h']).toBe(300_000)
    expect(BUCKET_MS['30d']).toBe(172_800_000)
  })
})