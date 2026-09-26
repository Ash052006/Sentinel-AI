/**
 * Honest time-bucketing helpers for the SOC dashboard.
 *
 * Rules:
 * - Never treat list position as a time axis. Every series is grouped by the
 *   real `timestamp` the backend supplies.
 * - Bounded feeds are labelled as bounded; these helpers never invent totals.
 * - If a window leaves fewer than two distinct non-empty buckets, callers
 *   should show an "insufficient historical data" state rather than a
 *   misleading line.
 */

export type TimeWindow = '1h' | '6h' | '24h' | '7d' | '30d'

export const TIME_WINDOWS: TimeWindow[] = ['1h', '6h', '24h', '7d', '30d']

export const WINDOW_LABEL: Record<TimeWindow, string> = {
  '1h': '1H',
  '6h': '6H',
  '24h': '24H',
  '7d': '7D',
  '30d': '30D',
}

export const WINDOW_MS: Record<TimeWindow, number> = {
  '1h': 3_600_000,
  '6h': 21_600_000,
  '24h': 86_400_000,
  '7d': 604_800_000,
  '30d': 2_592_000_000,
}

export const BUCKET_MS: Record<TimeWindow, number> = {
  '1h': 300_000,
  '6h': 1_800_000,
  '24h': 7_200_000,
  '7d': 43_200_000,
  '30d': 172_800_000,
}

export interface SeriesInput {
  detections?: Array<string | number | null | undefined>
  correlations?: Array<string | number | null | undefined>
  risk?: Array<string | number | null | undefined>
}

const MONTHS = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
]

const pad2 = (value: number): string => String(value).padStart(2, '0')

const DAY_MS = 86_400_000

export function toTimestamp(value: string | number | null | undefined): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null
  if (typeof value !== 'string' || value.length === 0) return null
  const ms = Date.parse(value)
  return Number.isNaN(ms) ? null : ms
}

export interface ActivityBucket {
  key: number
  label: string
  detections: number
  correlations: number
  risk: number
}

function bucketLabel(ms: number, spanMs: number): string {
  const date = new Date(ms)
  if (spanMs >= DAY_MS) return `${date.getUTCDate()} ${MONTHS[date.getUTCMonth()]}`
  return `${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}`
}

function parseSeries(values: SeriesInput['detections']): number[] {
  const out: number[] = []
  if (!values) return out
  for (const value of values) {
    const ts = toTimestamp(value)
    if (ts !== null) out.push(ts)
  }
  return out
}

/**
 * Buckets the supplied timestamps into chronologically-ordered buckets within
 * the trailing window `[now - WINDOW_MS, now]`. Empty buckets are included so
 * the x-axis reflects real gaps instead of a connected slope between distant
 * spikes.
 */
export function buildActivitySeries(
  input: SeriesInput,
  window: TimeWindow,
  now: number = Date.now(),
): ActivityBucket[] {
  const span = BUCKET_MS[window]
  const cutoff = now - WINDOW_MS[window]

  const counts = new Map<number, ActivityBucket>()

  const bump = (ts: number, field: 'detections' | 'correlations' | 'risk') => {
    if (ts < cutoff || ts > now) return
    const key = Math.floor(ts / span) * span
    const bucket = counts.get(key) ?? {
      key,
      label: bucketLabel(key, span),
      detections: 0,
      correlations: 0,
      risk: 0,
    }
    bucket[field] += 1
    counts.set(key, bucket)
  }

  for (const ts of parseSeries(input.detections)) bump(ts, 'detections')
  for (const ts of parseSeries(input.correlations)) bump(ts, 'correlations')
  for (const ts of parseSeries(input.risk)) bump(ts, 'risk')

  const buckets: ActivityBucket[] = []
  for (let key = Math.floor(cutoff / span) * span; key <= now; key += span) {
    buckets.push(
      counts.get(key) ?? {
        key,
        label: bucketLabel(key, span),
        detections: 0,
        correlations: 0,
        risk: 0,
      },
    )
  }
  return buckets
}

export function nonEmptyBuckets(series: ActivityBucket[]): number {
  return series.filter((bucket) => bucket.detections + bucket.correlations + bucket.risk > 0).length
}

/**
 * A series needs at least two distinct non-empty time buckets to be a real
 * chronological series. A single spike is better reported honestly than drawn.
 */
export function hasSufficientSeries(series: ActivityBucket[]): boolean {
  return nonEmptyBuckets(series) >= 2
}

export interface DailyBucket {
  key: number
  label: string
  detections: number
  correlations: number
  risk: number
}

/**
 * Fallback view used when a trailing window has insufficient diversity:
 * groups every loaded timestamp by UTC day across the full observed sample,
 * sorted chronologically. Always derived from the same real timestamps.
 */
export function buildDailyFallbackSeries(input: SeriesInput): DailyBucket[] {
  const detections = parseSeries(input.detections)
  const correlations = parseSeries(input.correlations)
  const risk = parseSeries(input.risk)
  const all = [...detections, ...correlations, ...risk]
  if (all.length === 0) return []

  const min = Math.min(...all)
  const max = Math.max(...all)

  const counts = new Map<number, DailyBucket>()
  const bump = (ts: number, field: 'detections' | 'correlations' | 'risk') => {
    const key = Math.floor(ts / DAY_MS) * DAY_MS
    const bucket = counts.get(key) ?? {
      key,
      label: `${new Date(key).getUTCDate()} ${MONTHS[new Date(key).getUTCMonth()]}`,
      detections: 0,
      correlations: 0,
      risk: 0,
    }
    bucket[field] += 1
    counts.set(key, bucket)
  }

  for (const ts of detections) bump(ts, 'detections')
  for (const ts of correlations) bump(ts, 'correlations')
  for (const ts of risk) bump(ts, 'risk')

  const buckets: DailyBucket[] = []
  for (let key = Math.floor(min / DAY_MS) * DAY_MS; key <= max; key += DAY_MS) {
    buckets.push(
      counts.get(key) ?? {
        key,
        label: `${new Date(key).getUTCDate()} ${MONTHS[new Date(key).getUTCMonth()]}`,
        detections: 0,
        correlations: 0,
        risk: 0,
      },
    )
  }
  return buckets
}

export function seriesTotals(series: ActivityBucket[] | DailyBucket[]): {
  detections: number
  correlations: number
  risk: number
} {
  return series.reduce(
    (acc, bucket) => ({
      detections: acc.detections + bucket.detections,
      correlations: acc.correlations + bucket.correlations,
      risk: acc.risk + bucket.risk,
    }),
    { detections: 0, correlations: 0, risk: 0 },
  )
}