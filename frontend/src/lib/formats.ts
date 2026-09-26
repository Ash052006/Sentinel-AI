export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '—'
  return `${date.toISOString().replace('T', ' ').slice(0, 19)}Z`
}

const MONTHS = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
]

const pad2 = (value: number): string => String(value).padStart(2, '0')

/**
 * Full, never-truncated UTC timestamp for dense SOC tables, e.g.
 * `23 Oct 2027 04:00:52 UTC`. Rendered from the exact ISO-8601 string the
 * backend supplies (parsed as UTC) so seconds are always visible and the
 * reader can rely on a consistent " readable_at_utc" column.
 */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '—'
  const day = pad2(date.getUTCDate())
  const month = MONTHS[date.getUTCMonth()]
  const time = `${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}:${pad2(date.getUTCSeconds())}`
  return `${day} ${month} ${date.getUTCFullYear()} ${time} UTC`
}

/**
 * Compact timestamp without seconds for chart axes/grids.
 */
export function formatTimeShort(iso: string | null | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '—'
  return `${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}`
}

export function shortId(id: string | null | undefined): string {
  if (!id) return '—'
  return id.replace(/-/g, '').slice(0, 12)
}

export function shorten(text: string | null | undefined, max = 64): string {
  if (!text) return '—'
  if (text.length <= max) return text
  return `${text.slice(0, max)}…`
}

export function percent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—'
  const scaled = value * 100
  return `${scaled.toFixed(digits)}%`
}