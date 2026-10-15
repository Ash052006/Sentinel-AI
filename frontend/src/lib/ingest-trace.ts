import type { IngestEventTrace } from '../api/ingest'
import { formatTimestamp } from './formats'

/**
 * Derives a raw -> normalized summary from an ingestion trace.
 *
 * Every row is a claim the console can *establish* from the backend
 * response alone. Nothing is inferred from outside knowledge of the
 * NormalizationAgent, and a field the response does not carry is reported
 * as absent rather than assumed.
 */

export type TraceFieldStatus =
  /** Same value in the raw record and in the normalized event. */
  | 'preserved'
  /** Present in both halves but carrying a different value. */
  | 'mapped'
  /** Produced by the agent; the raw record carries no such field. */
  | 'derived'
  /** Not available from the response. */
  | 'absent'

export interface TraceSummaryRow {
  field: string
  value: string
  status: TraceFieldStatus
  note: string
}

export const TRACE_STATUS_LABEL: Record<TraceFieldStatus, string> = {
  preserved: 'preserved',
  mapped: 'mapped',
  derived: 'derived',
  absent: 'not available',
}

const DISPLAY = '—'

function display(value: unknown): string {
  if (value === null || value === undefined) return DISPLAY
  if (typeof value === 'string') return value.length ? value : DISPLAY
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

/**
 * Timestamps are compared as instants, not strings: the backend re-emits the
 * same moment as UTC (`...+00:00` in, `...Z` out), so a string comparison
 * would report a false mismatch.
 */
function sameInstant(raw: unknown, value: unknown): boolean {
  if (typeof raw !== 'string' || typeof value !== 'string') return false
  const left = Date.parse(raw)
  const right = Date.parse(value)
  return Number.isFinite(left) && Number.isFinite(right) && left === right
}

function compare(
  raw: Record<string, unknown>,
  key: string,
  value: unknown,
  note: string,
  render: (value: unknown) => string = display,
): TraceSummaryRow {
  const original = raw[key]
  const shown = render(value)

  if (original === undefined) {
    return { field: key, value: shown, status: 'derived', note }
  }

  const preserved =
    typeof value === 'string' && value.length > 0
      ? String(original) === value || sameInstant(original, value)
      : original === null || original === undefined

  return {
    field: key,
    value: shown,
    status: preserved ? 'preserved' : 'mapped',
    note,
  }
}

export function summarizeTrace(trace: IngestEventTrace): TraceSummaryRow[] {
  const { raw_event: raw, normalized_event: normalized } = trace
  const rawFieldCount = Object.keys(raw ?? {}).length

  return [
    {
      field: 'event_id',
      value: trace.event_id,
      status:
        trace.event_id === normalized.event_id ? 'preserved' : 'mapped',
      note:
        trace.event_id === normalized.event_id
          ? 'The same identity is reported for the raw and normalized halves.'
          : 'The response reports a different identity for the two halves.',
    },
    compare(
      raw,
      'timestamp',
      normalized.timestamp,
      'Original observation time, not the normalization time.',
      (value) => formatTimestamp(value as string),
    ),
    compare(raw, 'source', normalized.source, 'Originating system.'),
    compare(raw, 'source_type', normalized.source_type, 'Source class.'),
    compare(
      raw,
      'action',
      normalized.action,
      'Free-text action; source-specific keys are mapped by the agent.',
    ),
    compare(
      raw,
      'outcome',
      normalized.outcome,
      'Mapped to the shared outcome vocabulary.',
    ),
    compare(
      raw,
      'event_category',
      normalized.event_category,
      'Classified by the agent from event_type when not supplied.',
    ),
    {
      field: 'raw_data',
      value: rawFieldCount ? `${rawFieldCount} field(s) retained` : DISPLAY,
      status: rawFieldCount ? 'preserved' : 'absent',
      note: rawFieldCount
        ? 'Returned verbatim alongside the normalized event.'
        : 'The response carries no raw record for this event.',
    },
    {
      field: 'provenance',
      value: normalized.provenance,
      status: raw.provenance === undefined ? 'derived' : 'mapped',
      note:
        'Set by the collector and passed through unchanged; normalizing an ' +
        'event is not itself a provenance change.',
    },
  ]
}
