import { describe, expect, it } from 'vitest'
import type { IngestEventTrace } from '../api/ingest'
import { summarizeTrace } from './ingest-trace'

/**
 * `summarizeTrace` makes claims about the transformation on the Data Ingest
 * page, so each claim is pinned here: a field is only reported as preserved
 * when the response itself proves it.
 */

function trace(overrides: Partial<IngestEventTrace> = {}): IngestEventTrace {
  return {
    event_id: 'ddacb151-c62b-4e0f-bfea-b83369417957',
    line_number: 1,
    raw_event: {
      timestamp: '2026-09-27T10:00:00+00:00',
      source: 'windows-dc01',
      source_type: 'operating_system',
      event_type: 'logon',
      action: 'network logon attempt',
      outcome: 'failure',
    },
    normalized_event: {
      event_id: 'ddacb151-c62b-4e0f-bfea-b83369417957',
      timestamp: '2026-09-27T10:00:00Z',
      event_category: 'authentication',
      action: 'network logon attempt',
      outcome: 'failure',
      source: 'windows-dc01',
      source_type: 'operating_system',
      actor: null,
      source_endpoint: null,
      destination_endpoint: null,
      process: null,
      file: null,
      normalized_data: {},
      provenance: 'observed',
    },
    provenance: 'observed',
    ...overrides,
  }
}

const statusOf = (rows: ReturnType<typeof summarizeTrace>, field: string) =>
  rows.find((row) => row.field === field)

describe('summarizeTrace', () => {
  it('reports identical identity as preserved', () => {
    const rows = summarizeTrace(trace())
    expect(statusOf(rows, 'event_id')).toMatchObject({
      value: 'ddacb151-c62b-4e0f-bfea-b83369417957',
      status: 'preserved',
    })
  })

  it('does not claim the identity is preserved when the halves disagree', () => {
    const subject = trace()
    const rows = summarizeTrace({
      ...subject,
      normalized_event: { ...subject.normalized_event, event_id: 'other' },
    })
    expect(statusOf(rows, 'event_id')?.status).toBe('mapped')
  })

  it('compares timestamps as instants, not strings', () => {
    const rows = summarizeTrace(trace())
    const row = statusOf(rows, 'timestamp')
    // Raw is +00:00, normalized is Z: same moment, different spelling.
    expect(row?.value).toBe('2026-09-27 10:00:00Z')
    expect(row?.status).toBe('preserved')
  })

  it('reports a genuinely different timestamp as mapped', () => {
    const rows = summarizeTrace(
      trace({
        raw_event: { ...trace().raw_event, timestamp: '2020-01-01T00:00:00+00:00' },
      }),
    )
    expect(statusOf(rows, 'timestamp')?.status).toBe('mapped')
  })

  it('reports a field the raw record lacks as derived', () => {
    const rows = summarizeTrace(trace())
    expect(statusOf(rows, 'event_category')).toMatchObject({
      value: 'authentication',
      status: 'derived',
    })
  })

  it('reports a raw field the agent translated as mapped', () => {
    const subject = trace()
    const rows = summarizeTrace({
      ...subject,
      normalized_event: { ...subject.normalized_event, outcome: 'denied' },
    })
    expect(statusOf(rows, 'outcome')).toMatchObject({
      value: 'denied',
      status: 'mapped',
    })
  })

  it('reports a value dropped by the agent as mapped rather than preserved', () => {
    const subject = trace()
    const rows = summarizeTrace({
      ...subject,
      normalized_event: { ...subject.normalized_event, action: null },
    })
    expect(statusOf(rows, 'action')?.status).toBe('mapped')
    expect(statusOf(rows, 'action')?.value).toBe('—')
  })

  it('counts the retained raw fields', () => {
    const rows = summarizeTrace(trace())
    expect(statusOf(rows, 'raw_data')).toMatchObject({
      value: '6 field(s) retained',
      status: 'preserved',
    })
  })

  it('marks provenance as derived and shows the reported marker', () => {
    const rows = summarizeTrace(trace())
    expect(statusOf(rows, 'provenance')).toMatchObject({
      value: 'observed',
      status: 'derived',
    })
  })

  it('does not invent a provenance marker the response does not carry', () => {
    const subject = trace()
    const rows = summarizeTrace({
      ...subject,
      normalized_event: { ...subject.normalized_event, provenance: 'enriched' },
      provenance: 'enriched',
    })
    expect(statusOf(rows, 'provenance')?.value).toBe('enriched')
  })
})
