import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { CorrelationDetailPage } from './correlation-detail-page'
import { renderWithProviders } from '../test/utils'
import type { CorrelationMember, CorrelationResult } from '../types/api'
import { shortId } from '../lib/formats'

vi.mock('../api/correlations', () => ({ correlationsApi: { get: vi.fn() } }))
vi.mock('../api/risks', () => ({ risksApi: { forCorrelation: vi.fn() } }))
vi.mock('../api/memories', () => ({ memoriesApi: { forCorrelation: vi.fn() } }))

const correlationsApi = (await import('../api/correlations')).correlationsApi
const risksApi = (await import('../api/risks')).risksApi
const memoriesApi = (await import('../api/memories')).memoriesApi

const CORR = '85d156d8-afde-42a1-9c9c-61e7a4617e09'
const SHARED_EVENT = '4b572882-b7e4-401c-ba1e-7131955b6f70'

// shortId() strips dashes and keeps 12 chars, so each detection needs a
// genuinely distinct 12-character prefix for the rendered text to differ.
const DETECTION_IDS = [
  'a1000000-0000-4000-8000-000000000001',
  'b2000000-0000-4000-8000-000000000002',
  'c3000000-0000-4000-8000-000000000003',
  'd4000000-0000-4000-8000-000000000004',
  'e5000000-0000-4000-8000-000000000005',
  'f6000000-0000-4000-8000-000000000006',
  'a7000000-0000-4000-8000-000000000007',
]

function member(index: number, eventId: string): CorrelationMember {
  const detectionId = DETECTION_IDS[index % DETECTION_IDS.length]
  const suffix = String(index).padStart(12, '0')
  return {
    id: `cm-${CORR}-${suffix}`,
    correlation_id: CORR,
    detection_id: detectionId,
    event_id: eventId,
    timestamp: '2026-10-02T14:00:00+00:00',
    member_order: index + 1,
    created_at: '2026-10-02T14:00:00+00:00',
    updated_at: '2026-10-02T14:00:00+00:00',
  }
}

function correlation(members: CorrelationMember[]): CorrelationResult {
  return {
    id: CORR,
    correlation_id: CORR,
    status: 'candidate',
    confidence: null,
    evidence: { reason: 'shared_event_id', member_count: members.length },
    result_metadata: {},
    timestamp: '2026-10-02T14:00:00+00:00',
    provenance: 'correlated',
    members,
    created_at: '2026-10-02T14:00:00+00:00',
    updated_at: '2026-10-02T14:00:00+00:00',
  }
}

const emptyPage = { items: [], total: 0, page: 1, page_size: 50 }

function renderDetail() {
  return renderWithProviders(
    <Routes>
      <Route path="/correlations/:correlationId" element={<CorrelationDetailPage />} />
    </Routes>,
    { route: `/correlations/${CORR}`, entries: [`/correlations/${CORR}`] },
  )
}

describe('CorrelationDetailPage — shared-event grouping (P0-1)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(risksApi.forCorrelation).mockResolvedValue(emptyPage as never)
    vi.mocked(memoriesApi.forCorrelation).mockResolvedValue(emptyPage as never)
  })

  it('states that seven members share one event instead of implying seven events', async () => {
    const members = Array.from({ length: 7 }, (_, i) => member(i, SHARED_EVENT))
    vi.mocked(correlationsApi.get).mockResolvedValue(correlation(members) as never)

    renderDetail()

    const note = await screen.findByTestId('member-grouping-note')
    expect(note).toHaveTextContent('7 members reference the same single event')
    // The exact shared event identity must be visible next to the claim.
    expect(within(note).getByText(shortId(SHARED_EVENT))).toBeInTheDocument()
    expect(note).toHaveTextContent('not 7 separate events')
    // Correlation membership is grouped by event ID -- state the reason.
    expect(note).toHaveTextContent('groups detections by event ID')
  })

  it('does not claim a single event when members span several events', async () => {
    const members = [
      member(0, SHARED_EVENT),
      member(1, '00000000-0000-4000-8000-000000000001'),
      member(2, '00000000-0000-4000-8000-000000000002'),
    ]
    vi.mocked(correlationsApi.get).mockResolvedValue(correlation(members) as never)

    renderDetail()

    const note = await screen.findByTestId('member-grouping-note')
    expect(note).toHaveTextContent('spans')
    expect(note).toHaveTextContent('3 distinct events')
    expect(note).not.toHaveTextContent('same single event')
  })

  it('still renders every persisted member identity', async () => {
    const members = Array.from({ length: 7 }, (_, i) => member(i, SHARED_EVENT))
    vi.mocked(correlationsApi.get).mockResolvedValue(correlation(members) as never)

    renderDetail()

    await screen.findByTestId('member-grouping-note')

    // Scope to the members table: seven distinct detection ids, and the shared
    // event id repeated once per row.
    const table = screen.getByTestId('members-table')
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(7)
    for (const [index, m] of members.entries()) {
      expect(within(rows[index] as HTMLElement).getByText(shortId(m.detection_id))).toBeInTheDocument()
      expect(within(rows[index] as HTMLElement).getByText(shortId(m.event_id))).toBeInTheDocument()
    }
    expect(within(table).getAllByText(shortId(SHARED_EVENT))).toHaveLength(7)
  })

  it('offers to run a multi-agent debate scoped to this correlation', async () => {
    const members = Array.from({ length: 7 }, (_, i) => member(i, SHARED_EVENT))
    vi.mocked(correlationsApi.get).mockResolvedValue(correlation(members) as never)

    renderDetail()

    const link = await screen.findByRole('link', { name: /run agent debate/i })
    // The debate must be scoped to this correlation, not left to a bare route.
    expect(link).toHaveAttribute('href', `/debates/correlation/${CORR}`)
  })
})