import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { IncidentDetailPage } from './incident-detail-page'
import { renderWithProviders } from '../test/utils'
import type { CorrelationMember, CorrelationResult, DetectionResult } from '../types/api'
import { shortId } from '../lib/formats'

vi.mock('../api/correlations', () => ({ correlationsApi: { get: vi.fn() } }))
vi.mock('../api/risks', () => ({ risksApi: { forCorrelation: vi.fn() } }))
vi.mock('../api/memories', () => ({ memoriesApi: { forCorrelation: vi.fn() } }))
vi.mock('../api/detections', () => ({ detectionsApi: { get: vi.fn() } }))

const correlationsApi = (await import('../api/correlations')).correlationsApi
const risksApi = (await import('../api/risks')).risksApi
const memoriesApi = (await import('../api/memories')).memoriesApi
const detectionsApi = (await import('../api/detections')).detectionsApi

const CORR = '85d156d8-afde-42a1-9c9c-61e7a4617e09'
const SHARED_EVENT = '4b572882-b7e4-401c-ba1e-7131955b6f70'

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
  return {
    id: `cm-${CORR}-${String(index).padStart(12, '0')}`,
    correlation_id: CORR,
    detection_id: DETECTION_IDS[index % DETECTION_IDS.length],
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

function detection(id: string): DetectionResult {
  return {
    id,
    detection_id: id,
    rule_id: '11111111-1111-4111-8111-111111111111',
    severity: 'high',
    confidence: 0.8,
    detected_at: '2026-10-02T14:00:00+00:00',
    status: 'matched',
    provenance: 'detected',
  } as unknown as DetectionResult
}

const emptyPage = { items: [], total: 0, page: 1, page_size: 50 }

function renderDetail() {
  return renderWithProviders(
    <Routes>
      <Route path="/incidents/:correlationId" element={<IncidentDetailPage />} />
    </Routes>,
    { route: `/incidents/${CORR}`, entries: [`/incidents/${CORR}`] },
  )
}

describe('IncidentDetailPage — event identity is not inflated (P0-1)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(risksApi.forCorrelation).mockResolvedValue(emptyPage as never)
    vi.mocked(memoriesApi.forCorrelation).mockResolvedValue(emptyPage as never)
    vi.mocked(detectionsApi.get).mockImplementation(
      async (id: string) => detection(id) as never,
    )
  })

  it('lists one shared event once, with the number of detections referencing it', async () => {
    const members = Array.from({ length: 7 }, (_, i) => member(i, SHARED_EVENT))
    vi.mocked(correlationsApi.get).mockResolvedValue(correlation(members) as never)

    renderDetail()

    await screen.findByTestId('member-grouping-note')
    // The grouping note states the shared-event boundary explicitly.
    expect(screen.getByTestId('member-grouping-note')).toHaveTextContent(
      '7 members reference the same single event',
    )

    // The repeated event must be rendered once in the reference list, not once
    // per member -- seven identical rows read as seven distinct events.
    const reference = screen.getByText(`referenced by 7 detections`)
    expect(reference).toBeInTheDocument()
    expect(screen.queryAllByText(/^referenced by \d+ detection$/)).toHaveLength(0)
  })

  it('renders one entry per distinct event when members span several events', async () => {
    const members = [
      member(0, SHARED_EVENT),
      member(1, '00000000-0000-4000-8000-000000000001'),
      member(2, '00000000-0000-4000-8000-000000000002'),
    ]
    vi.mocked(correlationsApi.get).mockResolvedValue(correlation(members) as never)

    renderDetail()

    await screen.findByTestId('member-grouping-note')
    expect(screen.getByTestId('member-grouping-note')).toHaveTextContent('3 distinct events')
    // A single-event correlation is the only case that claims "one event".
    // Here every event is referenced by exactly one detection, so the plural
    // form must not be used.
    expect(screen.getAllByText('referenced by 1 detection')).toHaveLength(3)
    expect(screen.queryByText(/referenced by \d+ detections$/)).not.toBeInTheDocument()
  })

  it('still shows the exact event identity, not only a count', async () => {
    const members = Array.from({ length: 7 }, (_, i) => member(i, SHARED_EVENT))
    vi.mocked(correlationsApi.get).mockResolvedValue(correlation(members) as never)

    renderDetail()

    await screen.findByTestId('member-grouping-note')
    expect(screen.getAllByText(shortId(SHARED_EVENT)).length).toBeGreaterThan(0)
  })
})

describe('IncidentDetailPage — absent correlation confidence (P2-6)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(risksApi.forCorrelation).mockResolvedValue(emptyPage as never)
    vi.mocked(memoriesApi.forCorrelation).mockResolvedValue(emptyPage as never)
    vi.mocked(detectionsApi.get).mockImplementation(
      async (id: string) => detection(id) as never,
    )
  })

  it('explains that a dash is a missing measurement, not a confidence of zero', async () => {
    const members = Array.from({ length: 2 }, (_, i) => member(i, SHARED_EVENT))
    vi.mocked(correlationsApi.get).mockResolvedValue(correlation(members) as never)

    renderDetail()

    const note = await screen.findByTestId('correlation-confidence-absent')
    expect(note).toHaveTextContent('Not produced by the correlation engine')
    expect(note).toHaveTextContent('not a confidence of zero')
  })

  it('omits the explanation when a confidence was actually produced', async () => {
    const members = Array.from({ length: 2 }, (_, i) => member(i, SHARED_EVENT))
    const withConfidence = {
      ...correlation(members),
      confidence: 0.42,
    } as CorrelationResult
    vi.mocked(correlationsApi.get).mockResolvedValue(withConfidence as never)

    renderDetail()

    await screen.findByTestId('member-grouping-note')
    expect(screen.queryByTestId('correlation-confidence-absent')).not.toBeInTheDocument()
  })
})