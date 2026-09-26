import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThreatHuntingPage } from './threat-hunting-page'
import { renderWithProviders } from '../test/utils'
import type {
  ThreatHuntEvidenceRecord,
  ThreatHuntFindingRecord,
  ThreatHuntRecord,
  ThreatHuntSummary,
  ThreatHuntTimelineItemRecord,
} from '../types/api'

function makeHunt(overrides: Partial<ThreatHuntSummary> = {}): ThreatHuntSummary {
  return {
    hunt_id: overrides.hunt_id ?? '11111111-1111-4111-8111-111111111111',
    name: overrides.name ?? 'Reconnaissance sweep',
    hunt_type: overrides.hunt_type ?? 'detection_review',
    status: overrides.status ?? 'draft',
    start_time: overrides.start_time ?? '2026-09-23T00:00:00+00:00',
    end_time: overrides.end_time ?? '2026-09-24T00:00:00+00:00',
    created_by: overrides.created_by ?? 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    created_by_role: overrides.created_by_role ?? 'analyst',
    created_at: overrides.created_at ?? '2026-09-24T08:00:00+00:00',
    started_at: overrides.started_at ?? null,
    completed_at: overrides.completed_at ?? null,
    result_count: overrides.result_count ?? 0,
    finding_count: overrides.finding_count ?? 0,
    timeline_count: overrides.timeline_count ?? 0,
    error_code: overrides.error_code ?? null,
    error_message: overrides.error_message ?? null,
  }
}

function makeHuntDetail(hunt: ThreatHuntSummary): ThreatHuntRecord {
  return {
    ...hunt,
    description: 'Revisit persisted detection history.',
    filters: [],
  }
}

function makeFinding(overrides: Partial<ThreatHuntFindingRecord> = {}): ThreatHuntFindingRecord {
  return {
    finding_id: overrides.finding_id ?? '22222222-2222-4222-8222-222222222222',
    title: overrides.title ?? 'RULE-RECON: 4 evidence item(s)',
    description: overrides.description ?? 'Row(s) grouped by rule_id RULE-RECON.',
    severity: overrides.severity ?? 'high',
    provenance: overrides.provenance ?? 'detected',
    observed_at: overrides.observed_at ?? '2026-09-23T10:00:00+00:00',
    evidence_ids: overrides.evidence_ids ?? [],
    context: overrides.context ?? { rule_id: 'RULE-RECON', count: 4 },
  }
}

function makeEvidence(overrides: Partial<ThreatHuntEvidenceRecord> = {}): ThreatHuntEvidenceRecord {
  return {
    evidence_id: overrides.evidence_id ?? '33333333-3333-4333-8333-333333333333',
    evidence_type: overrides.evidence_type ?? 'detection',
    reference_id: overrides.reference_id ?? '44444444-4444-4444-8444-444444444444',
    event_id: overrides.event_id ?? null,
    correlation_id: overrides.correlation_id ?? null,
    provenance: overrides.provenance ?? 'detected',
    severity: overrides.severity ?? 'high',
    observed_at: overrides.observed_at ?? '2026-09-23T10:00:00+00:00',
    title: overrides.title ?? 'RULE-RECON matched',
    summary: overrides.summary ?? 'Detection RULE-RECON for event at 2026-09-23T10:00:00Z severity high.',
  }
}

function makeTimeline(overrides: Partial<ThreatHuntTimelineItemRecord> = {}): ThreatHuntTimelineItemRecord {
  return {
    timeline_item_id: overrides.timeline_item_id ?? '55555555-5555-4555-8555-555555555555',
    evidence_id: overrides.evidence_id ?? '33333333-3333-4333-8333-333333333333',
    observed_at: overrides.observed_at ?? '2026-09-23T10:00:00+00:00',
    evidence_type: overrides.evidence_type ?? 'detection',
    evidence_summary: overrides.evidence_summary ?? 'Detection RULE-RECON for event.',
    provenance: overrides.provenance ?? 'detected',
  }
}

vi.mock('../api/threat-hunting', () => ({
  threatHuntingApi: {
    hunts: vi.fn(),
    hunt: vi.fn(),
    create: vi.fn(),
    run: vi.fn(),
    cancel: vi.fn(),
    findings: vi.fn(),
    evidence: vi.fn(),
    timeline: vi.fn(),
  },
}))

const threatHuntingApi = (await import('../api/threat-hunting')).threatHuntingApi

describe('ThreatHuntingPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(threatHuntingApi.hunts).mockResolvedValue({
      items: [makeHunt()],
      total: 1,
      page: 1,
      page_size: 50,
    })
  })

  it('renders hunts from the API with their status labels', async () => {
    vi.mocked(threatHuntingApi.hunts).mockResolvedValue({
      items: [makeHunt({ status: 'completed', result_count: 7, finding_count: 2 })],
      total: 1,
      page: 1,
      page_size: 50,
    })
    renderWithProviders(<ThreatHuntingPage />)

    const row = await screen.findByTestId('threat-hunt-row')
    expect(within(row).getByText('COMPLETED')).toBeInTheDocument()
    expect(within(row).getByText('Reconnaissance sweep')).toBeInTheDocument()
    expect(within(row).getByText('7')).toBeInTheDocument()
  })

  it('shows the run and cancel actions for drafts', async () => {
    const draft = makeHunt({ hunt_id: '99999999-9999-4999-8999-999999999999', status: 'draft' })
    vi.mocked(threatHuntingApi.hunts).mockResolvedValue({
      items: [draft],
      total: 1,
      page: 1,
      page_size: 50,
    })
    renderWithProviders(<ThreatHuntingPage />)

    await screen.findByTestId('threat-hunt-row')
    expect(screen.getByTestId('run-99999999-9999-4999-8999-999999999999')).toBeInTheDocument()
    expect(screen.getByTestId('cancel-99999999-9999-4999-8999-999999999999')).toBeInTheDocument()

    await userEvent.setup().click(screen.getByTestId('run-99999999-9999-4999-8999-999999999999'))
    await waitFor(() =>
      expect(threatHuntingApi.run).toHaveBeenCalledWith('99999999-9999-4999-8999-999999999999'),
    )
  })

  it('creates a draft hunt from the form', async () => {
    const user = userEvent.setup()
    vi.mocked(threatHuntingApi.create).mockResolvedValue(makeHuntDetail(makeHunt({ status: 'draft' })))
    renderWithProviders(<ThreatHuntingPage />)

    await screen.findByTestId('hunt-create-form')
    const name = screen.getByLabelText('Hunt name')
    await user.clear(name)
    await user.type(name, 'Indicator sweep')
    await user.click(screen.getByRole('button', { name: /create draft/i }))

    await waitFor(() => expect(threatHuntingApi.create).toHaveBeenCalledTimes(1))
    const body = vi.mocked(threatHuntingApi.create).mock.calls[0][0]
    expect(body.name).toBe('Indicator sweep')
    expect(body.hunt_type).toBe('detection_review')
    expect(new Date(body.end_time).getTime()).toBeGreaterThan(new Date(body.start_time).getTime())
    expect(await screen.findByTestId('hunt-notice')).toBeInTheDocument()
  })

  it('opens findings for a completed hunt', async () => {
    const user = userEvent.setup()
    const completed = makeHunt({ status: 'completed', result_count: 1, finding_count: 1, timeline_count: 1 })
    vi.mocked(threatHuntingApi.hunts).mockResolvedValue({
      items: [completed],
      total: 1,
      page: 1,
      page_size: 50,
    })
    vi.mocked(threatHuntingApi.hunt).mockResolvedValue(makeHuntDetail(completed))
    vi.mocked(threatHuntingApi.findings).mockResolvedValue({
      items: [makeFinding()],
      total: 1,
      page: 1,
      page_size: 50,
    })
    vi.mocked(threatHuntingApi.evidence).mockResolvedValue({ items: [makeEvidence()], total: 1, page: 1, page_size: 50 })
    vi.mocked(threatHuntingApi.timeline).mockResolvedValue({ items: [makeTimeline()], total: 1, page: 1, page_size: 50 })

    renderWithProviders(<ThreatHuntingPage />)
    const row = await screen.findByTestId('threat-hunt-row')
    await user.click(row)

    expect(await screen.findByTestId('hunt-findings')).toBeInTheDocument()
    expect(await screen.findByTestId('hunt-finding-row')).toBeInTheDocument()
    expect(screen.getByText('RULE-RECON: 4 evidence item(s)')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'evidence' }))
    expect(await screen.findByTestId('hunt-evidence-row')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'timeline' }))
    expect(await screen.findByTestId('hunt-timeline-row')).toBeInTheDocument()
  })
})