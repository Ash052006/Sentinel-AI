import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { IncidentReportsPage } from './incident-reports-page'
import { renderWithProviders } from '../test/utils'
import type {
  IncidentReportPayload,
  IncidentReportRecord,
  ReportSummary,
} from '../types/api'

function makePayload(): IncidentReportPayload {
  return {
    schema_version: '2.20',
    report_id: '11111111-1111-4111-8111-111111111111',
    correlation_id: '22222222-2222-4222-8222-222222222222',
    generated_at: '2026-09-25T10:00:00+00:00',
    generated_by: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    generated_by_role: 'analyst',
    model: 'gemini-2.5-pro',
    availability: {},
    incident: {},
    correlation: [],
    detections: [],
    threat_intelligence: [],
    risk_assessment: null,
    incident_memories: [],
    threat_hunts: [],
    approvals: [],
    soar_executions: [],
    timeline: [],
    evidence_catalog: [{ reference_id: '44444444-4444-4444-8444-444444444444' }],
    source_limitations: ['some sources not provided'],
    ai: {
      title: 'Deterministic report for RESOLVED correlation',
      executive_summary: 'A bounded narrative over cataloged evidence.',
      incident_overview: 'Overview text.',
      investigation_summary: 'Investigation text.',
      attribution_summary: 'Attribution remains NOT_PROVIDED.',
      threat_hunting_summary: 'Hunting text.',
      response_summary: 'Response remains NOT_PROVIDED.',
      findings: [
        {
          title: 'Detections observed',
          summary: 'N detection record(s) with attribution NOT_PROVIDED.',
          evidence_references: ['44444444-4444-4444-8444-444444444444'],
          provenance: 'observed',
        },
      ],
      limitations: ['No threat intelligence was provided.'],
      recommended_follow_up: ['Re-run with SOAR history available.'],
    },
  }
}

function makeSummary(overrides: Partial<ReportSummary> = {}): ReportSummary {
  return {
    report_id: '11111111-1111-4111-8111-111111111111',
    correlation_id: '22222222-2222-4222-8222-222222222222',
    status: 'generated',
    title: 'Deterministic report for RESOLVED correlation',
    model: 'gemini-2.5-pro',
    generated_by: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    generated_by_role: 'analyst',
    generated_at: '2026-09-25T10:00:00+00:00',
    error_code: null,
    error_message: null,
    created_at: '2026-09-25T10:00:00+00:00',
    updated_at: '2026-09-25T10:00:00+00:00',
    ...overrides,
  }
}

function makeRecord(overrides: Partial<IncidentReportRecord> = {}): IncidentReportRecord {
  return {
    ...makeSummary(overrides),
    payload: overrides.payload ?? makePayload(),
  }
}

vi.mock('../api/incident-reports', () => ({
  incidentReportsApi: {
    list: vi.fn(),
    report: vi.fn(),
    generate: vi.fn(),
  },
}))

const incidentReportsApi = (await import('../api/incident-reports')).incidentReportsApi

describe('IncidentReportsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(incidentReportsApi.list).mockResolvedValue({
      items: [makeSummary()],
      total: 1,
      page: 1,
      page_size: 50,
      correlation_id: null,
    })
  })

  it('renders generated reports with status labels', async () => {
    vi.mocked(incidentReportsApi.list).mockResolvedValue({
      items: [makeSummary()],
      total: 1,
      page: 1,
      page_size: 50,
      correlation_id: null,
    })
    renderWithProviders(<IncidentReportsPage />)

    const row = await screen.findByTestId('incident-report-row')
    expect(within(row).getByText('GENERATED')).toBeInTheDocument()
    expect(within(row).getByText('Deterministic report for RESOLVED correlation')).toBeInTheDocument()
  })

  it('renders failed reports with their error surface', async () => {
    vi.mocked(incidentReportsApi.list).mockResolvedValue({
      items: [
        makeSummary({
          status: 'failed',
          title: null,
          generated_at: null,
          error_code: 'REPORT_PROVIDER_UNAVAILABLE',
          error_message: 'the report provider call failed',
        }),
      ],
      total: 1,
      page: 1,
      page_size: 50,
      correlation_id: null,
    })
    renderWithProviders(<IncidentReportsPage />)

    const row = await screen.findByTestId('incident-report-row')
    expect(within(row).getByText('FAILED')).toBeInTheDocument()
    expect(within(row).getByText('Failed generation')).toBeInTheDocument()
  })

  it('opens the payload view for a generated report', async () => {
    const user = userEvent.setup()
    const record = makeRecord()
    vi.mocked(incidentReportsApi.report).mockResolvedValue(record)
    renderWithProviders(<IncidentReportsPage />)

    const row = await screen.findByTestId('incident-report-row')
    await user.click(row)

    expect(await screen.findByTestId('report-payload')).toBeInTheDocument()
    expect(screen.getByText('Detections observed')).toBeInTheDocument()
    expect(screen.getByText('44444444-4444-4444-8444-444444444444')).toBeInTheDocument()
    expect(screen.getByText('Attribution remains NOT_PROVIDED.')).toBeInTheDocument()
  })

  it('generates a report from the form', async () => {
    const user = userEvent.setup()
    vi.mocked(incidentReportsApi.generate).mockResolvedValue(makeRecord())
    renderWithProviders(<IncidentReportsPage />)

    const input = await screen.findByLabelText('Correlation ID')
    await user.type(input, '22222222-2222-4222-8222-222222222222')
    await user.click(screen.getByRole('button', { name: /generate report/i }))

    await waitFor(() => expect(incidentReportsApi.generate).toHaveBeenCalledTimes(1))
    expect(vi.mocked(incidentReportsApi.generate).mock.calls[0][0]).toEqual({
      correlation_id: '22222222-2222-4222-8222-222222222222',
      report_version: '2.20',
    })
    expect(await screen.findByTestId('report-notice')).toBeInTheDocument()
  })
})