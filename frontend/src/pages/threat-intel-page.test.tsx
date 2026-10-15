import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ThreatIntelPage } from './threat-intel-page'
import { renderWithProviders } from '../test/utils'
import { ApiError } from '../api/client'
import { threatIntelligenceApi } from '../api/threat-intelligence'
import type {
  ThreatIntelIndicatorDetail,
  ThreatIntelIndicatorPage,
  ThreatIntelIndicatorRecord,
  ThreatIntelLookupRecord,
} from '../types/api'

vi.mock('../api/threat-intelligence', () => ({
  threatIntelligenceApi: {
    listIndicators: vi.fn(),
    indicator: vi.fn(),
    events: vi.fn(),
  },
}))

const TI = vi.mocked(threatIntelligenceApi)

const EVENT_A = 'aaaaaaaa-0000-4000-8000-000000000001'

/**
 * Fixtures mirror a real `GET /api/threat-intelligence/...` response.
 *
 * `8.8.8.8` and `google.com` are ordinary public indicators chosen so the
 * view demonstrates provider coverage and honest status rather than an
 * alarming fabricated verdict.  Note that no fixture contains a verdict,
 * severity, or risk field: the API does not return one, so there is nothing
 * for the UI to render as a threat judgement.
 */
function indicator(
  overrides: Partial<ThreatIntelIndicatorRecord> = {},
): ThreatIntelIndicatorRecord {
  return {
    indicator_id: '8f14e45f-ea0f-4c1b-9d3a-2b7c6d5e4f30',
    indicator_type: 'ip',
    value: '8.8.8.8',
    canonical_key: 'ip:8.8.8.8',
    first_seen: '2026-09-27T10:00:00Z',
    last_seen: '2026-09-28T11:00:00Z',
    providers: ['VirusTotal', 'abuseipdb'],
    lookup_count: 2,
    success_count: 2,
    error_count: 0,
    latest_lookup_at: '2026-09-28T11:00:00Z',
    status: 'enriched',
    provenance: 'observed',
    created_at: '2026-09-27T10:00:00Z',
    updated_at: '2026-09-28T11:00:00Z',
    ...overrides,
  }
}

function lookup(overrides: Partial<ThreatIntelLookupRecord> = {}): ThreatIntelLookupRecord {
  return {
    lookup_id: '11111111-1111-4111-8111-111111111111',
    indicator_id: '8f14e45f-ea0f-4c1b-9d3a-2b7c6d5e4f30',
    event_id: EVENT_A,
    provider: 'VirusTotal',
    status: 'success',
    status_label: 'ENRICHED',
    found: true,
    provider_result_available: true,
    confidence: null,
    performed_at: '2026-09-28T11:00:00Z',
    result_timestamp: '2026-09-28T10:59:00Z',
    error_type: null,
    error_message: null,
    retryable: null,
    evidence: { asn: 15169, reputation: 4211, resource_type: 'ip_address' },
    result_metadata: { resource_type: 'ip_address', vt_id: '8.8.8.8' },
    provenance: 'enriched',
    created_at: '2026-09-28T11:00:00Z',
    updated_at: '2026-09-28T11:00:00Z',
    ...overrides,
  }
}

function page(
  items: ThreatIntelIndicatorRecord[],
  overrides: Partial<ThreatIntelIndicatorPage> = {},
): ThreatIntelIndicatorPage {
  return {
    items,
    total: items.length,
    page: 1,
    page_size: 50,
    read_only: true,
    verdict_available: false,
    ...overrides,
  }
}

function detail(
  record: ThreatIntelIndicatorRecord,
  lookups: ThreatIntelLookupRecord[],
  overrides: Partial<ThreatIntelIndicatorDetail> = {},
): ThreatIntelIndicatorDetail {
  return {
    indicator: record,
    lookups,
    lookups_truncated: false,
    events: [EVENT_A],
    events_truncated: false,
    read_only: true,
    verdict_available: false,
    ...overrides,
  }
}

function renderPage() {
  return renderWithProviders(<ThreatIntelPage />, { route: '/threat-intelligence' })
}

beforeEach(() => {
  vi.clearAllMocks()
  TI.listIndicators.mockResolvedValue(page([]))
  TI.indicator.mockResolvedValue(detail(indicator(), [lookup()]))
})

describe('ThreatIntelPage — Step 8A read surface', () => {
  it('shows a loading state while indicators are being fetched', () => {
    TI.listIndicators.mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByTestId('loading-rows')).toBeInTheDocument()
  })

  it('returns an empty state rather than fabricating rows when no indicator is persisted', async () => {
    TI.listIndicators.mockResolvedValue(page([]))
    renderPage()

    expect(await screen.findByText('No indicators recorded')).toBeInTheDocument()
    expect(screen.queryByTestId('ti-indicator-row')).not.toBeInTheDocument()
    // The empty state explains who creates indicators, rather than implying
    // the feature is missing.
    expect(screen.getAllByText(/created by the Threat Intelligence Agent/i)).not.toHaveLength(0)
    // No placeholder indicators appear anywhere in the table region.
    const panel = screen.getByTestId('ti-indicators-panel')
    expect(panel.textContent).not.toMatch(/8\.8\.8\.8|google\.com/)
  })

  it('renders the persisted indicator list with type, value, seen times, providers and status', async () => {
    TI.listIndicators.mockResolvedValue(
      page([
        indicator(),
        indicator({
          indicator_id: '3c59dc04-8e88-4b0c-9f27-6d1a5b2c8e01',
          indicator_type: 'domain',
          value: 'google.com',
          canonical_key: 'domain:google.com',
          providers: ['VirusTotal', 'AlienVault OTX'],
          status: 'partial',
          lookup_count: 3,
          success_count: 2,
          error_count: 1,
        }),
        indicator({
          indicator_id: '5b3a1c7d-4e2f-4a8b-b6c1-9d0e2f3a4b5c',
          indicator_type: 'hash',
          value: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
          canonical_key:
            'hash:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
          providers: [],
          status: 'no_lookup',
          lookup_count: 0,
          success_count: 0,
          error_count: 0,
          latest_lookup_at: null,
        }),
      ]),
    )
    renderPage()

    const rows = await screen.findAllByTestId('ti-indicator-row')
    expect(rows).toHaveLength(3)

    // Every column of the specified table, from the real payload.
    const panel = screen.getByTestId('ti-indicators-panel')
    expect(panel).toHaveTextContent('IP')
    expect(panel).toHaveTextContent('8.8.8.8')
    expect(panel).toHaveTextContent('27 Sep 2026 10:00:00 UTC')
    expect(panel).toHaveTextContent('28 Sep 2026 11:00:00 UTC')
    expect(panel).toHaveTextContent('VirusTotal, abuseipdb')
    expect(panel).toHaveTextContent('DOMAIN')
    expect(panel).toHaveTextContent('google.com')
    expect(panel).toHaveTextContent('HASH')
    expect(panel).toHaveTextContent('partial')
    // An indicator with no lookup says so rather than claiming a provider.
    const noLookupRow = rows[2]
    expect(within(noLookupRow).getByTestId('ti-row-providers')).toHaveTextContent('—')
    expect(within(noLookupRow).getByTestId('ti-row-status')).toHaveTextContent(
      'no lookup',
    )
  })

  it('shows provider status for each lookup in the indicator detail', async () => {
    const record = indicator()
    TI.listIndicators.mockResolvedValue(page([record]))
    TI.indicator.mockResolvedValue(
      detail(record, [
        lookup({ lookup_id: 'l1', provider: 'VirusTotal', found: true }),
        lookup({
          lookup_id: 'l2',
          provider: 'abuseipdb',
          found: false,
          status_label: 'NO DATA',
          provider_result_available: false,
          evidence: {},
          result_metadata: null,
        }),
      ]),
    )
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByTestId('ti-indicator-row'))

    const detailPanel = await screen.findByTestId('ti-detail-panel')
    expect(detailPanel).toHaveTextContent('Indicator detail')
    expect(within(detailPanel).getByTestId('ti-canonical-key')).toHaveTextContent(
      'ip:8.8.8.8',
    )
    expect(detailPanel).toHaveTextContent('27 Sep 2026 10:00:00 UTC')
    expect(detailPanel).toHaveTextContent('28 Sep 2026 11:00:00 UTC')

    const rows = within(detailPanel).getAllByTestId('ti-lookup-row')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('VirusTotal')
    expect(within(rows[0]).getByTestId('ti-lookup-status')).toHaveTextContent(
      'ENRICHED',
    )
    expect(rows[0]).toHaveTextContent('28 Sep 2026 11:00:00 UTC')
    expect(rows[0]).toHaveTextContent('Provider returned data')

    // "queried, nothing found" is distinct from "failed" and from "benign".
    expect(rows[1]).toHaveTextContent('abuseipdb')
    expect(within(rows[1]).getByTestId('ti-lookup-status')).toHaveTextContent('NO DATA')
    expect(rows[1]).toHaveTextContent('no record for this indicator')
    expect(rows[1]).not.toHaveTextContent('Provider returned data')
  })

  it('renders a failed provider lookup as FAILED and never as a malicious verdict', async () => {
    const record = indicator({
      status: 'partial',
      lookup_count: 2,
      success_count: 1,
      error_count: 1,
    })
    TI.listIndicators.mockResolvedValue(page([record]))
    TI.indicator.mockResolvedValue(
      detail(record, [
        lookup({ lookup_id: 'l1', provider: 'VirusTotal', found: true }),
        lookup({
          lookup_id: 'l2',
          provider: 'AlienVault OTX',
          status: 'error',
          status_label: 'FAILED',
          found: null,
          provider_result_available: false,
          error_type: 'provider_error',
          error_message: "Provider 'AlienVault OTX' lookup failed: bad request",
          retryable: false,
          evidence: null,
          result_metadata: null,
        }),
      ]),
    )
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByTestId('ti-indicator-row'))

    const detailPanel = await screen.findByTestId('ti-detail-panel')
    const rows = within(detailPanel).getAllByTestId('ti-lookup-row')
    const failed = rows[1]
    expect(within(failed).getByTestId('ti-lookup-status')).toHaveTextContent('FAILED')
    expect(within(failed).getByTestId('ti-lookup-error')).toHaveTextContent('bad request')

    // The honest-failure requirement, in full: no verdict, severity, or risk
    // anywhere on the page, and the failure is not dressed up as a finding.
    expect(detailPanel.textContent ?? '').not.toMatch(/malicious/i)
    expect(detailPanel.textContent ?? '').not.toMatch(/benign/i)
    expect(detailPanel.textContent ?? '').not.toMatch(/verdict/i)
    expect(detailPanel.textContent ?? '').not.toMatch(/\bseverity\b/i)
    expect(detailPanel.textContent ?? '').not.toMatch(/\brisk\b/i)
  })

  it('distinguishes a rate-limited provider from a failed one', async () => {
    const record = indicator({ status: 'failed', success_count: 0, error_count: 1 })
    TI.listIndicators.mockResolvedValue(page([record]))
    TI.indicator.mockResolvedValue(
      detail(record, [
        lookup({
          provider: 'VirusTotal',
          status: 'error',
          status_label: 'RATE LIMITED',
          found: null,
          provider_result_available: false,
          error_type: 'rate_limit',
          error_message: 'Provider rate limit exceeded',
          retryable: true,
          evidence: null,
          result_metadata: null,
        }),
      ]),
    )
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByTestId('ti-indicator-row'))
    const detailPanel = await screen.findByTestId('ti-detail-panel')
    expect(within(detailPanel).getByTestId('ti-lookup-status')).toHaveTextContent(
      'RATE LIMITED',
    )
    expect(detailPanel).toHaveTextContent('retryable')
  })

  it('renders safe provider evidence from the response and nothing more', async () => {
    const record = indicator()
    TI.listIndicators.mockResolvedValue(page([record]))
    TI.indicator.mockResolvedValue(
      detail(record, [
        lookup({
          provider: 'abuseipdb',
          evidence: {
            ipAddress: '8.8.8.8',
            countryCode: 'US',
            abuseConfidenceScore: 0,
            isPublic: true,
          },
        }),
      ]),
    )
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByTestId('ti-indicator-row'))
    const evidence = await screen.findByTestId('ti-evidence')
    expect(evidence).toHaveTextContent('abuseipdb')
    expect(evidence).toHaveTextContent('8.8.8.8')
    expect(evidence).toHaveTextContent('countryCode')
    expect(evidence).toHaveTextContent('abuseConfidenceScore')
  })

  it('reports an indicator with no recorded lookups instead of inventing providers', async () => {
    const record = indicator({ status: 'no_lookup', providers: [], lookup_count: 0 })
    TI.listIndicators.mockResolvedValue(page([record]))
    TI.indicator.mockResolvedValue(detail(record, [], { events: [] }))
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByTestId('ti-indicator-row'))
    const detailPanel = await screen.findByTestId('ti-detail-panel')
    expect(detailPanel).toHaveTextContent('No lookups recorded')
    expect(within(detailPanel).getByTestId('ti-no-events')).toBeInTheDocument()
    expect(screen.queryByTestId('ti-lookup-row')).not.toBeInTheDocument()
  })

  it('surfaces an API error with a retry affordance', async () => {
    TI.listIndicators.mockRejectedValue(new ApiError(503, 'backend unavailable'))
    const user = userEvent.setup()
    renderPage()

    expect(await screen.findByText('Unable to load data')).toBeInTheDocument()
    expect(screen.getByText(/backend unavailable/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()

    TI.listIndicators.mockResolvedValue(page([indicator()]))
    await user.click(screen.getByRole('button', { name: /retry/i }))
    expect(await screen.findByTestId('ti-indicator-row')).toBeInTheDocument()
  })

  it('does not render indicators when the read surface rejects an unauthorized caller', async () => {
    TI.listIndicators.mockRejectedValue(
      new ApiError(403, 'Insufficient permissions'),
    )
    renderPage()

    expect(
      await screen.findByText('Threat intelligence is not available to your role'),
    ).toBeInTheDocument()
    expect(screen.queryByTestId('ti-indicator-row')).not.toBeInTheDocument()
    // A 403 is not reported as a server fault.
    expect(screen.queryByText('Unable to load data')).not.toBeInTheDocument()
  })

  it('surfaces a 404 for an indicator the server does not have', async () => {
    const record = indicator()
    TI.listIndicators.mockResolvedValue(page([record]))
    TI.indicator.mockRejectedValue(new ApiError(404, 'Indicator not found'))
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByTestId('ti-indicator-row'))
    expect(await screen.findByText('Unable to load data')).toBeInTheDocument()
    expect(screen.getByText(/Indicator not found/)).toBeInTheDocument()
  })

  it('requests the filters and search the user actually selected', async () => {
    TI.listIndicators.mockResolvedValue(page([indicator()]))
    const user = userEvent.setup()
    renderPage()

    await screen.findAllByTestId('ti-indicator-row')
    expect(TI.listIndicators).toHaveBeenCalledWith(1, 50, undefined, undefined)

    await user.selectOptions(
      screen.getByLabelText('Filter by indicator type'),
      'domain',
    )
    await user.type(screen.getByLabelText('Search indicators'), 'google.com')
    await user.click(screen.getByRole('button', { name: 'Search' }))

    expect(TI.listIndicators).toHaveBeenLastCalledWith(1, 50, 'domain', 'google.com')
  })

  it('distinguishes an empty filter result from an empty database', async () => {
    TI.listIndicators.mockResolvedValue(page([]))
    const user = userEvent.setup()
    renderPage()

    await screen.findByText('No indicators recorded')
    await user.type(screen.getByLabelText('Search indicators'), 'nothing-matches')
    await user.click(screen.getByRole('button', { name: 'Search' }))

    expect(await screen.findByText('No indicators match')).toBeInTheDocument()
  })

  it('never presents a page size as a total', async () => {
    TI.listIndicators.mockResolvedValue(
      page([indicator()], { total: 137, page: 2, page_size: 1 }),
    )
    renderPage()

    const panel = screen.getByTestId('ti-indicators-panel')
    await within(panel).findByTestId('ti-indicator-row')
    // total is the filtered count, not the number of rows rendered.
    expect(panel).toHaveTextContent('137')
    expect(screen.getAllByTestId('ti-indicator-row')).toHaveLength(1)
  })

  it('shows no indicator detail until one is selected', async () => {
    TI.listIndicators.mockResolvedValue(page([indicator()]))
    renderPage()

    await screen.findAllByTestId('ti-indicator-row')
    expect(screen.getByText('No indicator selected')).toBeInTheDocument()
    expect(screen.queryByTestId('ti-detail')).not.toBeInTheDocument()
    expect(TI.indicator).not.toHaveBeenCalled()
  })

  it('clears the detail view on request', async () => {
    const record = indicator()
    TI.listIndicators.mockResolvedValue(page([record]))
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByTestId('ti-indicator-row'))
    await screen.findByTestId('ti-detail')
    await user.click(screen.getByRole('button', { name: /clear selection/i }))
    expect(screen.queryByTestId('ti-detail')).not.toBeInTheDocument()
    expect(screen.getByText('No indicator selected')).toBeInTheDocument()
  })

  it('discloses truncated lookup history rather than hiding it', async () => {
    const record = indicator({ lookup_count: 500 })
    TI.listIndicators.mockResolvedValue(page([record]))
    TI.indicator.mockResolvedValue(
      detail(record, [lookup()], { lookups_truncated: true }),
    )
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByTestId('ti-indicator-row'))
    expect(await screen.findByTestId('ti-lookups-truncated')).toBeInTheDocument()
  })

  it('states the read-only guarantee and the absence of verdicts on the page', async () => {
    TI.listIndicators.mockResolvedValue(page([indicator()]))
    renderPage()

    expect(await screen.findByTestId('ti-status-legend')).toHaveTextContent(
      'reports provider outcomes only',
    )
    expect(screen.getByText(/this API never writes/i)).toBeInTheDocument()
  })
})
