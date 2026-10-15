import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { SearchResultsPage } from './search-results-page'
import { renderWithProviders } from '../test/utils'

vi.mock('../api/soc', () => ({
  socApi: {
    query: vi.fn(),
  },
}))

const socApi = await import('../api/soc')

describe('SearchResultsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(socApi.socApi.query).mockResolvedValue({
      intent: {
        resource: 'detections',
        operation: 'recent',
        mode: 'recent_feed',
        target: {},
        filters: {},
        pagination: { page: 1, page_size: 200, limit: 200 },
      },
      metadata: {
        resource: 'detections',
        operation: 'recent',
        mode: 'recent_feed',
        page: 1,
        page_size: 200,
        limit: 200,
        applied_filters: [],
        parser_provider: 'schema-available',
        parser_model: null,
        recorded_at: '2026-09-21T00:00:00Z',
      },
      read_only: true,
      found: true,
      count: 1,
      total: 1,
      items: [
        {
          id: 'row-9',
          event_id: 'e-9',
          detection_id: 'det-9',
          rule_id: 'soc_probe_rule',
          rule_type: 'sigma',
          severity: 'high',
          matched: true,
          confidence: 0.8,
          evidence: {},
          result_metadata: {},
          detected_at: '2026-09-20T09:00:00Z',
          provenance: 'detected',
          created_at: '2026-09-20T09:00:00Z',
          updated_at: '2026-09-20T09:00:00Z',
        },
      ],
      semantics: ['read only'],
      note: '',
    })
  })

  it('issues the query for the ?q= parameter and renders typed results', async () => {
    renderWithProviders(<SearchResultsPage />, {
      entries: ['/?q=show recent detections'],
    })

    expect(await screen.findByText('soc_probe_rule')).toBeInTheDocument()
    expect(vi.mocked(socApi.socApi.query)).toHaveBeenCalledWith('show recent detections')
    expect(screen.getByText('detections')).toBeInTheDocument()
    expect(screen.getByText('recent_feed')).toBeInTheDocument()
  })

  it('respects the read-only guarantee and renders no fake totals on empty result set', async () => {
    vi.mocked(socApi.socApi.query).mockResolvedValue({
      intent: {
        resource: 'correlations',
        operation: 'recent',
        mode: 'recent_feed',
        target: {},
        filters: {},
        pagination: { page: 1, page_size: 200, limit: 200 },
      },
      metadata: {
        resource: 'correlations',
        operation: 'recent',
        mode: 'recent_feed',
        page: 1,
        page_size: 200,
        limit: 200,
        applied_filters: [],
        parser_provider: 'schema-available',
        parser_model: null,
        recorded_at: '2026-09-21T00:00:00Z',
      },
      read_only: true,
      found: true,
      count: 0,
      total: 0,
      items: [],
      semantics: [],
      note: '',
    })

    renderWithProviders(<SearchResultsPage />, {
      entries: ['/?q=active correlations'],
    })

    expect(await screen.findByText('No matches')).toBeInTheDocument()
  })

  it('renders the querier notice verbatim when the resource is unavailable', async () => {
    vi.mocked(socApi.socApi.query).mockResolvedValue({
      intent: {
        resource: 'detections',
        operation: 'recent',
        mode: 'recent_feed',
        target: {},
        filters: {},
        pagination: { page: 1, page_size: 200, limit: 200 },
      },
      metadata: {
        resource: 'detections',
        operation: 'recent',
        mode: 'recent_feed',
        page: 1,
        page_size: 200,
        limit: 200,
        applied_filters: [],
        parser_provider: 'schema-available',
        parser_model: null,
        recorded_at: '2026-09-21T00:00:00Z',
      },
      read_only: true,
      found: false,
      count: 0,
      total: 0,
      items: [],
      semantics: [],
      note: 'no enrichment provider available, lookups skipped',
    })

    renderWithProviders(<SearchResultsPage />, {
      entries: ['/?q=search event ghost'],
    })

    expect(await screen.findByText(/no enrichment provider available/i)).toBeInTheDocument()
  })

  it('advertises only questions the read-only querier actually supports', async () => {
    renderWithProviders(<SearchResultsPage />, { entries: ['/'] })

    await screen.findByText(/Ask the SOC querier/i)
    const suggestions = (await screen.findByText(/Try:/i)).textContent ?? ''

    // Correlations support get/recent/by_event/by_detection with no filters and
    // no ordering, so "highest risk correlations" could never be answered and
    // must not be offered as an example.
    expect(suggestions).not.toMatch(/highest risk correlation/i)
    expect(suggestions).not.toMatch(/active incidents/i)

    // Every advertised example must be a supported capability.
    expect(suggestions).toMatch(/recent detections/i)
    expect(suggestions).toMatch(/recent correlations/i)
    // risk_level is a real filter, but only on risk assessments.
    expect(suggestions).toMatch(/critical risk assessments/i)
  })
})