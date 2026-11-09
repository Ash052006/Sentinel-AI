import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ThreatIntelPage } from './threat-intel-page'
import { renderWithProviders } from '../test/utils'
import { ApiError } from '../api/client'
import { threatIntelligenceApi } from '../api/threat-intelligence'
import type {
  ManualLookupResponse,
  ThreatIntelIndicatorPage,
  ThreatIntelIndicatorRecord,
} from '../types/api'

vi.mock('../api/threat-intelligence', () => ({
  threatIntelligenceApi: {
    listIndicators: vi.fn(),
    indicator: vi.fn(),
    events: vi.fn(),
    manualLookup: vi.fn(),
  },
}))

const TI = vi.mocked(threatIntelligenceApi)

function mockIndicator(
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

function mockPage(
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

describe('ThreatIntelPage — Manual Lookup', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    TI.listIndicators.mockResolvedValue(mockPage([mockIndicator()]))
    TI.indicator.mockResolvedValue({
      indicator: mockIndicator(),
      lookups: [],
      lookups_truncated: false,
      events: [],
      events_truncated: false,
      read_only: true,
      verdict_available: false,
    })
  })

  // 1. Form rendering
  it('renders the manual lookup panel, form inputs, and lookup button', async () => {
    renderWithProviders(<ThreatIntelPage />)

    expect(screen.getByTestId('manual-lookup-panel')).toBeInTheDocument()
    expect(screen.getByTestId('manual-lookup-type')).toBeInTheDocument()
    expect(screen.getByTestId('manual-lookup-input')).toBeInTheDocument()
    expect(screen.getByTestId('manual-lookup-button')).toBeInTheDocument()
    expect(screen.getByText('Manual Lookup')).toBeInTheDocument()
  })

  // 2. Indicator type selection
  it('allows the analyst to select different indicator types', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ThreatIntelPage />)

    const typeSelect = screen.getByTestId('manual-lookup-type') as HTMLSelectElement
    expect(typeSelect.value).toBe('ip')

    await user.selectOptions(typeSelect, 'domain')
    expect(typeSelect.value).toBe('domain')

    await user.selectOptions(typeSelect, 'url')
    expect(typeSelect.value).toBe('url')

    await user.selectOptions(typeSelect, 'hash')
    expect(typeSelect.value).toBe('hash')
  })

  // 3. Successful lookup
  it('submits manual lookup and displays normalized value, status, identity, and provider results', async () => {
    const user = userEvent.setup()
    const mockResponse: ManualLookupResponse = {
      indicator_id: '12345678-1234-5678-1234-567812345678',
      indicator_type: 'ip',
      normalized_indicator_value: '1.1.1.1',
      canonical_key: 'ip:1.1.1.1',
      status: 'enriched',
      providers_attempted: 2,
      providers_succeeded: 2,
      providers_failed: 0,
      providers_skipped: 0,
      is_new_indicator: true,
      results: [
        {
          provider: 'VirusTotal',
          status: 'success',
          found: true,
          confidence: 0.95,
          performed_at: '2026-10-01T12:00:00Z',
          evidence: { reputation: 100 },
        },
        {
          provider: 'abuseipdb',
          status: 'success',
          found: false,
          confidence: null,
          performed_at: '2026-10-01T12:00:00Z',
          evidence: {},
        },
      ],
    }
    TI.manualLookup.mockResolvedValueOnce(mockResponse)

    renderWithProviders(<ThreatIntelPage />)

    const input = screen.getByTestId('manual-lookup-input')
    const button = screen.getByTestId('manual-lookup-button')

    await user.type(input, '1.1.1.1')
    await user.click(button)

    expect(TI.manualLookup).toHaveBeenCalledWith({
      indicator: '1.1.1.1',
      indicator_type: 'ip',
    })

    await waitFor(() => {
      expect(screen.getByTestId('manual-lookup-results')).toBeInTheDocument()
    })

    expect(screen.getByTestId('manual-result-value')).toHaveTextContent('1.1.1.1')
    expect(screen.getByTestId('manual-result-canonical-key')).toHaveTextContent('ip:1.1.1.1')
    expect(screen.getByTestId('manual-result-identity')).toHaveTextContent('New Indicator')
    expect(screen.getByTestId('manual-result-status')).toHaveTextContent('enriched')

    const providerCards = screen.getAllByTestId('manual-provider-result')
    expect(providerCards).toHaveLength(2)

    expect(within(providerCards[0]).getByText('VirusTotal')).toBeInTheDocument()
    expect(within(providerCards[0]).getByText('Record found')).toBeInTheDocument()
    expect(within(providerCards[0]).getByText('Confidence: 95%')).toBeInTheDocument()

    expect(within(providerCards[1]).getByText('abuseipdb')).toBeInTheDocument()
    expect(within(providerCards[1]).getByText('No record found')).toBeInTheDocument()
  })

  // 4. Loading state
  it('disables input and button and shows loading indicator while request is in flight', async () => {
    const user = userEvent.setup()
    let resolveLookup!: (val: ManualLookupResponse) => void
    const lookupPromise = new Promise<ManualLookupResponse>((resolve) => {
      resolveLookup = resolve
    })
    TI.manualLookup.mockReturnValueOnce(lookupPromise)

    renderWithProviders(<ThreatIntelPage />)

    const input = screen.getByTestId('manual-lookup-input')
    const button = screen.getByTestId('manual-lookup-button')

    await user.type(input, '1.1.1.1')
    await user.click(button)

    expect(button).toBeDisabled()
    expect(button).toHaveTextContent('Looking up...')
    expect(screen.getByTestId('manual-lookup-loading')).toBeInTheDocument()

    // Resolve the promise
    resolveLookup({
      indicator_id: '12345678-1234-5678-1234-567812345678',
      indicator_type: 'ip',
      normalized_indicator_value: '1.1.1.1',
      canonical_key: 'ip:1.1.1.1',
      status: 'enriched',
      providers_attempted: 1,
      providers_succeeded: 1,
      providers_failed: 0,
      providers_skipped: 0,
      is_new_indicator: false,
      results: [],
    })

    await waitFor(() => {
      expect(screen.queryByTestId('manual-lookup-loading')).not.toBeInTheDocument()
    })
    expect(button).not.toBeDisabled()
    expect(button).toHaveTextContent('Lookup Indicator')
  })

  // 5. Client validation errors
  it('validates empty indicator input without sending network request', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ThreatIntelPage />)

    const button = screen.getByTestId('manual-lookup-button')
    await user.click(button)

    expect(TI.manualLookup).not.toHaveBeenCalled()
    expect(screen.getByTestId('manual-lookup-error')).toHaveTextContent(
      'Indicator value must not be empty or whitespace.',
    )
  })

  // 6. Partial provider failures
  it('renders partial status when one provider succeeds and another fails', async () => {
    const user = userEvent.setup()
    const mockResponse: ManualLookupResponse = {
      indicator_id: '12345678-1234-5678-1234-567812345678',
      indicator_type: 'domain',
      normalized_indicator_value: 'example.com',
      canonical_key: 'domain:example.com',
      status: 'partial',
      providers_attempted: 2,
      providers_succeeded: 1,
      providers_failed: 1,
      providers_skipped: 0,
      is_new_indicator: false,
      results: [
        {
          provider: 'VirusTotal',
          status: 'success',
          found: true,
          performed_at: '2026-10-01T12:00:00Z',
        },
        {
          provider: 'AlienVault OTX',
          status: 'error',
          error_message: 'Provider timed out after 5.0s',
          performed_at: '2026-10-01T12:00:00Z',
        },
      ],
    }
    TI.manualLookup.mockResolvedValueOnce(mockResponse)

    renderWithProviders(<ThreatIntelPage />)

    const input = screen.getByTestId('manual-lookup-input')
    const typeSelect = screen.getByTestId('manual-lookup-type')
    const button = screen.getByTestId('manual-lookup-button')

    await user.selectOptions(typeSelect, 'domain')
    await user.type(input, 'example.com')
    await user.click(button)

    await waitFor(() => {
      expect(screen.getByTestId('manual-lookup-results')).toBeInTheDocument()
    })

    expect(screen.getByTestId('manual-result-status')).toHaveTextContent('partial')
    const providerCards = screen.getAllByTestId('manual-provider-result')
    expect(providerCards).toHaveLength(2)

    expect(within(providerCards[0]).getByText('SUCCESS')).toBeInTheDocument()
    expect(within(providerCards[1]).getByText('ERROR')).toBeInTheDocument()
    expect(within(providerCards[1]).getByText('Provider timed out after 5.0s')).toBeInTheDocument()
  })

  // 7. All provider failures
  it('renders failed status when all attempted providers fail', async () => {
    const user = userEvent.setup()
    const mockResponse: ManualLookupResponse = {
      indicator_id: '12345678-1234-5678-1234-567812345678',
      indicator_type: 'ip',
      normalized_indicator_value: '1.2.3.4',
      canonical_key: 'ip:1.2.3.4',
      status: 'failed',
      providers_attempted: 2,
      providers_succeeded: 0,
      providers_failed: 2,
      providers_skipped: 0,
      is_new_indicator: true,
      results: [
        {
          provider: 'VirusTotal',
          status: 'error',
          error_message: 'API rate limit exceeded',
          performed_at: '2026-10-01T12:00:00Z',
        },
        {
          provider: 'abuseipdb',
          status: 'error',
          error_message: 'Connection reset by peer',
          performed_at: '2026-10-01T12:00:00Z',
        },
      ],
    }
    TI.manualLookup.mockResolvedValueOnce(mockResponse)

    renderWithProviders(<ThreatIntelPage />)

    const input = screen.getByTestId('manual-lookup-input')
    const button = screen.getByTestId('manual-lookup-button')

    await user.type(input, '1.2.3.4')
    await user.click(button)

    await waitFor(() => {
      expect(screen.getByTestId('manual-lookup-results')).toBeInTheDocument()
    })

    expect(screen.getByTestId('manual-result-status')).toHaveTextContent('failed')
    const providerCards = screen.getAllByTestId('manual-provider-result')
    expect(providerCards).toHaveLength(2)
    expect(within(providerCards[0]).getByText('API rate limit exceeded')).toBeInTheDocument()
    expect(within(providerCards[1]).getByText('Connection reset by peer')).toBeInTheDocument()
  })

  // 8. No configured providers
  it('renders informative message when no providers are configured', async () => {
    const user = userEvent.setup()
    const mockResponse: ManualLookupResponse = {
      indicator_id: '12345678-1234-5678-1234-567812345678',
      indicator_type: 'hash',
      normalized_indicator_value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      canonical_key: 'hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      status: 'no_lookup',
      providers_attempted: 0,
      providers_succeeded: 0,
      providers_failed: 0,
      providers_skipped: 0,
      is_new_indicator: true,
      results: [],
    }
    TI.manualLookup.mockResolvedValueOnce(mockResponse)

    renderWithProviders(<ThreatIntelPage />)

    const input = screen.getByTestId('manual-lookup-input')
    const typeSelect = screen.getByTestId('manual-lookup-type')
    const button = screen.getByTestId('manual-lookup-button')

    await user.selectOptions(typeSelect, 'hash')
    await user.type(input, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    await user.click(button)

    await waitFor(() => {
      expect(screen.getByTestId('manual-no-providers')).toBeInTheDocument()
    })
    expect(screen.getByTestId('manual-result-status')).toHaveTextContent('no lookup')
  })

  // 9. Safe API error rendering
  it('safely displays backend HTTP 422 or 500 error messages', async () => {
    const user = userEvent.setup()
    TI.manualLookup.mockRejectedValueOnce(
      new ApiError(422, "Invalid IP address: 'not-an-ip'. Must be a valid IPv4 or IPv6 address."),
    )

    renderWithProviders(<ThreatIntelPage />)

    const input = screen.getByTestId('manual-lookup-input')
    const button = screen.getByTestId('manual-lookup-button')

    await user.type(input, 'not-an-ip')
    await user.click(button)

    await waitFor(() => {
      expect(screen.getByTestId('manual-lookup-error')).toBeInTheDocument()
    })
    expect(screen.getByTestId('manual-lookup-error')).toHaveTextContent(
      "Invalid IP address: 'not-an-ip'",
    )
  })

  // 10. Existing search behavior remains unchanged
  it('preserves existing search and filter functionality on indicators list', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ThreatIntelPage />)

    // Form for search is separate from manual lookup
    const searchInput = screen.getByRole('textbox', { name: /search indicators/i })
    const searchButton = screen.getByRole('button', { name: /^search$/i })

    await user.type(searchInput, '8.8.8.8')
    await user.click(searchButton)

    expect(TI.listIndicators).toHaveBeenCalledWith(1, 50, undefined, '8.8.8.8')
    expect(TI.manualLookup).not.toHaveBeenCalled()
  })

  // 11. Indicator list refresh after success
  it('refreshes the indicators list when a manual lookup succeeds', async () => {
    const user = userEvent.setup()
    const mockResponse: ManualLookupResponse = {
      indicator_id: '12345678-1234-5678-1234-567812345678',
      indicator_type: 'ip',
      normalized_indicator_value: '9.9.9.9',
      canonical_key: 'ip:9.9.9.9',
      status: 'enriched',
      providers_attempted: 1,
      providers_succeeded: 1,
      providers_failed: 0,
      providers_skipped: 0,
      is_new_indicator: true,
      results: [
        {
          provider: 'VirusTotal',
          status: 'success',
          found: true,
          performed_at: '2026-10-01T12:00:00Z',
        },
      ],
    }
    TI.manualLookup.mockResolvedValueOnce(mockResponse)

    renderWithProviders(<ThreatIntelPage />)

    // Initially called once on mount
    expect(TI.listIndicators).toHaveBeenCalledTimes(1)

    const input = screen.getByTestId('manual-lookup-input')
    const button = screen.getByTestId('manual-lookup-button')

    await user.type(input, '9.9.9.9')
    await user.click(button)

    await waitFor(() => {
      expect(screen.getByTestId('manual-lookup-results')).toBeInTheDocument()
    })

    // After success, query cache invalidation causes listIndicators to be called again
    await waitFor(() => {
      expect(TI.listIndicators).toHaveBeenCalledTimes(2)
    })
  })
})
