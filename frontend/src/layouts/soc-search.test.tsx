import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { SocSearch } from './soc-search'
import type { SOCQueryResponse } from '../types/api'
import { socApi } from '../api/soc'

vi.mock('../api/soc', () => ({
  socApi: {
    query: vi.fn(),
  },
}))

const queryMock = vi.mocked(socApi.query)

function response(items: Array<Record<string, unknown>>, overrides: Partial<SOCQueryResponse> = {}): SOCQueryResponse {
  return {
    intent: {
      resource: 'detections',
      operation: 'recent',
      mode: 'recent_feed',
      target: {},
      filters: {},
      pagination: {},
    },
    metadata: {
      resource: 'detections',
      operation: 'recent',
      mode: 'recent_feed',
      page: null,
      page_size: null,
      limit: 50,
      applied_filters: [],
      parser_provider: 'test',
      parser_model: 'test',
      recorded_at: '2026-09-22T14:00:00Z',
    },
    read_only: true,
    found: true,
    count: 1,
    total: 42,
    items,
    semantics: [],
    note: '',
    ...overrides,
  }
}

function renderSearch(): void {
  render(
    <MemoryRouter>
      <SocSearch />
    </MemoryRouter>,
  )
}

describe('SocSearch', () => {
  it('routes a natural-language query to the read-only SOC querier and shows the results panel', async () => {
    queryMock.mockResolvedValueOnce(
      response([
        { detection_id: 'DET-1', rule_id: 'rule-web-01', severity: 'high', detected_at: 'x' },
      ]),
    )
    renderSearch()

    const input = screen.getByTestId('soc-search-input')
    await userEvent.type(input, '  show high risk detections  ')
    await userEvent.type(input, '{Enter}')

    expect(queryMock).toHaveBeenCalledWith('show high risk detections')

    const panel = await screen.findByTestId('soc-search-panel')
    expect(panel).toHaveTextContent('resource · detections')
    expect(panel).toHaveTextContent('op · recent')
    expect(panel).toHaveTextContent('mode · recent_feed')
    expect(panel).toHaveTextContent('1 of 42')
    expect(panel).toHaveTextContent('DET-1')
    expect(panel).toHaveTextContent('rule-web-01')
    expect(panel).toHaveTextContent('high')
    expect(screen.getByText('Open full results →')).toHaveAttribute(
      'href',
      '/search?q=show%20high%20risk%20detections',
    )
  })

  it('does not call the API for a blank query', async () => {
    renderSearch()
    await userEvent.type(screen.getByTestId('soc-search-input'), '{Enter}')
    expect(queryMock).not.toHaveBeenCalled()
  })

  it('shows the honest not-found state instead of fabricating data', async () => {
    queryMock.mockResolvedValueOnce(
      response([], {
        found: false,
        total: null,
        note: 'No matching records in the knowledge base.',
      }),
    )
    renderSearch()
    const input = screen.getByTestId('soc-search-input')
    await userEvent.type(input, 'something not in the data')
    await userEvent.type(input, '{Enter}')

    const panel = await screen.findByTestId('soc-search-panel')
    expect(panel).toHaveTextContent('No matching records in the knowledge base.')
  })

  it('surfaces provider errors in the panel', async () => {
    queryMock.mockRejectedValueOnce(new Error('backend unavailable'))
    renderSearch()
    const input = screen.getByTestId('soc-search-input')
    await userEvent.type(input, 'everything')
    await userEvent.type(input, '{Enter}')

    const panel = await screen.findByTestId('soc-search-panel')
    expect(panel).toHaveTextContent('backend unavailable')
  })

  it('closes the panel via the close button', async () => {
    queryMock.mockResolvedValueOnce(response([]))
    renderSearch()
    const input = screen.getByTestId('soc-search-input')
    await userEvent.type(input, 'incidents')
    await userEvent.type(input, '{Enter}')

    expect(await screen.findByTestId('soc-search-panel')).toBeInTheDocument()
    await userEvent.click(screen.getByLabelText('Close search results'))
    expect(screen.queryByTestId('soc-search-panel')).not.toBeInTheDocument()
  })
})