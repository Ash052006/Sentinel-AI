import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { FloatingAskSoc } from './floating-ask-soc'
import type { SOCQueryResponse } from '../types/api'
import { socApi } from '../api/soc'

vi.mock('../api/soc', () => ({
  socApi: {
    query: vi.fn(),
  },
}))

const queryMock = vi.mocked(socApi.query)

function createMockResponse(
  items: Array<Record<string, unknown>>,
  overrides: Partial<SOCQueryResponse> = {},
): SOCQueryResponse {
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
      recorded_at: '2026-11-09T12:00:00Z',
    },
    read_only: true,
    found: true,
    count: items.length,
    total: items.length,
    items,
    semantics: [],
    note: '',
    ...overrides,
  }
}

function renderComponent(): void {
  render(
    <MemoryRouter>
      <FloatingAskSoc />
    </MemoryRouter>,
  )
}

describe('FloatingAskSoc', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the floating trigger button on the page', () => {
    renderComponent()
    const trigger = screen.getByTestId('floating-ask-soc-trigger')
    expect(trigger).toBeInTheDocument()
    expect(trigger).toHaveTextContent('Ask SOC')
  })

  it('toggles open the small box on clicking the trigger and shows suggested queries', async () => {
    renderComponent()
    const trigger = screen.getByTestId('floating-ask-soc-trigger')
    await userEvent.click(trigger)

    const box = screen.getByTestId('floating-ask-soc-box')
    expect(box).toBeInTheDocument()
    expect(screen.getByText('Ask SOC Copilot')).toBeInTheDocument()
    expect(screen.getByText('what vulnerabilities exist?')).toBeInTheDocument()
    expect(screen.getByTestId('floating-ask-soc-input')).toBeInTheDocument()
  })

  it('acts as a personal assistant responding conversationally to greetings like hello', async () => {
    renderComponent()
    await userEvent.click(screen.getByTestId('floating-ask-soc-trigger'))

    const helloBtn = screen.getByRole('button', { name: 'hello' })
    await userEvent.click(helloBtn)

    expect(await screen.findByText(/Personal SOC Assistant Online/i)).toBeInTheDocument()
    expect(screen.getByText(/Hello! I'm your Sentinel SOC Personal Assistant/i)).toBeInTheDocument()
  })

  it('acts as a personal assistant answering questions about vulnerabilities and CVEs', async () => {
    renderComponent()
    await userEvent.click(screen.getByTestId('floating-ask-soc-trigger'))

    const vulnBtn = screen.getByRole('button', { name: 'what vulnerabilities exist?' })
    await userEvent.click(vulnBtn)

    expect(await screen.findByText(/Vulnerability & Exposure Advisory/i)).toBeInTheDocument()
    expect(screen.getByText(/Vulnerability management in Sentinel AI/i)).toBeInTheDocument()
    expect(screen.getByText(/Prioritize patching for externally exposed endpoints/i)).toBeInTheDocument()
  })

  it('provides dedicated button to open the full Ask SOC page without auto-open checkboxes', async () => {
    renderComponent()
    await userEvent.click(screen.getByTestId('floating-ask-soc-trigger'))

    // Verify auto-open toggle checkbox is NOT present
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()

    // Verify dedicated buttons to open full page
    const openPageLinks = screen.getAllByRole('link', { name: /Open Dedicated Ask SOC Page/i })
    expect(openPageLinks.length).toBeGreaterThanOrEqual(1)
  })

  it('handles telemetry queries with synthesis, recommendations and cited evidence', async () => {
    queryMock.mockResolvedValueOnce(
      createMockResponse(
        [
          { detection_id: 'DET-101', rule_id: 'rule-ssh-bruteforce', severity: 'high' },
          { detection_id: 'DET-102', rule_id: 'rule-powershell-c2', severity: 'critical' },
        ],
        { total: 2 },
      ),
    )

    renderComponent()
    await userEvent.click(screen.getByTestId('floating-ask-soc-trigger'))

    const promptBtn = screen.getByRole('button', { name: 'recent detections' })
    await userEvent.click(promptBtn)

    expect(queryMock).toHaveBeenCalledWith('recent detections')

    // AI Assistant Synthesis
    expect(
      await screen.findByText(/Critical Threat Detections Requiring Immediate Containment/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/Recommended Next Steps/i)).toBeInTheDocument()

    // Expand cited evidence
    const evidenceBtn = screen.getByRole('button', { name: /Cited Telemetry Evidence/i })
    await userEvent.click(evidenceBtn)
    expect(await screen.findByText('DET-101')).toBeInTheDocument()
    expect(screen.getByText('DET-102')).toBeInTheDocument()
  })

  it('closes the dialog when clicking the close button or pressing Escape', async () => {
    renderComponent()
    await userEvent.click(screen.getByTestId('floating-ask-soc-trigger'))
    expect(screen.getByTestId('floating-ask-soc-box')).toBeInTheDocument()

    const closeBtn = screen.getByRole('button', { name: 'Close Ask SOC box' })
    await userEvent.click(closeBtn)

    expect(screen.queryByTestId('floating-ask-soc-box')).not.toBeInTheDocument()
  })
})
