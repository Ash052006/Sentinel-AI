import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { DataIngestPage } from './data-ingest-page'
import { renderWithProviders } from '../test/utils'
import { ingestApi, type IngestFormat, type IngestSummary } from '../api/ingest'
import { ApiError } from '../api/client'

const FORMAT: IngestFormat = {
  description: 'One JSON object per line.',
  content_type: 'application/x-ndjson',
  required_fields: [
    { name: 'timestamp', required: true, description: 'ISO-8601.' },
    { name: 'source', required: true, description: 'Host.' },
    { name: 'source_type', required: true, description: 'Category.' },
    { name: 'event_type', required: true, description: 'Class.' },
  ],
  optional_fields: [
    { name: 'action', required: false, description: 'Free text.' },
  ],
  source_types: ['operating_system', 'network'],
  event_categories: ['authentication', 'process'],
  recognized_event_types: [
    { event_type: 'logon', event_category: 'authentication' },
    { event_type: 'process_creation', event_category: 'process' },
  ],
  notes: ['event_type decides the normalized event_category.'],
  example_lines: ['{"timestamp":"2026-09-27T10:00:00+00:00"}'],
}

const SUMMARY: IngestSummary = {
  total_records: 3,
  accepted_events: 2,
  rejected_records: 1,
  events_processed: 2,
  detections: 1,
  events_with_detections: 1,
  detection_results_created: 1,
  rule_failures: 2,
  active_rule_count: 53,
  errors: [{ line_number: 3, reason: 'Invalid JSON: JSONDecodeError' }],
  truncated_errors: false,
  duration_ms: 412,
}

/**
 * Verbatim capture of a real `POST /api/ingest/events` response body for
 * `backend/sample_events.jsonl` (first three lines, counters relaxed).
 *
 * Produced by the live backend -- FileLogCollector -> NormalizationAgent --
 * so these assertions check that the page renders the actual
 * NormalizationAgent output rather than a hand-written approximation.
 */
const SUMMARY_WITH_TRACE: IngestSummary = {
  total_records: 6,
  accepted_events: 6,
  rejected_records: 0,
  events_processed: 6,
  detections: 0,
  events_with_detections: 0,
  detection_results_created: 0,
  rule_failures: 0,
  active_rule_count: 53,
  errors: [],
  truncated_errors: false,
  truncated_events: false,
  duration_ms: 412,
  events: [
    {
      event_id: 'ddacb151-c62b-4e0f-bfea-b83369417957',
      line_number: 1,
      raw_event: {
        timestamp: '2026-09-27T10:00:00+00:00',
        source: 'windows-dc01',
        source_type: 'operating_system',
        event_type: 'logon',
        action: 'network logon attempt',
        outcome: 'failure',
        actor: 'CONTOSO\\jdoe',
        normalized_data: { logon_type: 3 },
        TargetUserName: 'jdoe',
      },
      normalized_event: {
        event_id: 'ddacb151-c62b-4e0f-bfea-b83369417957',
        timestamp: '2026-09-27T10:00:00Z',
        event_category: 'authentication',
        action: 'network logon attempt',
        outcome: 'failure',
        source: 'windows-dc01',
        source_type: 'operating_system',
        actor: { user_id: null, username: 'jdoe', domain: null },
        source_endpoint: null,
        destination_endpoint: null,
        process: null,
        file: null,
        normalized_data: { logon_type: 3 },
        provenance: 'observed',
      },
      provenance: 'observed',
    },
    {
      event_id: 'a82fbbf3-1a46-4681-b2e5-e93d0625d245',
      line_number: 2,
      raw_event: {
        timestamp: '2026-09-27T10:04:31+00:00',
        source: 'windows-dc01',
        source_type: 'operating_system',
        event_type: 'logon',
        action: 'network logon attempt',
        outcome: 'failure',
        actor: 'CONTOSO\\admin',
        normalized_data: { logon_type: 3 },
        TargetUserName: 'admin',
      },
      normalized_event: {
        event_id: 'a82fbbf3-1a46-4681-b2e5-e93d0625d245',
        timestamp: '2026-09-27T10:04:31Z',
        event_category: 'authentication',
        action: 'network logon attempt',
        outcome: 'failure',
        source: 'windows-dc01',
        source_type: 'operating_system',
        actor: { user_id: null, username: 'admin', domain: null },
        source_endpoint: null,
        destination_endpoint: null,
        process: null,
        file: null,
        normalized_data: { logon_type: 3 },
        provenance: 'observed',
      },
      provenance: 'observed',
    },
    {
      event_id: 'd1930fc5-4db3-4aff-ab1a-10af9e9286c5',
      line_number: 3,
      raw_event: {
        timestamp: '2026-09-27T10:09:02+00:00',
        source: 'windows-ws07',
        source_type: 'operating_system',
        event_type: 'process_creation',
        action:
          'powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA==',
        outcome: 'success',
        actor: 'CONTOSO\\jdoe',
        NewProcessName:
          'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine:
          'powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA==',
      },
      normalized_event: {
        event_id: 'd1930fc5-4db3-4aff-ab1a-10af9e9286c5',
        timestamp: '2026-09-27T10:09:02Z',
        event_category: 'process',
        action:
          'powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA==',
        outcome: 'success',
        source: 'windows-ws07',
        source_type: 'operating_system',
        actor: null,
        source_endpoint: null,
        destination_endpoint: null,
        process: {
          name: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
          pid: null,
          command_line:
            'powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA==',
          executable:
            'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
          parent_process: null,
        },
        file: null,
        normalized_data: {},
        provenance: 'observed',
      },
      provenance: 'observed',
    },
  ],
}

function makeFile(name = 'events.jsonl', contents = '{}\n') {
  return new File([contents], name, { type: 'application/x-ndjson' })
}

vi.mock('../api/ingest', () => ({
  ingestApi: {
    format: vi.fn(),
    events: vi.fn(),
  },
}))

function renderPage() {
  return renderWithProviders(
    <Routes>
      <Route path="/data-ingest" element={<DataIngestPage />} />
      <Route path="/detections" element={<div>detections view</div>} />
    </Routes>,
    { route: '/data-ingest', entries: ['/data-ingest'] },
  )
}

/** Uploads a file and waits for the run to finish rendering. */
async function ingest() {
  const user = userEvent.setup()
  renderPage()
  const input = await screen.findByTestId('ingest-input')
  await user.upload(input, makeFile('sample_events.jsonl'))
  await user.click(screen.getByTestId('ingest-submit'))
  return user
}

describe('DataIngestPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(ingestApi.format).mockResolvedValue(FORMAT)
    vi.mocked(ingestApi.events).mockResolvedValue(SUMMARY)
  })

  it('renders the format contract returned by the backend', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('operating_system')).toBeTruthy()
    })
    expect(screen.getByText(/ISO-8601/)).toBeTruthy()
    expect(screen.getByText('process_creation')).toBeTruthy()
    expect(screen.getByText('logon')).toBeTruthy()
    expect(ingestApi.format).toHaveBeenCalledTimes(1)
  })

  it('uploads the chosen file and reports the run summary', async () => {
    const user = userEvent.setup()
    renderPage()

    const input = await screen.findByTestId('ingest-input')
    await user.upload(input, makeFile())

    await user.click(screen.getByTestId('ingest-submit'))

    await waitFor(() => {
      expect(ingestApi.events).toHaveBeenCalledTimes(1)
    })
    expect(vi.mocked(ingestApi.events).mock.calls[0][0].name).toBe('events.jsonl')

    const result = await screen.findByTestId('ingest-result')
    expect(result.textContent).toContain('412 ms')
    expect(result.textContent).toContain('53')
    expect(screen.getByText('Invalid JSON: JSONDecodeError')).toBeTruthy()
  })

  it('surfaces the API error message when the upload is rejected', async () => {
    vi.mocked(ingestApi.events).mockRejectedValue(
      new ApiError(422, 'File is empty.'),
    )
    const user = userEvent.setup()
    renderPage()

    await user.upload(await screen.findByTestId('ingest-input'), makeFile())
    await user.click(screen.getByTestId('ingest-submit'))

    await waitFor(() => {
      expect(screen.getByText('File is empty.')).toBeTruthy()
    })
    expect(screen.queryByTestId('ingest-result')).toBeNull()
  })

  it('clears the selection and resets the summary', async () => {
    const user = userEvent.setup()
    renderPage()

    await user.upload(await screen.findByTestId('ingest-input'), makeFile())
    await user.click(screen.getByTestId('ingest-submit'))
    await screen.findByTestId('ingest-result')

    await user.click(screen.getByTestId('ingest-clear'))

    await waitFor(() => {
      expect(screen.queryByTestId('ingest-result')).toBeNull()
    })
    expect(screen.queryByText('events.jsonl')).toBeNull()
  })
})

describe('DataIngestPage normalization trace', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(ingestApi.format).mockResolvedValue(FORMAT)
    vi.mocked(ingestApi.events).mockResolvedValue(SUMMARY_WITH_TRACE)
  })

  it('lists one selectable row per event returned by the backend', async () => {
    await ingest()

    const rows = await screen.findAllByTestId('ingest-event-row')
    expect(rows).toHaveLength(3)
    expect(rows[0].textContent).toContain('windows-dc01')
    expect(rows[0].textContent).toContain('logon')
    expect(rows[0].textContent).toContain('authentication')
    expect(rows[0].textContent).toContain('observed')
    expect(rows[2].textContent).toContain('process_creation')
    expect(rows[2].textContent).toContain('process')
  })

  it('renders the raw event exactly as the backend returned it', async () => {
    await ingest()

    const panel = await screen.findByTestId('ingest-raw-panel')
    const raw = SUMMARY_WITH_TRACE.events![0].raw_event
    expect(within(panel).getByText('source')).toBeTruthy()
    expect(within(panel).getByText(String(raw.source))).toBeTruthy()
    expect(within(panel).getByText(String(raw.source_type))).toBeTruthy()
    expect(within(panel).getByText(String(raw.event_type))).toBeTruthy()
    expect(within(panel).getByText(String(raw.actor))).toBeTruthy()
    expect(within(panel).getByText(String(raw.action))).toBeTruthy()
    expect(within(panel).getByText(String(raw.outcome))).toBeTruthy()
    // Source-specific key the agent maps into actor.username
    expect(within(panel).getByText('TargetUserName')).toBeTruthy()
    expect(within(panel).getByText(String(raw.TargetUserName))).toBeTruthy()
  })

  it('renders the normalized event returned by the NormalizationAgent', async () => {
    const user = await ingest()
    await user.click(await screen.findByTestId('ingest-tab-normalized'))

    const panel = await screen.findByTestId('ingest-normalized-panel')
    const normalized = SUMMARY_WITH_TRACE.events![0].normalized_event
    const field = (name: string) =>
      panel.querySelector(`[data-normalized-field="${name}"]`)?.textContent

    expect(field('event_id')).toBe(normalized.event_id)
    expect(field('timestamp')).toBe('2026-09-27 10:00:00Z')
    expect(field('event_category')).toBe('authentication')
    expect(field('action')).toBe('network logon attempt')
    expect(field('outcome')).toBe('failure')
    expect(field('source')).toBe('windows-dc01')
    expect(field('source_type')).toBe('operating_system')
    expect(field('provenance')).toBe('observed')
  })

  it('renders nested normalized fields as readable structure', async () => {
    const user = await ingest()
    await user.click(await screen.findByTestId('ingest-tab-normalized'))
    await screen.findByTestId('ingest-normalized-panel')

    const actor = screen.getByTestId('ingest-entity-actor')
    expect(within(actor).getByText('username')).toBeTruthy()
    expect(actor.textContent).toContain('user_id')
    expect(actor.textContent).toContain('domain')
    expect(actor.textContent).toContain('jdoe')
    expect(actor.textContent).toContain('null')

    const extras = screen.getByTestId('ingest-normalized-data')
    expect(extras.textContent).toContain('logon_type')
    expect(extras.textContent).toContain('3')
  })

  it('expands nested objects in the raw event on demand', async () => {
    const user = await ingest()
    const panel = await screen.findByTestId('ingest-raw-panel')

    const nested = panel.querySelector('[data-field="normalized_data"]')!
    expect(nested.textContent).toContain('{1}')
    expect(nested.textContent).not.toContain('logon_type')

    await user.click(within(nested as HTMLElement).getByRole('button'))
    expect(nested.textContent).toContain('logon_type')
    expect(nested.textContent).toContain('3')
  })

  it('shows entities the agent did not map as absent rather than invented', async () => {
    const user = await ingest()
    await user.click(await screen.findByTestId('ingest-tab-normalized'))
    await screen.findByTestId('ingest-normalized-panel')

    expect(
      screen.getByTestId('ingest-entity-source_endpoint').textContent,
    ).toContain('not present in the source event')
    expect(screen.getByTestId('ingest-entity-destination_endpoint').textContent)
      .toContain('not present in the source event')
    expect(screen.getByTestId('ingest-entity-file').textContent).toContain(
      'not present in the source event',
    )
  })

  it('renders the process entity for the process_creation event', async () => {
    const user = await ingest()
    const rows = await screen.findAllByTestId('ingest-event-row')
    await user.click(rows[2])
    await user.click(screen.getByTestId('ingest-tab-normalized'))

    const panel = await screen.findByTestId('ingest-normalized-panel')
    const process = screen.getByTestId('ingest-entity-process')
    const expected = SUMMARY_WITH_TRACE.events![2].normalized_event.process!
    expect(process.textContent).toContain('parent_process')
    expect(process.textContent).toContain(expected.name!)
    expect(process.textContent).toContain(expected.command_line!)
    expect(process.textContent).toContain(expected.executable!)
    expect(
      panel.querySelector('[data-normalized-field="event_category"]')
        ?.textContent,
    ).toBe('process')
  })

  it('switches the inspected event when another row is selected', async () => {
    const user = await ingest()
    await screen.findAllByTestId('ingest-event-row')

    expect(screen.getByTestId('ingest-raw-panel').textContent).toContain(
      'windows-dc01',
    )
    await user.click(screen.getAllByTestId('ingest-event-row')[1])
    expect(screen.getByTestId('ingest-raw-panel').textContent).toContain(
      'CONTOSO\\admin',
    )
  })

  it('displays the provenance reported by the backend', async () => {
    const user = await ingest()
    const rows = await screen.findAllByTestId('ingest-event-row')
    expect(rows[0].textContent).toContain('observed')
    // Normalizing an event must not be shown as a provenance change.
    expect(screen.queryByText('enriched')).toBeNull()
    expect(screen.queryByText('detected')).toBeNull()

    await user.click(screen.getByTestId('ingest-tab-provenance'))
    const panel = await screen.findByTestId('ingest-provenance-panel')
    expect(panel.textContent).toContain('observed')
    expect(panel.textContent).toContain('Both values in the response agree')
  })

  it('marks provenance as a field the raw record does not carry', async () => {
    await ingest()
    const table = await screen.findByTestId('ingest-summary-table')
    const row = table.querySelector('[data-summary-field="provenance"]')!
    expect(row.textContent).toContain('observed')
    expect(row.textContent).toContain('derived')
  })

  it('builds the transformation summary from the response alone', async () => {
    await ingest()
    const table = await screen.findByTestId('ingest-summary-table')
    const status = (field: string) =>
      table.querySelector(`[data-summary-field="${field}"]`)?.textContent ?? ''

    // Same identity in both halves of the response.
    expect(status('event_id')).toContain('ddacb151')
    expect(status('event_id')).toContain('preserved')
    // Raw says +00:00, normalized says Z -- the same instant, so preserved.
    expect(status('timestamp')).toContain('2026-09-27 10:00:00Z')
    expect(status('timestamp')).toContain('preserved')
    expect(status('source')).toContain('windows-dc01')
    expect(status('source')).toContain('preserved')
    expect(status('outcome')).toContain('failure')
    expect(status('outcome')).toContain('preserved')
    expect(status('raw_data')).toContain('9 field(s) retained')
    // The raw record carries no event_category; the agent classified it.
    expect(status('event_category')).toContain('authentication')
    expect(status('event_category')).toContain('derived')
  })

  it('names the backend stage that performed the transformation', async () => {
    await ingest()
    const agent = await screen.findByTestId('pipeline-agent')
    expect(agent.textContent).toContain('NormalizationAgent')
    const pipeline = agent.closest('[data-testid="ingest-transformation"]')!
    expect(pipeline.textContent).toContain('Raw security event')
    expect(pipeline.textContent).toContain('Normalized security event')
    expect(pipeline.textContent).toContain('Visualization only')
  })

  it('shows a loading state while the backend is processing', async () => {
    let release: (value: IngestSummary) => void = () => {}
    vi.mocked(ingestApi.events).mockReturnValue(
      new Promise<IngestSummary>((resolve) => {
        release = resolve
      }),
    )

    const user = await ingest()

    const loading = await screen.findByTestId('ingest-loading')
    expect(loading.textContent).toContain('Collecting and normalizing')
    expect(loading.textContent).toContain('FileLogCollector')
    expect(screen.queryByTestId('ingest-transformation')).toBeNull()

    release(SUMMARY_WITH_TRACE)
    await screen.findByTestId('ingest-transformation')
    expect(screen.queryByTestId('ingest-loading')).toBeNull()
    await user.click(screen.getByTestId('ingest-tab-raw'))
  })
})

describe('DataIngestPage honest empty states', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(ingestApi.format).mockResolvedValue(FORMAT)
  })

  it('reports no normalized event when every line was rejected', async () => {
    vi.mocked(ingestApi.events).mockResolvedValue({
      ...SUMMARY_WITH_TRACE,
      total_records: 2,
      accepted_events: 0,
      rejected_records: 2,
      events_processed: 0,
      errors: [
        { line_number: 1, reason: 'Invalid JSON' },
        { line_number: 2, reason: 'Invalid JSON' },
      ],
      events: [],
    })

    await ingest()

    expect(await screen.findByText('No event was normalized')).toBeTruthy()
    expect(screen.getByTestId('ingest-transformation').textContent).toContain(
      'normalized none',
    )
    expect(screen.queryAllByTestId('ingest-event-row')).toHaveLength(0)
  })

  it('reports that the trace is missing when the response omits it', async () => {
    vi.mocked(ingestApi.events).mockResolvedValue(SUMMARY)

    await ingest()

    const panel = await screen.findByTestId('ingest-transformation')
    expect(
      within(panel).getByText('Not available from ingestion response'),
    ).toBeTruthy()
    expect(panel.textContent).toContain('Required backend change')
    expect(panel.textContent).toContain('IngestSummary.events')
    // No event data may be synthesised to fill the gap.
    expect(panel.querySelector('[data-field="source"]')).toBeNull()
    expect(panel.textContent).not.toContain('windows-dc01')
  })

  it('hides the trace view after the run is cleared', async () => {
    vi.mocked(ingestApi.events).mockResolvedValue(SUMMARY_WITH_TRACE)
    const user = await ingest()
    await screen.findByTestId('ingest-transformation')

    await user.click(screen.getByTestId('ingest-clear'))

    await waitFor(() => {
      expect(screen.queryByTestId('ingest-transformation')).toBeNull()
    })
  })
})

describe('DataIngestPage renders no invented event data', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(ingestApi.format).mockResolvedValue(FORMAT)
  })

  it('shows only values present in the mocked backend response', async () => {
    vi.mocked(ingestApi.events).mockResolvedValue(SUMMARY_WITH_TRACE)
    const user = await ingest()
    const panel = await screen.findByTestId('ingest-transformation')

    // Every event in the response drives a row, using the values the
    // backend returned for source, category and outcome.
    const rows = within(panel).getAllByTestId('ingest-event-row')
    for (const [index, trace] of SUMMARY_WITH_TRACE.events!.entries()) {
      expect(rows[index].textContent).toContain(trace.normalized_event.source)
      expect(rows[index].textContent).toContain(
        trace.normalized_event.event_category,
      )
      expect(rows[index].textContent).toContain(trace.normalized_event.outcome)
      expect(rows[index].textContent).toContain(trace.provenance)
    }

    // The inspector shows the selected event's raw record verbatim.
    const raw = SUMMARY_WITH_TRACE.events![0].raw_event
    const rawPanel = screen.getByTestId('ingest-raw-panel')
    for (const value of Object.values(raw)) {
      if (value !== null && typeof value !== 'object') {
        expect(rawPanel.textContent).toContain(String(value))
      }
    }
    expect(rawPanel.textContent).toContain('9') // field count is shown too

    await user.click(screen.getByTestId('ingest-tab-normalized'))
    const normalizedPanel = screen.getByTestId('ingest-normalized-panel')
    expect(
      normalizedPanel.querySelector('[data-normalized-field="event_id"]')
        ?.textContent,
    ).toBe(SUMMARY_WITH_TRACE.events![0].normalized_event.event_id)
    expect(
      normalizedPanel.querySelector('[data-normalized-field="source"]')
        ?.textContent,
    ).toBe(SUMMARY_WITH_TRACE.events![0].normalized_event.source)
  })

  it('does not reuse a previous run’s event when the new run returns none', async () => {
    vi.mocked(ingestApi.events).mockResolvedValue(SUMMARY_WITH_TRACE)
    const user = await ingest()
    await screen.findAllByTestId('ingest-event-row')
    expect(screen.getByTestId('ingest-raw-panel').textContent).toContain(
      'windows-dc01',
    )

    vi.mocked(ingestApi.events).mockResolvedValue({
      ...SUMMARY_WITH_TRACE,
      total_records: 1,
      accepted_events: 0,
      events_processed: 0,
      events: [],
    })
    await user.click(screen.getByTestId('ingest-clear'))
    await user.upload(screen.getByTestId('ingest-input'), makeFile('second.jsonl'))
    await user.click(screen.getByTestId('ingest-submit'))

    expect(await screen.findByText('No event was normalized')).toBeTruthy()
    expect(screen.queryByTestId('ingest-raw-panel')).toBeNull()
    expect(document.body.textContent).not.toContain('windows-dc01')
  })
})
