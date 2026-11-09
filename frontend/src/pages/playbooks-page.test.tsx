import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { PlaybooksPage } from './playbooks-page'
import { renderWithProviders } from '../test/utils'
import { ApiError } from '../api/client'
import type {
  Playbook,
  PlaybookAction,
  PlaybookEvidence,
  PlaybookListResult,
  PlaybookMetadata,
  PlaybookResult,
  PlaybookStep,
  PlaybookUncertainty,
} from '../types/api'

const CORR = '22222222-2222-4222-8222-222222222222'
const PLAYBOOK_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
const ACTION_ID = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
const DET = '33333333-3333-4333-8333-333333333333'
const DIGEST = 'a'.repeat(64)

function evidence(
  stance: 'supporting' | 'contradicting',
  reference: string,
  detail: string,
): PlaybookEvidence {
  return { source: 'detection', reference, stance, detail }
}

const ACTION: PlaybookAction = {
  action_id: ACTION_ID,
  action: 'isolate_endpoint',
  category: 'containment',
  target_type: 'endpoint',
  target_reference: 'host-42',
  target_basis: 'The correlated detection names a resolvable endpoint.',
  capability: 'available',
  execution_backend: 'mock_sandbox',
  approval: {
    requirement: 'approval_required',
    reason: 'Isolation is disruptive and needs human authorization.',
    authorized_roles: ['admin', 'ciso'],
    provenance: 'ai_generated',
  },
  rollback: {
    rollback_supported: true,
    rollback_action: 'restore_endpoint',
    reason: 'Isolation is reversed by restoring connectivity.',
  },
  risk_level: 'high',
  expected_outcome: 'The endpoint stops communicating with the network.',
  verification_required: true,
  verification_method: 'Confirm the endpoint is absent from flow logs.',
  priority: 'high',
  confidence: 0.72,
  confidence_band: 'high',
  confidence_basis: {
    evidence_support: 0.8,
    target_certainty: 0.7,
    prediction_support: 0.6,
    debate_agreement: 0.7,
    capability_availability: 1.0,
    contradiction_penalty: 0.1,
    evidence_gap_penalty: 0.2,
  },
  evidence: [
    evidence('supporting', `detection:${DET}`, 'Detection names the endpoint.'),
    evidence('contradicting', `correlation:${CORR}`, 'Only one source was available.'),
  ],
  rationale: {
    summary: 'The correlated detection isolates a single compromised endpoint.',
    grounding: 'established_evidence',
    grounding_detail: 'A persisted detection established the compromise.',
    priority_reason: 'Containment is prioritized over investigation.',
    prediction_reference: null,
    debate_reference: null,
    provenance: 'ai_generated',
  },
  prerequisites: [],
  depends_on: [],
  provenance: 'ai_generated',
}

const STEP: PlaybookStep = {
  step_number: 1,
  name: 'Contain the endpoint',
  purpose: 'Stop the spread while evidence is preserved.',
  actions: [ACTION],
  depends_on_steps: [],
}

const PLAYBOOK: Playbook = {
  playbook_id: PLAYBOOK_ID,
  correlation_id: CORR,
  status: 'proposed',
  lifecycle: 'approval_required',
  steps: [STEP],
  limitations: [],
  provenance: 'ai_generated',
}

const UNCERTAINTY: PlaybookUncertainty = {
  confidence: 0.72,
  confidence_band: 'high',
  confidence_basis: {
    evidence_support: 0.8,
    target_certainty: 0.7,
    prediction_support: 0.6,
    debate_agreement: 0.7,
    capability_availability: 1.0,
    contradiction_penalty: 0.1,
    evidence_gap_penalty: 0.2,
  },
  supporting_evidence_count: 1,
  contradicting_evidence_count: 1,
  evidence_gaps: ['No endpoint telemetry was available.'],
  unresolved_questions: ['Was the destination host already compromised?'],
  conflicting_claims: ['The skeptic disputed the isolation target.'],
  provenance: 'ai_generated',
}

const METADATA: PlaybookMetadata = {
  engine_version: 'v3.25.0',
  playbook_configuration_digest: DIGEST,
  graph_snapshot_digest: DIGEST,
  debate_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  debate_consensus_state: 'partial_consensus',
  prediction_session_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  prediction_status: 'PREDICTED',
  prediction_count: 1,
  graph_node_count: 42,
  graph_edge_count: 91,
  target_count: 1,
  max_depth: 2,
  candidate_provider: null,
  candidate_model: null,
  candidate_proposed_count: 0,
  candidate_accepted_count: 0,
  candidate_rejected_count: 0,
  unavailable_inputs: { attack_mappings: 'no persisted mapping rows' },
  limitations: [],
  provenance: 'ai_generated',
}

const RESULT: PlaybookResult = {
  playbook_id: PLAYBOOK_ID,
  correlation_id: CORR,
  status: 'proposed',
  lifecycle: 'approval_required',
  playbook: PLAYBOOK,
  uncertainty: UNCERTAINTY,
  current_state: [
    evidence('supporting', `correlation:${CORR}`, 'Persisted correlation anchoring the proposal.'),
  ],
  metadata: METADATA,
  limitations: [
    {
      kind: 'containment_limited_to_evidence',
      detail: 'Containment is scoped to the evidence that established the target.',
    },
  ],
  execution_note:
    'This playbook is a proposal. It has not been approved and has not been executed.',
  provenance: 'ai_generated',
}

const INSUFFICIENT: PlaybookResult = {
  ...RESULT,
  status: 'insufficient_evidence',
  lifecycle: 'proposed',
  playbook: { ...PLAYBOOK, status: 'insufficient_evidence', lifecycle: 'proposed', steps: [] },
  uncertainty: { ...UNCERTAINTY, supporting_evidence_count: 0, contradicting_evidence_count: 0 },
  current_state: [],
  metadata: {
    ...METADATA,
    prediction_count: 0,
    unavailable_inputs: {
      attack_mappings: 'no persisted mapping rows',
      debate: 'the persisted debate was produced from a different graph snapshot',
      prediction: 'the persisted prediction session contains no predictions',
    },
  },
  limitations: [
    { kind: 'input_source_unavailable', detail: 'No persisted source justified a response action.' },
  ],
}

const LIST: PlaybookListResult = {
  correlation_id: CORR,
  playbooks: [
    {
      playbook_id: PLAYBOOK_ID,
      correlation_id: CORR,
      status: 'proposed',
      lifecycle: 'approval_required',
      action_count: 1,
      step_count: 1,
      approval_required_count: 1,
      not_executable_count: 0,
      confidence: 0.72,
      prediction_session_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      provenance: 'ai_generated',
    },
  ],
  provenance: 'ai_generated',
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/**
 * The correlation view fires two requests at once — the generate POST and the
 * stored-proposals list GET — so the mock routes on the URL rather than
 * answering every call with one body.
 */
function mockRoutes(result: unknown, list: unknown = LIST) {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input)
    if (url.startsWith('/api/playbooks/correlation/')) return json(list)
    return json(result)
  })
}

function renderRoute(path: string, pattern: string) {
  return renderWithProviders(
    <Routes>
      <Route path={pattern} element={<PlaybooksPage />} />
    </Routes>,
    { route: path, entries: [path] },
  )
}

describe('PlaybooksPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('generates a proposal for a correlation and renders the actions', async () => {
    mockRoutes(RESULT)

    renderRoute(
      `/playbooks/correlation/${CORR}`,
      '/playbooks/correlation/:correlationId',
    )

    expect(await screen.findByTestId('playbook-action-target')).toHaveTextContent(
      'host-42',
    )
    expect(screen.getByTestId('playbook-action-type')).toHaveTextContent(
      'isolate endpoint',
    )
    // A disruptive action is always marked as needing human authorization.
    const action = screen.getByTestId('playbook-action')
    expect(within(action).getByText('approval required')).toBeInTheDocument()
    expect(screen.getByTestId('playbook-rollback-supported')).toBeInTheDocument()
  })

  it('POSTs to the correlation-scoped endpoint without sending a playbook body', async () => {
    const calls: Array<{ url: string; method: string; body: unknown }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      calls.push({ url, method: init?.method ?? 'GET', body: init?.body })
      if (url.startsWith('/api/playbooks/correlation/')) return json(LIST)
      return json(RESULT)
    })

    renderRoute(
      `/playbooks/correlation/${CORR}`,
      '/playbooks/correlation/:correlationId',
    )
    await screen.findByTestId('playbook-action-target')

    const post = calls.find((call) => call.method === 'POST')
    expect(post?.url).toBe(`/api/playbooks/${CORR}`)
    // The client may ask for a proposal but cannot define one.
    expect(post?.body ?? null).toBeNull()
  })

  it('reads a stored proposal back from the playbook id without re-running it', async () => {
    const calls: Array<{ url: string; method: string }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      calls.push({ url: String(input), method: init?.method ?? 'GET' })
      return json(RESULT)
    })

    renderRoute(`/playbooks/${PLAYBOOK_ID}`, '/playbooks/:playbookId')
    await screen.findByTestId('playbook-action-target')

    expect(calls.every((call) => call.method === 'GET')).toBe(true)
    expect(calls[0]?.url).toBe(`/api/playbooks/${PLAYBOOK_ID}`)
  })

  it('shows supporting and contradicting citations side by side', async () => {
    mockRoutes(RESULT)

    renderRoute(`/playbooks/${PLAYBOOK_ID}`, '/playbooks/:playbookId')
    await screen.findByTestId('playbook-action-target')

    const lists = screen.getAllByTestId('playbook-evidence-list')
    expect(lists).toHaveLength(2)
    expect(lists[0]).toHaveTextContent(`detection:${DET}`)
    // Opposition is rendered, never suppressed: a contested proposal must not
    // look like a confident one.
    expect(screen.getByText('contradicting')).toBeInTheDocument()
  })

  it('shows the deterministic confidence breakdown', async () => {
    mockRoutes(RESULT)

    renderRoute(`/playbooks/${PLAYBOOK_ID}`, '/playbooks/:playbookId')
    await screen.findByTestId('playbook-action-target')

    const basis = screen.getByTestId('playbook-confidence-basis')
    expect(basis).toHaveTextContent('evidence support')
    expect(basis).toHaveTextContent('target certainty')
    expect(basis).toHaveTextContent('debate agreement')
    expect(basis).toHaveTextContent('contradiction penalty')
  })

  it('reports gaps, unresolved questions and conflicting claims', async () => {
    mockRoutes(RESULT)

    renderRoute(`/playbooks/${PLAYBOOK_ID}`, '/playbooks/:playbookId')
    await screen.findByTestId('playbook-action-target')

    expect(screen.getByTestId('playbook-evidence-gaps')).toHaveTextContent(
      'No endpoint telemetry was available.',
    )
    expect(screen.getByTestId('playbook-unresolved')).toHaveTextContent(
      'Was the destination host already compromised?',
    )
    expect(screen.getByTestId('playbook-conflicting-claims')).toHaveTextContent(
      'The skeptic disputed the isolation target.',
    )
  })

  it('states that the proposal has never been executed', async () => {
    mockRoutes(RESULT)

    renderRoute(`/playbooks/${PLAYBOOK_ID}`, '/playbooks/:playbookId')
    await screen.findByTestId('playbook-action-target')

    expect(screen.getByTestId('playbook-execution-note')).toHaveTextContent(
      /not been approved and has not been executed/i,
    )
  })

  it('renders insufficient evidence as a successful answer, not a failure', async () => {
    mockRoutes(INSUFFICIENT)

    renderRoute(
      `/playbooks/correlation/${CORR}`,
      '/playbooks/correlation/:correlationId',
    )

    expect(await screen.findByTestId('playbook-insufficient')).toBeInTheDocument()
    expect(screen.queryByTestId('playbook-error')).toBeNull()
    expect(screen.getByText('insufficient evidence')).toBeInTheDocument()
    expect(screen.getByText('returned without speculation')).toBeInTheDocument()
  })

  it('does not count reviewed graph entities as action support', async () => {
    mockRoutes({
      ...INSUFFICIENT,
      uncertainty: {
        ...INSUFFICIENT.uncertainty,
        supporting_evidence_count: 39,
      },
      metadata: { ...INSUFFICIENT.metadata, graph_node_count: 39 },
    })

    renderRoute(
      `/playbooks/correlation/${CORR}`,
      '/playbooks/correlation/:correlationId',
    )

    await screen.findByTestId('playbook-insufficient')
    const supporting = screen.getByText('Supporting').parentElement
    expect(supporting).not.toBeNull()
    expect(within(supporting as HTMLElement).getByText('0')).toBeInTheDocument()
    expect(screen.getByTestId('playbook-uncertainty-note')).toHaveTextContent(
      /39 entities were reviewed as input, not as action support/i,
    )
  })

  it('reports unavailable inputs instead of hiding them', async () => {
    mockRoutes(INSUFFICIENT)

    renderRoute(`/playbooks/${PLAYBOOK_ID}`, '/playbooks/:playbookId')
    await screen.findByTestId('playbook-insufficient')

    const inputs = screen.getByTestId('playbook-unavailable-inputs')
    expect(inputs).toHaveTextContent('attack_mappings')
    expect(inputs).toHaveTextContent('debate')
  })

  it('makes missing upstream artifacts actionable instead of only listing them', async () => {
    mockRoutes(INSUFFICIENT)

    renderRoute(
      `/playbooks/correlation/${CORR}`,
      '/playbooks/correlation/:correlationId',
    )

    const prerequisites = await screen.findByTestId('playbook-prerequisites')
    expect(prerequisites).toHaveTextContent(/never runs these steps automatically/i)
    expect(
      within(prerequisites).getByRole('link', { name: /run agent debate/i }),
    ).toHaveAttribute('href', `/debates/correlation/${CORR}`)
    expect(
      within(prerequisites).getByRole('link', { name: /run attack prediction/i }),
    ).toHaveAttribute('href', `/predictions/correlation/${CORR}`)
    expect(
      within(prerequisites).getByRole('button', { name: /regenerate proposal/i }),
    ).toBeInTheDocument()
  })

  it('routes a stored proposal to the current generation instead of re-running it', async () => {
    mockRoutes(INSUFFICIENT)

    renderRoute(`/playbooks/${PLAYBOOK_ID}`, '/playbooks/:playbookId')

    const prerequisites = await screen.findByTestId('playbook-prerequisites')
    expect(
      within(prerequisites).getByRole('link', {
        name: /generate current proposal/i,
      }),
    ).toHaveAttribute('href', `/playbooks/correlation/${CORR}`)
    expect(
      within(prerequisites).queryByRole('button', {
        name: /regenerate proposal/i,
      }),
    ).toBeNull()
  })

  it('lists the proposals already stored for the correlation', async () => {
    mockRoutes(RESULT)

    renderRoute(
      `/playbooks/correlation/${CORR}`,
      '/playbooks/correlation/:correlationId',
    )
    await screen.findByTestId('playbook-action-target')

    const list = await screen.findByTestId('playbook-list')
    expect(list).toHaveTextContent('1 actions')
    expect(list).toHaveTextContent('need approval')
    expect(
      screen.getByRole('link', { name: 'Open' }),
    ).toHaveAttribute('href', `/playbooks/${PLAYBOOK_ID}`)
  })

  it('reports a governed failure and never renders a proposal', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      json(
        {
          detail: {
            correlation_id: CORR,
            playbook_id: null,
            status: 'failed',
            failure_code: 'playbook_context_error',
            detail: 'no persisted graph exists for this correlation',
            provenance: 'ai_generated',
          },
        },
        404,
      ),
    )

    renderRoute(
      `/playbooks/correlation/${CORR}`,
      '/playbooks/correlation/:correlationId',
    )

    await waitFor(() =>
      expect(screen.getByTestId('playbook-error')).toBeInTheDocument(),
    )
    expect(screen.queryByTestId('playbook-action')).toBeNull()
    expect(
      screen.getByText(/no persisted graph exists for this correlation/),
    ).toBeInTheDocument()
    // The governed code travels with the message so the UI never shows only a
    // bare status code for a structured failure.
    expect(screen.getByText(/playbook_context_error/)).toBeInTheDocument()
  })

  it('surfaces the backend detail for a missing proposal', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      throw new ApiError(404, 'playbook not found')
    })

    renderRoute(`/playbooks/${PLAYBOOK_ID}`, '/playbooks/:playbookId')

    await waitFor(() =>
      expect(screen.getByTestId('playbook-error')).toBeInTheDocument(),
    )
    expect(screen.getByText('playbook not found')).toBeInTheDocument()
  })

  it('guides the user to pick a correlation when no target is in the route', () => {
    renderRoute('/playbooks', '/playbooks')

    expect(
      screen.getByText(/A playbook is always scoped to a single correlation/),
    ).toBeInTheDocument()
  })
})
