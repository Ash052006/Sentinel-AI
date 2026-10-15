import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { DebatePage } from './debate-page'
import { renderWithProviders } from '../test/utils'
import { ApiError } from '../api/client'
import type { DebateSession } from '../types/api'

const CORR = '22222222-2222-4222-8222-222222222222'
const DEBATE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const DET = '33333333-3333-4333-8333-333333333333'
const EVENT = '11111111-1111-4111-8111-111111111111'

function ref(reference: string, kind: string, nodeId: string) {
  return { reference, entity_kind: kind, node_id: nodeId }
}

const SESSION: DebateSession = {
  debate_id: DEBATE,
  correlation_id: CORR,
  status: 'completed',
  agents: [
    {
      agent_id: 'agent:detection_analyst',
      role: 'detection_analyst',
      display_name: 'Detection Analyst',
      objective: 'Establish what the detections show.',
      focus_node_types: ['DETECTION'],
    },
    {
      agent_id: 'agent:skeptic',
      role: 'skeptic',
      display_name: 'Skeptic / Contrarian',
      objective: 'Challenge the leading reading.',
      focus_node_types: [],
    },
  ],
  facts: [
    {
      fact_id: 'fact-1',
      claim_kind: 'fact',
      statement: 'The correlation contains 2 persisted detections.',
      evidence_references: [ref(`correlation:${CORR}`, 'CORRELATION', 'n-corr')],
      provenance: 'correlated',
    },
  ],
  assessments: [
    {
      agent_id: 'agent:detection_analyst',
      role: 'detection_analyst',
      objective: 'Establish what the detections show.',
      observations: [
        {
          claim_id: 'claim-1',
          claim_kind: 'observation',
          statement: 'Two detections were correlated into one incident.',
          evidence_references: [
            ref(`detection:${DET}`, 'DETECTION', 'n-det'),
          ],
          confidence: 0.8,
          provenance: 'ai_generated',
          author_role: 'detection_analyst',
        },
      ],
      hypotheses: [
        {
          claim_id: 'claim-2',
          claim_kind: 'hypothesis',
          statement: 'The host is beaconing to an uncommon destination.',
          evidence_references: [
            ref(`detection:${DET}`, 'DETECTION', 'n-det'),
          ],
          confidence: 0.6,
          provenance: 'ai_generated',
          author_role: 'detection_analyst',
        },
      ],
      confidence: 0.75,
      evidence_references: [ref(`detection:${DET}`, 'DETECTION', 'n-det')],
      limitations: ['No process telemetry was available.'],
      provenance: 'ai_generated',
    },
  ],
  arguments: [
    {
      argument_id: 'arg-1',
      round_kind: 'round_2_cross_agent_arguments',
      author_agent_id: 'agent:skeptic',
      author_role: 'skeptic',
      target_agent_id: 'agent:detection_analyst',
      target_role: 'detection_analyst',
      target_hypothesis_id: 'claim-2',
      stance: 'supports',
      statement: 'The beacon interval is regular enough to support the reading.',
      evidence_references: [ref(`detection:${DET}`, 'DETECTION', 'n-det')],
      provenance: 'ai_generated',
    },
  ],
  counterarguments: [
    {
      counterargument_id: 'counter-1',
      round_kind: 'round_3_counterarguments',
      author_agent_id: 'agent:skeptic',
      author_role: 'skeptic',
      target_argument_id: 'arg-1',
      weakness: 'missing_evidence',
      statement: 'No DNS logs were supplied to corroborate the beacon claim.',
      evidence_references: [
        ref(`event_reference:${EVENT}`, 'EVENT', 'n-event'),
      ],
      provenance: 'ai_generated',
    },
  ],
  rounds: [
    {
      round_number: 0,
      round_kind: 'round_0_shared_evidence',
      summary: 'Shared bounded evidence assembled.',
      agent_ids: [],
      argument_ids: [],
      counterargument_ids: [],
    },
    {
      round_number: 1,
      round_kind: 'round_1_independent_assessments',
      summary: 'Five agents assessed the evidence independently.',
      agent_ids: ['agent:detection_analyst', 'agent:skeptic'],
      argument_ids: [],
      counterargument_ids: [],
    },
    {
      round_number: 4,
      round_kind: 'round_4_reconciliation',
      summary: 'Arguments reconciled deterministically.',
      agent_ids: [],
      argument_ids: ['arg-1'],
      counterargument_ids: ['counter-1'],
    },
  ],
  consensus: {
    state: 'partial_consensus',
    leading_hypothesis: 'The host is beaconing to an uncommon destination.',
    leading_hypothesis_id: 'claim-2',
    supporting_arguments: [
      {
        argument_id: 'arg-1',
        round_kind: 'round_2_cross_agent_arguments',
        author_agent_id: 'agent:skeptic',
        author_role: 'skeptic',
        target_agent_id: 'agent:detection_analyst',
        target_role: 'detection_analyst',
        target_hypothesis_id: 'claim-2',
        stance: 'supports',
        statement: 'The beacon interval is regular enough to support the reading.',
        evidence_references: [ref(`detection:${DET}`, 'DETECTION', 'n-det')],
        provenance: 'ai_generated',
      },
    ],
    opposing_arguments: [],
    consensus_strength: 0.6,
    confidence: 0.62,
    dissent: [
      {
        dissent_id: 'dissent-1',
        raised_by_role: 'skeptic',
        position: 'The beacon reading may be coincidental background traffic.',
        reason: 'missing_evidence',
        evidence_references: [],
        provenance: 'ai_generated',
      },
    ],
    unresolved_questions: ['Was the destination newly registered?'],
    evidence_gaps: ['DNS query logs'],
    evidence_references: [ref(`detection:${DET}`, 'DETECTION', 'n-det')],
    provenance: 'ai_generated',
  },
  evidence_scope: {
    correlation_id: CORR,
    graph_node_count: 3,
    graph_edge_count: 2,
    evidence_reference_count: 4,
    node_type_counts: { CORRELATION: 1, DETECTION: 2, EVENT: 1 },
    graph_truncated: false,
    graph_truncated_reason: null,
    unavailable_entity_types: {},
  },
  metadata: {
    provider: 'gemini',
    model: 'gemini-2.5-flash',
    engine_version: 'v3.23.0',
    configuration_digest: 'cfgdigest0000000000000000',
    graph_snapshot_digest: 'graphdigest00000000000000',
    graph_node_count: 3,
    graph_edge_count: 2,
    agent_count: 5,
    max_rounds: 4,
    observations_count: 5,
    hypotheses_count: 4,
    arguments_count: 1,
    counterarguments_count: 1,
    prompt_bytes: 4096,
    created_at: '2026-09-25T09:10:00Z',
    provenance: 'ai_generated',
  },
  limitations: ['Conclusions are AI reasoning, not evidence.'],
}

function renderRoute(path: string, pattern: string) {
  return renderWithProviders(
    <Routes>
      <Route path={pattern} element={<DebatePage />} />
    </Routes>,
    { route: path, entries: [path] },
  )
}

describe('DebatePage', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('runs the debate for a correlation and renders the consensus', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      new Response(JSON.stringify(SESSION), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    renderRoute(`/debates/correlation/${CORR}`, '/debates/correlation/:correlationId')

    expect(
      await screen.findByTestId('debate-leading-hypothesis'),
    ).toHaveTextContent('The host is beaconing to an uncommon destination.')

    // Consensus state is reported honestly as partial, never upgraded.
    expect(screen.getAllByText('partial consensus').length).toBeGreaterThan(0)
  })

  it('POSTs to the correlation-scoped endpoint rather than reading a stored debate', async () => {
    const calls: Array<{ url: string; method: string }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      calls.push({
        url: String(input),
        method: init?.method ?? 'GET',
      })
      return new Response(JSON.stringify(SESSION), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })

    renderRoute(`/debates/correlation/${CORR}`, '/debates/correlation/:correlationId')
    await screen.findByTestId('debate-leading-hypothesis')

    const post = calls.find((call) => call.method === 'POST')
    expect(post?.url).toBe(`/api/debates/${CORR}`)
  })

  it('reads a stored debate back from the debate id without re-running it', async () => {
    const calls: Array<{ url: string; method: string }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      calls.push({ url: String(input), method: init?.method ?? 'GET' })
      return new Response(JSON.stringify(SESSION), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })

    renderRoute(`/debates/${DEBATE}`, '/debates/:debateId')
    await screen.findByTestId('debate-leading-hypothesis')

    expect(calls.every((call) => call.method === 'GET')).toBe(true)
    expect(calls[0]?.url).toBe(`/api/debates/${DEBATE}`)
  })

  it('renders every claim with its evidence citations', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      new Response(JSON.stringify(SESSION), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    renderRoute(`/debates/${DEBATE}`, '/debates/:debateId')

    expect(await screen.findByTestId('debate-observation')).toHaveTextContent(
      'Two detections were correlated into one incident.',
    )
    expect(screen.getByTestId('debate-hypothesis')).toHaveTextContent(
      'The host is beaconing to an uncommon destination.',
    )
    // Citations are the V3.22 graph source references, verbatim.
    expect(screen.getAllByText(`detection:${DET}`).length).toBeGreaterThan(0)
    expect(screen.getByTestId('debate-facts')).toHaveTextContent(
      'The correlation contains 2 persisted detections.',
    )
  })

  it('surfaces dissent, unresolved questions and evidence gaps', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      new Response(JSON.stringify(SESSION), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    renderRoute(`/debates/${DEBATE}`, '/debates/:debateId')

    expect(
      await screen.findByText(
        'The beacon reading may be coincidental background traffic.',
      ),
    ).toBeInTheDocument()
    expect(screen.getByTestId('debate-unresolved')).toHaveTextContent(
      'Was the destination newly registered?',
    )
    expect(screen.getByTestId('debate-evidence-gaps')).toHaveTextContent(
      'DNS query logs',
    )
  })

  it('reports a provider outage as a failure and never renders a consensus', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      new Response(
        JSON.stringify({
          detail: {
            correlation_id: CORR,
            status: 'failed',
            failure_code: 'debate_provider_unavailable',
            detail: 'model provider is unavailable',
            provenance: 'ai_generated',
          },
        }),
        { status: 503, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    renderRoute(`/debates/correlation/${CORR}`, '/debates/correlation/:correlationId')

    await waitFor(() => expect(screen.getByTestId('debate-error')).toBeInTheDocument())
    expect(screen.queryByTestId('debate-leading-hypothesis')).toBeNull()
    // Assert the governed message itself, not the panel's static copy, which
    // also mentions an unavailable provider.
    expect(
      screen.getByText('model provider is unavailable (debate_provider_unavailable)'),
    ).toBeInTheDocument()
  })

  it('surfaces the backend detail for a failed debate', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      throw new ApiError(503, 'debate provider unavailable')
    })

    renderRoute(`/debates/${DEBATE}`, '/debates/:debateId')

    await waitFor(() =>
      expect(screen.getByTestId('debate-error')).toBeInTheDocument(),
    )
    expect(screen.getByText('debate provider unavailable')).toBeInTheDocument()
  })

  it('guides the user to pick a correlation when no target is in the route', () => {
    renderRoute('/debates', '/debates')

    expect(
      screen.getByText(/A debate is always scoped to a single correlation/),
    ).toBeInTheDocument()
  })
})