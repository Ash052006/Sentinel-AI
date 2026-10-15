import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { PredictionPage } from './prediction-page'
import { renderWithProviders } from '../test/utils'
import { ApiError } from '../api/client'
import type { AttackPrediction, PredictionResult } from '../types/api'

const CORR = '22222222-2222-4222-8222-222222222222'
const SESSION = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
const PRED = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const DET = '33333333-3333-4333-8333-333333333333'
const DIGEST = 'a'.repeat(64)

function evidence(stance: 'supporting' | 'contradicting', reference: string, detail: string) {
  return {
    reference,
    entity_kind: 'DETECTION',
    node_id: `n-${reference}`,
    stance,
    detail,
  }
}

const PREDICTION: AttackPrediction = {
  prediction_id: PRED,
  prediction_kind: 'LATERAL_MOVEMENT',
  depth: 'immediate',
  status: 'PREDICTED',
  target: 'Lateral movement',
  target_basis: 'persisted_attack_mapping',
  technique: {
    technique_id: 'T1021',
    technique_name: 'Remote Services',
    tactic: 'Lateral Movement',
    technique_id_reason: 'Persisted mapping on the correlated detection.',
  },
  rationale: {
    summary: 'The correlated detection resolves a remote-service mapping, making lateral movement the next stage.',
    basis: 'persisted_attack_mapping',
    basis_detail: 'Persisted mapping names lateral movement as a reachable successor.',
    observed_techniques: ['T1078'],
    debate_agreement: 0.7,
  },
  uncertainty: {
    confidence: 0.62,
    confidence_band: 'moderate',
    confidence_basis: {
      evidence_support: 0.9,
      evidence_diversity: 0.5,
      debate_support: 0.7,
      target_specificity: 0.8,
      contradiction_penalty: 0.1,
    },
    supporting_evidence: [
      evidence('supporting', `detection:${DET}`, 'Detection names the mapping.'),
    ],
    contradicting_evidence: [
      evidence('contradicting', `correlation:${CORR}`, 'Only one source was available.'),
    ],
    evidence_gaps: ['No endpoint telemetry was available.'],
    unresolved_questions: ['Was the destination host already compromised?'],
    evidence_support: 'mixed',
    limitations: [
      {
        kind: 'single_source_evidence',
        detail: 'Only one persisted source supported this projection.',
      },
    ],
  },
  provenance: 'ai_generated',
}

const RESULT: PredictionResult = {
  prediction_session_id: SESSION,
  correlation_id: CORR,
  status: 'PREDICTED',
  predictions: [PREDICTION],
  current_state: [
    {
      reference: `correlation:${CORR}`,
      entity_kind: 'CORRELATION',
      node_id: 'n-corr',
      stance: 'supporting',
      detail: 'Persisted correlation anchoring the projection.',
    },
  ],
  observed_techniques: ['T1078'],
  metadata: {
    engine_version: 'v3.24.0',
    prediction_configuration_digest: DIGEST,
    graph_snapshot_digest: DIGEST,
    debate_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    debate_consensus_state: 'partial_consensus',
    debate_provider: 'gemini',
    debate_model: 'gemini-2.5-pro',
    graph_node_count: 42,
    graph_edge_count: 91,
    observed_technique_count: 1,
    max_depth: 2,
    unavailable_inputs: { attack_mappings: 'no persisted mapping rows' },
    limitations: [
      { kind: 'no_persisted_attack_mapping', detail: 'No mapping rows were available.' },
    ],
  },
  limitations: [
    { kind: 'graph_truncated', detail: 'The bounded graph was truncated at 200 nodes.' },
  ],
  limitations_note:
    'This is a projection, not a finding. Nothing above should be treated as evidence without a persisted source.',
  provenance: 'ai_generated',
}

const INSUFFICIENT: PredictionResult = {
  ...RESULT,
  status: 'INSUFFICIENT_EVIDENCE',
  predictions: [],
  current_state: [],
  observed_techniques: [],
  metadata: {
    ...RESULT.metadata,
    observed_technique_count: 0,
    unavailable_inputs: {
      attack_mappings: 'no persisted mapping rows',
      debate: 'no debate was available',
    },
  },
  limitations: [
    { kind: 'input_source_unavailable', detail: 'No persisted source named a next stage.' },
  ],
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderRoute(path: string, pattern: string) {
  return renderWithProviders(
    <Routes>
      <Route path={pattern} element={<PredictionPage />} />
    </Routes>,
    { route: path, entries: [path] },
  )
}

describe('PredictionPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('runs a prediction for a correlation and renders the projection', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(RESULT))

    renderRoute(
      `/predictions/correlation/${CORR}`,
      '/predictions/correlation/:correlationId',
    )

    expect(await screen.findByTestId('prediction-target')).toHaveTextContent(
      'Lateral movement',
    )
    // "predicted" labels the outcome badge and the confidence band alike.
    expect(screen.getAllByText('predicted').length).toBeGreaterThan(0)
    expect(screen.getByText('next stage')).toBeInTheDocument()
  })

  it('POSTs to the correlation-scoped endpoint without sending a prediction body', async () => {
    const calls: Array<{ url: string; method: string; body: unknown }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      calls.push({
        url: String(input),
        method: init?.method ?? 'GET',
        body: init?.body,
      })
      return json(RESULT)
    })

    renderRoute(
      `/predictions/correlation/${CORR}`,
      '/predictions/correlation/:correlationId',
    )
    await screen.findByTestId('prediction-target')

    const post = calls.find((call) => call.method === 'POST')
    expect(post?.url).toBe(`/api/attack-predictions/${CORR}`)
    // The client may ask for a prediction but cannot define one.
    expect(post?.body ?? null).toBeNull()
  })

  it('reads a stored prediction back from the prediction id without re-running it', async () => {
    const calls: Array<{ url: string; method: string }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      calls.push({ url: String(input), method: init?.method ?? 'GET' })
      return json(RESULT)
    })

    renderRoute(`/predictions/${SESSION}`, '/predictions/:predictionId')
    await screen.findByTestId('prediction-target')

    expect(calls.every((call) => call.method === 'GET')).toBe(true)
    expect(calls[0]?.url).toBe(`/api/attack-predictions/${SESSION}`)
  })

  it('shows supporting and contradicting citations side by side', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(RESULT))

    renderRoute(`/predictions/${SESSION}`, '/predictions/:predictionId')
    await screen.findByTestId('prediction-target')

    // Two lists: supporting and contradicting.
    const lists = screen.getAllByTestId('prediction-evidence-list')
    expect(lists).toHaveLength(2)
    expect(lists[0]).toHaveTextContent(`detection:${DET}`)
    // Opposition is rendered, never suppressed: a contested projection must not
    // look like a confident one.
    expect(screen.getByText('contradicting')).toBeInTheDocument()
    expect(screen.getByText(/penalty −0.10/)).toBeInTheDocument()
  })

  it('shows the deterministic confidence breakdown', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(RESULT))

    renderRoute(`/predictions/${SESSION}`, '/predictions/:predictionId')
    await screen.findByTestId('prediction-target')

    const basis = screen.getByTestId('prediction-confidence-basis')
    expect(basis).toHaveTextContent('Evidence')
    expect(basis).toHaveTextContent('Diversity')
    expect(basis).toHaveTextContent('Debate')
    expect(basis).toHaveTextContent('Specificity')
    expect(basis).toHaveTextContent('Penalty')
  })

  it('labels the ATT&CK technique and always explains its presence or absence', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(RESULT))

    renderRoute(`/predictions/${SESSION}`, '/predictions/:predictionId')
    await screen.findByTestId('prediction-target')

    expect(screen.getByTestId('prediction-technique-id')).toHaveTextContent('T1021')
    expect(
      screen.getByText('Persisted mapping on the correlated detection.'),
    ).toBeInTheDocument()
  })

  it('explains an absent ATT&CK id rather than rendering a blank', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      json({
        ...RESULT,
        predictions: [
          {
            ...PREDICTION,
            technique: {
              technique_id: null,
              technique_name: null,
              tactic: null,
              technique_id_reason: 'No persisted detection named an ATT&CK technique.',
            },
          },
        ],
      }),
    )

    renderRoute(`/predictions/${SESSION}`, '/predictions/:predictionId')
    await screen.findByTestId('prediction-target')

    expect(screen.getByTestId('prediction-technique-absent')).toBeInTheDocument()
    expect(
      screen.getByText('No persisted detection named an ATT&CK technique.'),
    ).toBeInTheDocument()
  })

  it('surfaces evidence gaps, unresolved questions and limitations', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(RESULT))

    renderRoute(`/predictions/${SESSION}`, '/predictions/:predictionId')
    await screen.findByTestId('prediction-target')

    expect(screen.getByTestId('prediction-evidence-gaps')).toHaveTextContent(
      'No endpoint telemetry was available.',
    )
    expect(screen.getByTestId('prediction-unresolved')).toHaveTextContent(
      'Was the destination host already compromised?',
    )
    expect(screen.getAllByText('Single source').length).toBeGreaterThan(0)
  })

  it('renders insufficient evidence as a successful answer, not a failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(INSUFFICIENT))

    renderRoute(
      `/predictions/correlation/${CORR}`,
      '/predictions/correlation/:correlationId',
    )

    expect(await screen.findByTestId('prediction-insufficient')).toBeInTheDocument()
    expect(screen.queryByTestId('prediction-error')).toBeNull()
    expect(screen.getByText('insufficient evidence')).toBeInTheDocument()
    expect(screen.getByText('returned without speculation')).toBeInTheDocument()
    expect(
      screen.getByText(/Returning nothing is the correct result/i),
    ).toBeInTheDocument()
  })

  it('reports unavailable inputs instead of hiding them', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(INSUFFICIENT))

    renderRoute(`/predictions/${SESSION}`, '/predictions/:predictionId')
    await screen.findByTestId('prediction-insufficient')

    const inputs = screen.getByTestId('prediction-unavailable-inputs')
    expect(inputs).toHaveTextContent('attack_mappings')
    expect(inputs).toHaveTextContent('debate')
  })

  it('reports a governed failure and never renders a projection', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      json(
        {
          detail: {
            correlation_id: CORR,
            prediction_session_id: null,
            status: 'failed',
            failure_code: 'prediction_input_unavailable',
            detail: 'correlation could not be resolved',
            provenance: 'ai_generated',
          },
        },
        503,
      ),
    )

    renderRoute(
      `/predictions/correlation/${CORR}`,
      '/predictions/correlation/:correlationId',
    )

    await waitFor(() =>
      expect(screen.getByTestId('prediction-error')).toBeInTheDocument(),
    )
    expect(screen.queryByTestId('prediction-target')).toBeNull()
    expect(
      screen.getByText(/correlation could not be resolved/),
    ).toBeInTheDocument()
    // The governed code travels with the message so the UI never shows only a
    // bare status code for a structured failure.
    expect(
      screen.getByText(/prediction_input_unavailable/),
    ).toBeInTheDocument()
  })

  it('surfaces the backend detail for a missing prediction', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      throw new ApiError(404, 'prediction session not found')
    })

    renderRoute(`/predictions/${SESSION}`, '/predictions/:predictionId')

    await waitFor(() =>
      expect(screen.getByTestId('prediction-error')).toBeInTheDocument(),
    )
    expect(screen.getByText('prediction session not found')).toBeInTheDocument()
  })

  it('guides the user to pick a correlation when no target is in the route', () => {
    renderRoute('/predictions', '/predictions')

    expect(
      screen.getByText(/A prediction is always scoped to a single correlation/),
    ).toBeInTheDocument()
  })
})