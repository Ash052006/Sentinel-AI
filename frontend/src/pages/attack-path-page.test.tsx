import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { AttackPathPage } from './attack-path-page'
import { renderWithProviders } from '../test/utils'
import type {
  AttackPathGraph,
  AttackPathNode,
  AttackPathResponse,
} from '../types/api'

const CORR = '22222222-2222-4222-8222-222222222222'
const DET = '33333333-3333-4333-8333-333333333333'
const IND = '44444444-4444-4444-8444-444444444444'

const NODES: AttackPathNode[] = [
  {
    node_id: `cor-${CORR}`,
    node_type: 'correlation',
    label: 'Suspicious DNS correlation',
    provenance: 'correlated',
    source_reference: CORR,
    occurrence: '2026-09-25T09:00:00+00:00',
    status: 'active',
    severity: null,
    fields: { status: 'active' },
    evidence_references: [CORR],
  },
  {
    node_id: `det-${DET}`,
    node_type: 'detection',
    label: 'Anomalous DNS query',
    provenance: 'detected',
    source_reference: DET,
    occurrence: '2026-09-25T09:01:00+00:00',
    status: null,
    severity: 'high',
    fields: { severity: 'high', confidence: '0.87' },
    evidence_references: [DET],
  },
  {
    node_id: `ind-${IND}`,
    node_type: 'indicator',
    label: 'evil.example.com',
    provenance: 'enriched',
    source_reference: IND,
    occurrence: null,
    status: null,
    severity: null,
    fields: { indicator_type: 'domain' },
    evidence_references: [IND],
  },
]

const GRAPH: AttackPathGraph = {
  nodes: NODES,
  edges: [
    {
      edge_id: `e-1-${CORR}`,
      source_node_id: `cor-${CORR}`,
      target_node_id: `det-${DET}`,
      relationship_type: 'correlation_has_detection',
      provenance: 'correlated',
      source_reference: `cm-${CORR}`,
      evidence_references: [`cm-${CORR}`],
    },
    {
      edge_id: `e-2-${DET}`,
      source_node_id: `det-${DET}`,
      target_node_id: `ind-${IND}`,
      relationship_type: 'detection_has_indicator',
      provenance: 'enriched',
      source_reference: `lk-${DET}`,
      evidence_references: [`lk-${DET}`],
    },
  ],
}

function makeResponse(overrides: Partial<AttackPathResponse> = {}): AttackPathResponse {
  return {
    graph: GRAPH,
    metadata: {
      correlation_id: CORR,
      generated_at: '2026-09-25T10:00:00+00:00',
      node_count: NODES.length,
      edge_count: GRAPH.edges.length,
      truncated: false,
      limitation: null,
      bounds: { max_attack_path_nodes: 120, max_attack_path_edges: 240 },
    },
    availability: {
      correlation: 'provided',
      detections: 'provided',
      indicators: 'provided',
      risk_assessment: 'not_provided',
      incident_memory: 'not_provided',
      threat_hunts: 'none_found',
      policy_decisions: 'not_provided',
      approvals: 'not_provided',
      soar_executions: 'not_provided',
      investigation: 'not_provided',
      attribution: 'not_provided',
      security_events: 'not_provided',
    },
    ...overrides,
  }
}

vi.mock('../api/attack-paths', () => ({
  attackPathsApi: {
    graph: vi.fn(),
  },
}))

const attackPathsApi = (await import('../api/attack-paths')).attackPathsApi

function renderGraph(): void {
  renderWithProviders(
    <Routes>
      <Route path="/attack-paths" element={<AttackPathPage />} />
      <Route path="/attack-paths/:correlationId" element={<AttackPathPage />} />
    </Routes>,
    {
      route: `/attack-paths/${CORR}`,
      entries: [`/attack-paths/${CORR}`],
    },
  )
}

describe('AttackPathPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(attackPathsApi.graph).mockResolvedValue(makeResponse())
  })

  it('renders the deterministic graph with nodes and edges', async () => {
    renderGraph()

    expect(await screen.findByTestId('attack-path-graph')).toBeInTheDocument()
    expect(screen.getByTestId(`attack-path-node-cor-${CORR}`)).toBeInTheDocument()
    expect(screen.getByTestId(`attack-path-node-det-${DET}`)).toBeInTheDocument()
    expect(screen.getByTestId(`attack-path-node-ind-${IND}`)).toBeInTheDocument()
    expect(screen.getByTestId(`attack-path-edge-e-1-${CORR}`)).toBeInTheDocument()
    expect(screen.getByTestId(`attack-path-edge-e-2-${DET}`)).toBeInTheDocument()
    expect(screen.getAllByText(/Suspicious DNS/).length).toBeGreaterThan(0)
    expect(attackPathsApi.graph).toHaveBeenCalledWith(CORR)
  })

  it('shows per-surface availability labels', async () => {
    renderGraph()

    const panel = await screen.findByTestId('attack-path-availability')
    expect(within(panel).getAllByText('provided').length).toBe(3)
    expect(within(panel).getByText('none found')).toBeInTheDocument()
    expect(within(panel).getAllByText('not provided').length).toBe(8)
  })

  it('selecting a node reveals provenance and evidence references', async () => {
    const user = userEvent.setup()
    renderGraph()

    const node = await screen.findByTestId(`attack-path-node-det-${DET}`)
    await user.click(node)

    const detail = screen.getByTestId('attack-path-node-detail')
    expect(within(detail).getByText('Anomalous DNS query')).toBeInTheDocument()
    expect(within(detail).getByText('detected')).toBeInTheDocument()
    expect(within(detail).getAllByText('333333333333').length).toBeGreaterThan(0)
    expect(within(detail).getAllByText('high').length).toBeGreaterThan(0)
    expect(within(detail).getByText('0.87')).toBeInTheDocument()
  })

  it('renders the truncation banner when the projection was bounded', async () => {
    vi.mocked(attackPathsApi.graph).mockResolvedValue(
      makeResponse({
        metadata: {
          ...makeResponse().metadata,
          truncated: true,
          limitation: 'max_attack_path_nodes=120 reached; auxiliary surfaces trimmed deterministically.',
        },
      }),
    )
    renderGraph()

    const banner = await screen.findByTestId('attack-path-truncated')
    expect(within(banner).getByText(/Projection truncated/)).toBeInTheDocument()
    expect(within(banner).getByText(/max_attack_path_nodes=120/)).toBeInTheDocument()
  })

  it('shows an empty state when the correlation has no relationship records', async () => {
    vi.mocked(attackPathsApi.graph).mockResolvedValue(
      makeResponse({
        graph: { nodes: [], edges: [] },
        metadata: { ...makeResponse().metadata, node_count: 0, edge_count: 0 },
      }),
    )
    renderGraph()

    expect(await screen.findByText('No attack path to render')).toBeInTheDocument()
  })

  it('surfaces API failures and retries the request', async () => {
    vi.mocked(attackPathsApi.graph)
      .mockRejectedValueOnce(new Error('STATUS: 404; Correlation not found'))
      .mockResolvedValue(makeResponse())

    const user = userEvent.setup()
    renderGraph()

    const error = await screen.findByText('Unable to load data')
    expect(error).toBeInTheDocument()
    expect(screen.getByText(/Correlation not found/)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByTestId('attack-path-graph')).toBeInTheDocument())
    expect(attackPathsApi.graph).toHaveBeenCalledTimes(2)
  })

  it('shows a loading state while the projection loads', () => {
    vi.mocked(attackPathsApi.graph).mockImplementation(
      () => new Promise(() => undefined) as Promise<AttackPathResponse>,
    )
    renderGraph()

    expect(screen.getByTestId('loading-rows')).toBeInTheDocument()
  })

  it('prompts for a correlation when none is selected', () => {
    renderWithProviders(
      <Routes>
        <Route path="/attack-paths" element={<AttackPathPage />} />
        <Route path="/attack-paths/:correlationId" element={<AttackPathPage />} />
      </Routes>,
      {
        route: '/attack-paths',
        entries: ['/attack-paths'],
      },
    )

    expect(screen.getByText('No correlation selected')).toBeInTheDocument()
  })
})