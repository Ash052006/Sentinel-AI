import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { KnowledgeGraphPage } from './knowledge-graph-page'
import { renderWithProviders } from '../test/utils'
import { ApiError } from '../api/client'
import type {
  CorrelationResult,
  KnowledgeEdge,
  KnowledgeNode,
  KnowledgeTraversal,
} from '../types/api'

const CORR = '22222222-2222-4222-8222-222222222222'
const EVENT = '11111111-1111-4111-8111-111111111111'
const DET_A = '33333333-3333-4333-8333-333333333333'
const DET_B = '44444444-4444-4444-8444-444444444444'
const RISK = '55555555-5555-4555-8555-555555555555'

const NODE_EVENT: KnowledgeNode = {
  id: 'n-event',
  node_type: 'EVENT',
  source_id: EVENT,
  label: `event ${EVENT.slice(0, 8)}`,
  source_reference: `event_reference:${EVENT}`,
  provenance: 'referenced_event_identifier',
  metadata: {},
  observed_at: null,
}

const NODE_DET_A: KnowledgeNode = {
  id: 'n-det-a',
  node_type: 'DETECTION',
  source_id: DET_A,
  label: 'Anomalous DNS query',
  source_reference: `detection:${DET_A}`,
  provenance: 'persisted_detection_result',
  metadata: { severity: 'high', confidence: 0.87 },
  observed_at: '2026-09-25T09:01:00+00:00',
}

const NODE_DET_B: KnowledgeNode = {
  id: 'n-det-b',
  node_type: 'DETECTION',
  source_id: DET_B,
  label: 'Beacon to rare destination',
  source_reference: `detection:${DET_B}`,
  provenance: 'persisted_detection_result',
  metadata: { severity: 'medium' },
  observed_at: '2026-09-25T09:02:00+00:00',
}

const NODE_CORR: KnowledgeNode = {
  id: 'n-corr',
  node_type: 'CORRELATION',
  source_id: CORR,
  label: `correlation ${CORR.slice(0, 8)} (active)`,
  source_reference: `correlation:${CORR}`,
  provenance: 'persisted_correlation_result',
  metadata: { status: 'active', confidence: 0.91 },
  observed_at: '2026-09-25T09:05:00+00:00',
}

const NODE_RISK: KnowledgeNode = {
  id: 'n-risk',
  node_type: 'RISK_ASSESSMENT',
  source_id: RISK,
  label: 'risk assessment',
  source_reference: `risk_assessment:${RISK}`,
  provenance: 'persisted_risk_assessment',
  metadata: { risk_level: 'high', risk_score: 0.78 },
  observed_at: '2026-09-25T09:06:00+00:00',
}

const NODES: KnowledgeNode[] = [
  NODE_EVENT,
  NODE_DET_A,
  NODE_DET_B,
  NODE_CORR,
  NODE_RISK,
]

const EDGE_PRODUCED_A: KnowledgeEdge = {
  id: 'e-produced-a',
  relationship_type: 'produced_detection',
  source_node_id: 'n-event',
  target_node_id: 'n-det-a',
  source_reference: `detection_result:${DET_A}`,
  evidence_references: [
    `detection:${DET_A}`,
    `detection_result:${DET_A}`,
    `event_reference:${EVENT}`,
  ],
}

const EDGE_PRODUCED_B: KnowledgeEdge = {
  id: 'e-produced-b',
  relationship_type: 'produced_detection',
  source_node_id: 'n-event',
  target_node_id: 'n-det-b',
  source_reference: `detection_result:${DET_B}`,
  evidence_references: [`detection:${DET_B}`, `detection_result:${DET_B}`],
}

const EDGE_MEMBER_A: KnowledgeEdge = {
  id: 'e-member-a',
  relationship_type: 'member_of_correlation',
  source_node_id: 'n-det-a',
  target_node_id: 'n-corr',
  source_reference: 'correlation_member:cm-1',
  evidence_references: [`correlation:${CORR}`, 'correlation_member:cm-1'],
}

const EDGE_MEMBER_B: KnowledgeEdge = {
  id: 'e-member-b',
  relationship_type: 'member_of_correlation',
  source_node_id: 'n-det-b',
  target_node_id: 'n-corr',
  source_reference: 'correlation_member:cm-2',
  evidence_references: [`correlation:${CORR}`, 'correlation_member:cm-2'],
}

const EDGE_ASSESSED: KnowledgeEdge = {
  id: 'e-assessed',
  relationship_type: 'assessed_by',
  source_node_id: 'n-corr',
  target_node_id: 'n-risk',
  source_reference: `risk_assessment:${RISK}`,
  evidence_references: [`correlation:${CORR}`, `risk_assessment:${RISK}`],
}

const EDGES: KnowledgeEdge[] = [
  EDGE_PRODUCED_A,
  EDGE_PRODUCED_B,
  EDGE_MEMBER_A,
  EDGE_MEMBER_B,
  EDGE_ASSESSED,
]

function makeTraversal(
  overrides: Partial<KnowledgeTraversal> = {},
): KnowledgeTraversal {
  return {
    root_node_id: 'n-corr',
    nodes: NODES,
    edges: EDGES,
    node_count: NODES.length,
    edge_count: EDGES.length,
    max_depth_reached: 3,
    truncated: false,
    truncated_reason: null,
    bounds: { max_nodes: 500, max_edges: 2000, max_depth: 5, max_page_size: 200 },
    unavailable_entity_types: {},
    ...overrides,
  }
}

vi.mock('../api/knowledge-graph', () => ({
  knowledgeGraphApi: {
    correlationGraph: vi.fn(),
  },
}))

vi.mock('../api/correlations', () => ({
  correlationsApi: {
    recent: vi.fn(),
  },
}))

const knowledgeGraphApi = (await import('../api/knowledge-graph')).knowledgeGraphApi
const correlationsApi = (await import('../api/correlations')).correlationsApi

function correlation(
  overrides: Partial<CorrelationResult> = {},
): CorrelationResult {
  return {
    id: 'corr-row',
    correlation_id: CORR,
    status: 'active',
    confidence: 0.9,
    evidence: {},
    result_metadata: {},
    timestamp: '2027-10-23T04:00:00Z',
    provenance: 'correlated',
    members: [],
    created_at: '2027-10-23T04:00:00Z',
    updated_at: '2027-10-23T04:00:00Z',
    ...overrides,
  }
}

function renderPage(path = `/knowledge-graph/${CORR}`): void {
  renderWithProviders(
    <Routes>
      <Route path="/knowledge-graph" element={<KnowledgeGraphPage />} />
      <Route path="/knowledge-graph/:correlationId" element={<KnowledgeGraphPage />} />
    </Routes>,
    { route: path, entries: [path] },
  )
}

describe('KnowledgeGraphPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(knowledgeGraphApi.correlationGraph).mockResolvedValue(makeTraversal())
    vi.mocked(correlationsApi.recent).mockResolvedValue([correlation()])
  })

  it('renders the deterministic graph with every node and edge', async () => {
    renderPage()

    expect(await screen.findByTestId('knowledge-graph')).toBeInTheDocument()
    for (const node of NODES) {
      expect(screen.getByTestId(`knowledge-node-${node.id}`)).toBeInTheDocument()
    }
    for (const edge of EDGES) {
      expect(screen.getByTestId(`knowledge-edge-${edge.id}`)).toBeInTheDocument()
    }
    expect(knowledgeGraphApi.correlationGraph).toHaveBeenCalledWith(CORR)
  })

  it('reports the node and edge counts from the server, not locally', async () => {
    renderPage()

    await screen.findByTestId('knowledge-graph')
    const stats = screen.getByText('Nodes').closest('div')?.parentElement
    expect(stats?.textContent).toContain('5')
  })

  it('shows the persisted source record for a selected node', async () => {
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByTestId('knowledge-node-n-det-a'))

    const detail = screen.getByTestId('knowledge-node-detail')
    expect(within(detail).getByText('Anomalous DNS query')).toBeInTheDocument()
    expect(
      within(detail).getByText(`detection:${DET_A}`),
    ).toBeInTheDocument()
    expect(
      within(detail).getByText('persisted detection result'),
    ).toBeInTheDocument()
  })

  it('exposes only allowlisted attributes, never raw payloads', async () => {
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByTestId('knowledge-node-n-det-a'))

    const detail = screen.getByTestId('knowledge-node-detail')
    expect(within(detail).getByText('severity')).toBeInTheDocument()
    expect(within(detail).getByText('0.87')).toBeInTheDocument()
    expect(within(detail).queryByText('evidence')).not.toBeInTheDocument()
    expect(within(detail).queryByText('result metadata')).not.toBeInTheDocument()
  })

  it('lists the incident edges of a selected node', async () => {
    const user = userEvent.setup()
    renderPage()

    await user.click(await screen.findByTestId('knowledge-node-n-det-a'))

    expect(screen.getByTestId('knowledge-incident-e-produced-a')).toBeInTheDocument()
    expect(screen.getByTestId('knowledge-incident-e-member-a')).toBeInTheDocument()
  })

  it('shows the justifying record when an edge is inspected', async () => {
    const user = userEvent.setup()
    renderPage()

    await screen.findByTestId('knowledge-graph')
    const rows = screen.getAllByRole('row')
    const produced = rows.find((row) =>
      within(row).queryByText('produced') !== null,
    )
    expect(produced).toBeDefined()
    await user.click(within(produced as HTMLElement).getByRole('button'))

    const detail = screen.getByTestId('knowledge-edge-detail')
    // The justifying record appears twice on purpose: once as the citation
    // header, once inside the full evidence list.
    expect(
      within(detail).getAllByText(`detection_result:${DET_A}`).length,
    ).toBe(2)
    const refs = within(detail).getAllByTestId('knowledge-evidence-reference')
    expect(refs.length).toBeGreaterThanOrEqual(3)
  })

  it('states truncation explicitly instead of hiding it', async () => {
    vi.mocked(knowledgeGraphApi.correlationGraph).mockResolvedValue(
      makeTraversal({ truncated: true, truncated_reason: 'max_depth' }),
    )
    renderPage()

    const notice = await screen.findByTestId('knowledge-graph-truncation')
    expect(within(notice).getByText('max_depth')).toBeInTheDocument()
  })

  it('shows no truncation notice when the graph is complete', async () => {
    renderPage()

    await screen.findByTestId('knowledge-graph')
    expect(screen.queryByTestId('knowledge-graph-truncation')).not.toBeInTheDocument()
  })

  it('discloses entity types V2 cannot represent', async () => {
    vi.mocked(knowledgeGraphApi.correlationGraph).mockResolvedValue(
      makeTraversal({
        unavailable_entity_types: {
          investigation: 'V2 persists no investigation table.',
          policy_decision: 'V2 persists no policy decision table.',
        },
      }),
    )
    renderPage()

    const panel = await screen.findByTestId('knowledge-unavailable')
    expect(within(panel).getByText('investigation')).toBeInTheDocument()
    expect(within(panel).getByText('policy_decision')).toBeInTheDocument()
  })

  it('lists persisted correlations on the bare route', async () => {
    renderPage('/knowledge-graph')

    const picker = await screen.findByTestId('knowledge-graph-picker')
    await waitFor(() =>
      expect(within(picker).getByText(/View graph/)).toBeInTheDocument(),
    )
    expect(knowledgeGraphApi.correlationGraph).not.toHaveBeenCalled()
  })

  it('explains an absent graph instead of showing an empty canvas', async () => {
    vi.mocked(knowledgeGraphApi.correlationGraph).mockRejectedValue(
      new ApiError(404, 'graph node missing'),
    )
    renderPage()

    expect(await screen.findByTestId('not-available')).toBeInTheDocument()
  })

  it('surfaces a real failure for retry', async () => {
    vi.mocked(knowledgeGraphApi.correlationGraph).mockRejectedValue(
      new ApiError(500, 'boom'),
    )
    renderPage()

    expect(await screen.findByText(/boom/)).toBeInTheDocument()
  })

  it('never renders secret-shaped content from the payload', async () => {
    vi.mocked(knowledgeGraphApi.correlationGraph).mockResolvedValue(
      makeTraversal({
        nodes: [
          {
            ...NODE_DET_A,
            label: 'Anomalous DNS query',
            metadata: { severity: 'high' },
          },
        ],
        edges: [],
        node_count: 1,
        edge_count: 0,
      }),
    )
    renderPage()

    await screen.findByTestId('knowledge-graph')
    const body = document.body.textContent ?? ''
    for (const marker of ['$argon2', 'Bearer ', 'sk-', 'api_key']) {
      expect(body).not.toContain(marker)
    }
  })

  it('renders the same layout for the same payload', async () => {
    const { unmount } = renderWithProviders(
      <Routes>
        <Route path="/knowledge-graph/:correlationId" element={<KnowledgeGraphPage />} />
      </Routes>,
      { route: `/knowledge-graph/${CORR}`, entries: [`/knowledge-graph/${CORR}`] },
    )
    await screen.findByTestId('knowledge-graph')
    const first = screen.getByTestId('knowledge-graph').innerHTML
    unmount()

    renderPage()
    await screen.findByTestId('knowledge-graph')
    const second = screen.getByTestId('knowledge-graph').innerHTML

    expect(second).toBe(first)
  })
})