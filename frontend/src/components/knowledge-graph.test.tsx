import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { KnowledgeGraphView } from './knowledge-graph'
import type { KnowledgeEdge, KnowledgeNode } from '../types/api'

const NODE_CORR: KnowledgeNode = {
  id: 'n-corr',
  node_type: 'CORRELATION',
  source_id: 'corr-1',
  label: 'Correlated activity across three detections',
  source_reference: 'correlation:corr-1',
  provenance: 'correlated',
  metadata: { status: 'active' },
  observed_at: '2026-10-15T14:08:17Z',
}

const NODE_EVENT: KnowledgeNode = {
  id: 'n-event',
  node_type: 'EVENT',
  source_id: 'evt-1',
  label: 'Anomalous DNS query from workstation',
  source_reference: 'event_reference:evt-1',
  provenance: 'referenced_event_identifier',
  metadata: {},
  observed_at: null,
}

const NODE_DET: KnowledgeNode = {
  id: 'n-det',
  node_type: 'DETECTION',
  source_id: 'det-1',
  label: 'DNS tunneling detection',
  source_reference: 'detection_result:det-1',
  provenance: 'detected',
  metadata: { severity: 'high' },
  observed_at: '2026-10-15T14:07:00Z',
}

const NODE_RISK: KnowledgeNode = {
  id: 'n-risk',
  node_type: 'RISK_ASSESSMENT',
  source_id: 'risk-1',
  label: 'Risk assessment',
  source_reference: 'risk_assessment:risk-1',
  provenance: 'risk_assessed',
  metadata: { risk_level: 'high' },
  observed_at: null,
}

const NODE_ORPHAN: KnowledgeNode = {
  id: 'n-orphan',
  node_type: 'INCIDENT_MEMORY',
  source_id: 'mem-1',
  label: 'Unrelated memory',
  source_reference: 'incident_memory:mem-1',
  provenance: 'recalled',
  metadata: {},
  observed_at: null,
}

const EDGES: KnowledgeEdge[] = [
  {
    id: 'e-member',
    relationship_type: 'member_of_correlation',
    source_node_id: 'n-det',
    target_node_id: 'n-corr',
    source_reference: 'correlation_member:cm-1',
    evidence_references: ['correlation:corr-1', 'correlation_member:cm-1'],
  },
  {
    id: 'e-produced',
    relationship_type: 'produced_detection',
    source_node_id: 'n-event',
    target_node_id: 'n-det',
    source_reference: 'detection_result:det-1',
    evidence_references: ['detection_result:det-1'],
  },
  {
    id: 'e-assessed',
    relationship_type: 'assessed_by',
    source_node_id: 'n-corr',
    target_node_id: 'n-risk',
    source_reference: 'risk_assessment:risk-1',
    evidence_references: ['correlation:corr-1', 'risk_assessment:risk-1'],
  },
]

const ALL_NODES = [NODE_CORR, NODE_EVENT, NODE_DET, NODE_RISK, NODE_ORPHAN]

const CYCLE_A: KnowledgeNode = {
  id: 'n-c1',
  node_type: 'INCIDENT_MEMORY',
  source_id: 'mem-a',
  label: 'Cycle record one',
  source_reference: 'incident_memory:mem-a',
  provenance: 'recalled',
  metadata: {},
  observed_at: null,
}

const CYCLE_B: KnowledgeNode = {
  id: 'n-c2',
  node_type: 'THREAT_HUNT',
  source_id: 'hunt-a',
  label: 'Cycle record two',
  source_reference: 'threat_hunt:hunt-a',
  provenance: 'investigated',
  metadata: {},
  observed_at: null,
}

const CYCLE_C: KnowledgeNode = {
  id: 'n-c3',
  node_type: 'THREAT_INDICATOR',
  source_id: 'ioc-a',
  label: 'Cycle record three',
  source_reference: 'threat_indicator:ioc-a',
  provenance: 'observed',
  metadata: {},
  observed_at: null,
}

const CYCLE_NODES = [CYCLE_A, CYCLE_B, CYCLE_C]

const CYCLE_EDGES: KnowledgeEdge[] = [
  {
    id: 'e-c12',
    relationship_type: 'recalled_by',
    source_node_id: 'n-c1',
    target_node_id: 'n-c2',
    source_reference: 'threat_hunt:hunt-a',
    evidence_references: ['incident_memory:mem-a'],
  },
  {
    id: 'e-c23',
    relationship_type: 'investigated_by_hunt',
    source_node_id: 'n-c2',
    target_node_id: 'n-c3',
    source_reference: 'threat_indicator:ioc-a',
    evidence_references: ['threat_hunt:hunt-a'],
  },
  {
    id: 'e-c31',
    relationship_type: 'associated_with_indicator',
    source_node_id: 'n-c3',
    target_node_id: 'n-c1',
    source_reference: 'incident_memory:mem-a',
    evidence_references: ['threat_indicator:ioc-a'],
  },
]

function renderView(
  overrides: Partial<{
    nodes: KnowledgeNode[]
    edges: KnowledgeEdge[]
    rootNodeId: string | null
    selectedNodeId: string | null
    onSelectNode: (id: string | null) => void
  }> = {},
) {
  const onSelectNode = overrides.onSelectNode ?? vi.fn()
  render(
    <KnowledgeGraphView
      nodes={overrides.nodes ?? ALL_NODES}
      edges={overrides.edges ?? EDGES}
      rootNodeId={overrides.rootNodeId ?? 'n-corr'}
      selectedNodeId={overrides.selectedNodeId ?? null}
      onSelectNode={onSelectNode}
    />,
  )
  return { onSelectNode }
}

function boxOf(id: string) {
  const rect = screen
    .getByTestId(`knowledge-node-${id}`)
    .querySelector('rect') as SVGRectElement
  return {
    x: Number(rect.getAttribute('x')),
    y: Number(rect.getAttribute('y')),
    width: Number(rect.getAttribute('width')),
    height: Number(rect.getAttribute('height')),
  }
}

function pathPoints(id: string) {
  const d = screen.getByTestId(`knowledge-edge-${id}`).getAttribute('d') ?? ''
  const numbers = d.match(/-?\d+(?:\.\d+)?/g) ?? []
  return {
    startX: Number(numbers[0]),
    endX: Number(numbers[numbers.length - 2]),
  }
}

function geometryOf(root: HTMLElement) {
  return Array.from(root.querySelectorAll('[data-testid^="knowledge-node-"]')).map(
    (node) => {
      const rect = node.querySelector('rect')
      return `${node.getAttribute('data-testid')}@${rect?.getAttribute('x')},${rect?.getAttribute('y')}`
    },
  )
}

const selectCalls: (string | null)[] = []

function SelectionHarness() {
  const [selected, setSelected] = useState<string | null>(null)
  return (
    <KnowledgeGraphView
      nodes={ALL_NODES}
      edges={EDGES}
      rootNodeId="n-corr"
      selectedNodeId={selected}
      onSelectNode={(id) => {
        selectCalls.push(id)
        setSelected(id)
      }}
    />
  )
}

describe('KnowledgeGraphView', () => {
  it('renders every node and edge from the payload', () => {
    renderView()
    for (const node of ALL_NODES) {
      expect(screen.getByTestId(`knowledge-node-${node.id}`)).toBeInTheDocument()
    }
    for (const edge of EDGES) {
      expect(screen.getByTestId(`knowledge-edge-${edge.id}`)).toBeInTheDocument()
    }
    expect(screen.getByTestId('knowledge-graph')).toBeInTheDocument()
    expect(screen.getByTestId('knowledge-graph-content')).toBeInTheDocument()
  })

  it('keeps full identifiers, provenance and labels available in tooltips', () => {
    renderView()
    const corr = screen.getByTestId('knowledge-node-n-corr')
    const corrTitle = corr.querySelector('title')
    expect(corrTitle?.textContent).toContain('correlation:corr-1')
    expect(corrTitle?.textContent).toContain('provenance: correlated')
    expect(corrTitle?.textContent).toContain(
      'Correlated activity across three detections',
    )

    const labelLines = Array.from(corr.querySelectorAll('text')).filter(
      (text) => text.getAttribute('fill') === '#d6dde7',
    )
    expect(labelLines).toHaveLength(2)
    expect(labelLines[0].textContent).toBe('Correlated activity across')
    expect(labelLines[1].textContent).toBe('three detections')

    const risk = screen.getByTestId('knowledge-node-n-risk')
    const riskLabels = Array.from(risk.querySelectorAll('text')).filter(
      (text) => text.getAttribute('fill') === '#d6dde7',
    )
    expect(riskLabels).toHaveLength(1)

    const edge = screen.getByTestId('knowledge-edge-e-member')
    const edgeTitle = edge.parentElement?.querySelector('title')
    expect(edgeTitle?.textContent).toContain('member of')
    expect(edgeTitle?.textContent).toContain('correlation_member:cm-1')
  })

  it('selects a node on click and deselects on second click', async () => {
    selectCalls.length = 0
    render(<SelectionHarness />)
    const node = screen.getByTestId('knowledge-node-n-det')

    await userEvent.click(node)
    expect(selectCalls).toEqual(['n-det'])
    expect(node.getAttribute('filter')).toBe('url(#knowledge-graph-glow)')

    await userEvent.click(node)
    expect(selectCalls).toEqual(['n-det', null])
    expect(node.getAttribute('filter')).toBeNull()
  })

  it('keeps only the one-hop neighbourhood lit when a node is selected', () => {
    renderView({ selectedNodeId: 'n-det' })

    expect(
      screen.getByTestId('knowledge-node-n-corr').getAttribute('opacity'),
    ).toBe('1')
    expect(
      screen.getByTestId('knowledge-node-n-event').getAttribute('opacity'),
    ).toBe('1')
    expect(
      screen.getByTestId('knowledge-node-n-risk').getAttribute('opacity'),
    ).toBe('0.4')
    expect(
      screen.getByTestId('knowledge-node-n-orphan').getAttribute('opacity'),
    ).toBe('0.4')

    const activeEdge = screen.getByTestId('knowledge-edge-e-member')
    expect(activeEdge.getAttribute('stroke')).toBe('#a8bcd2')
    expect(activeEdge.getAttribute('marker-end')).toBe(
      'url(#knowledge-graph-arrow-active)',
    )
    expect(activeEdge.getAttribute('opacity')).toBe('1')

    const dimmedEdge = screen.getByTestId('knowledge-edge-e-assessed')
    expect(dimmedEdge.getAttribute('stroke')).toBe('#39434f')
    expect(dimmedEdge.getAttribute('marker-end')).toBeNull()
    expect(dimmedEdge.getAttribute('opacity')).toBe('0.4')
  })

  it('draws the selection outline and glow only for the selected node', () => {
    renderView({ selectedNodeId: 'n-corr' })
    const selected = screen.getByTestId('knowledge-node-n-corr')
    expect(selected.querySelectorAll('rect')).toHaveLength(2)
    expect(selected.getAttribute('filter')).toBe('url(#knowledge-graph-glow)')

    const normal = screen.getByTestId('knowledge-node-n-event')
    expect(normal.querySelectorAll('rect')).toHaveLength(1)
    expect(normal.getAttribute('filter')).toBeNull()
  })

  it('emphasises the root node with a distinct fill and stroke', () => {
    renderView()
    const root = screen.getByTestId('knowledge-node-n-corr')
    const rootRect = root.querySelector('rect') as SVGRectElement
    expect(rootRect.getAttribute('fill')).toBe('#172130')
    expect(rootRect.getAttribute('stroke-width')).toBe('2')

    const plain = screen.getByTestId('knowledge-node-n-event')
    const plainRect = plain.querySelector('rect') as SVGRectElement
    expect(plainRect.getAttribute('fill')).toBe('#161d26')
    expect(plainRect.getAttribute('stroke-width')).toBe('1.5')
  })

  it('flows left to right without reversing any relationship', () => {
    renderView()
    expect(boxOf('n-event').x).toBeLessThan(boxOf('n-det').x)
    expect(boxOf('n-det').x).toBeLessThan(boxOf('n-corr').x)
    expect(boxOf('n-corr').x).toBeLessThan(boxOf('n-risk').x)

    const direction: [string, string, string][] = [
      ['e-produced', 'n-event', 'n-det'],
      ['e-member', 'n-det', 'n-corr'],
      ['e-assessed', 'n-corr', 'n-risk'],
    ]
    for (const [edgeId, sourceId, targetId] of direction) {
      const source = boxOf(sourceId)
      const target = boxOf(targetId)
      const { startX, endX } = pathPoints(edgeId)
      expect(startX).toBeGreaterThanOrEqual(source.x)
      expect(startX).toBeLessThanOrEqual(source.x + source.width)
      expect(endX).toBe(target.x)
      expect(startX).toBeLessThan(endX)
    }
  })

  it('fits every node and the routing lane inside the viewBox', () => {
    renderView()
    const svg = screen.getByTestId('knowledge-graph')
    const viewBox = (svg.getAttribute('viewBox') ?? '').split(' ')
    const viewW = Number(viewBox[2])
    const viewH = Number(viewBox[3])
    expect(viewW).toBeGreaterThan(0)
    expect(viewH).toBeGreaterThan(0)

    const content = screen.getByTestId('knowledge-graph-content')
    const match = /translate\((-?[\d.]+) (-?[\d.]+)\)/.exec(
      content.getAttribute('transform') ?? '',
    )
    const tx = Number(match?.[1])
    const ty = Number(match?.[2])

    const boxes = ALL_NODES.map((node) => boxOf(node.id))
    for (const box of boxes) {
      expect(tx + box.x).toBeGreaterThanOrEqual(0)
      expect(ty + box.y).toBeGreaterThanOrEqual(0)
      expect(tx + box.x + box.width).toBeLessThanOrEqual(viewW)
      expect(ty + box.y + box.height).toBeLessThanOrEqual(viewH)
    }

    const columns = new Map<number, typeof boxes>()
    for (const box of boxes) {
      const column = columns.get(box.x) ?? []
      column.push(box)
      columns.set(box.x, column)
    }
    let overlapsChecked = 0
    for (const column of columns.values()) {
      if (column.length < 2) continue
      const sorted = [...column].sort((a, b) => a.y - b.y)
      for (let i = 1; i < sorted.length; i += 1) {
        expect(sorted[i].y).toBeGreaterThanOrEqual(
          sorted[i - 1].y + sorted[i - 1].height,
        )
        overlapsChecked += 1
      }
    }
    expect(overlapsChecked).toBeGreaterThan(0)

    const topmostLane = -67
    expect(ty + topmostLane).toBeGreaterThanOrEqual(0)
  })

  it('zooms with the buttons and restores the centred view on reset', async () => {
    renderView()
    const content = screen.getByTestId('knowledge-graph-content')
    const initial = content.getAttribute('transform')

    await userEvent.click(screen.getByRole('button', { name: 'Zoom in' }))
    expect(content.getAttribute('transform')).toContain('scale(1.25)')

    await userEvent.click(screen.getByRole('button', { name: 'Reset view' }))
    expect(content.getAttribute('transform')).toBe(initial)
    expect(initial).toContain('scale(1)')
  })

  it('layers cycle members apart and keeps the closing edge direction', () => {
    renderView({ nodes: CYCLE_NODES, edges: CYCLE_EDGES, rootNodeId: 'n-c1' })

    expect(boxOf('n-c1').x).toBeLessThan(boxOf('n-c2').x)
    expect(boxOf('n-c2').x).toBeLessThan(boxOf('n-c3').x)

    const closing = pathPoints('e-c31')
    const source = boxOf('n-c3')
    const target = boxOf('n-c1')
    expect(closing.startX).toBeGreaterThanOrEqual(source.x)
    expect(closing.startX).toBeLessThanOrEqual(source.x + source.width)
    expect(closing.endX).toBe(target.x)
    expect(closing.startX).toBeGreaterThan(closing.endX)
  })

  it('is deterministic: identical payloads produce identical geometry', () => {
    const first = render(
      <KnowledgeGraphView
        nodes={ALL_NODES}
        edges={EDGES}
        rootNodeId="n-corr"
        selectedNodeId={null}
        onSelectNode={vi.fn()}
      />,
    )
    const second = render(
      <KnowledgeGraphView
        nodes={[...ALL_NODES].reverse()}
        edges={[...EDGES].reverse()}
        rootNodeId="n-corr"
        selectedNodeId={null}
        onSelectNode={vi.fn()}
      />,
    )

    const a = geometryOf(first.container)
    const b = geometryOf(second.container)
    expect(a.length).toBe(ALL_NODES.length)
    expect(a).toEqual(b)

    const third = render(
      <KnowledgeGraphView
        nodes={CYCLE_NODES}
        edges={CYCLE_EDGES}
        rootNodeId="n-c1"
        selectedNodeId={null}
        onSelectNode={vi.fn()}
      />,
    )
    const fourth = render(
      <KnowledgeGraphView
        nodes={[...CYCLE_NODES].reverse()}
        edges={[...CYCLE_EDGES].reverse()}
        rootNodeId="n-c1"
        selectedNodeId={null}
        onSelectNode={vi.fn()}
      />,
    )
    expect(geometryOf(third.container)).toEqual(geometryOf(fourth.container))
  })
})
