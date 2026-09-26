import { useMemo, useRef, useState } from 'react'
import { Minus, Plus, RotateCcw } from 'lucide-react'
import { Button } from './ui/button'
import { shortId } from '../lib/formats'
import { NODE_COLORS, NODE_LABELS } from '../lib/labels'
import type { AttackPathEdge, AttackPathGraph, AttackPathNode, AttackPathNodeType } from '../types/api'

/**
 * V2.21 attack-path graph renderer.
 *
 * Self-contained SVG — no graph library. The layout is deterministic: a
 * breadth-first traversal from the correlation root assigns each node a
 * layer; within a layer nodes are ordered by (node type, node id). Rows run
 * left-to-right along the persisted, evidence-grounded relationships, so the
 * same payload always renders the same diagram.
 */

const NODE_W = 168
const NODE_H = 48
const GAP_X = 130
const GAP_Y = 24

const TYPE_ORDER: Record<AttackPathNodeType, number> = {
  correlation: 0,
  detection: 1,
  indicator: 2,
  risk: 3,
  memory: 4,
  hunt: 5,
  policy_decision: 6,
  approval: 7,
  soar_execution: 8,
}

interface Position {
  x: number
  y: number
}

function layoutGraph(graph: AttackPathGraph): {
  position: Map<string, Position>
  width: number
  height: number
} {
  const nodes = graph.nodes
  if (nodes.length === 0) {
    return { position: new Map(), width: 0, height: 0 }
  }
  const byId = new Map(nodes.map((node) => [node.node_id, node]))
  const outgoing = new Map<string, string[]>()
  for (const edge of graph.edges) {
    const list = outgoing.get(edge.source_node_id) ?? []
    list.push(edge.target_node_id)
    outgoing.set(edge.source_node_id, list)
  }

  const root = nodes.find((node) => node.node_type === 'correlation') ?? nodes[0]
  const depth = new Map<string, number>([[root.node_id, 0]])
  const queue = [root.node_id]
  while (queue.length > 0) {
    const current = queue.shift() as string
    const currentDepth = depth.get(current) ?? 0
    for (const target of outgoing.get(current) ?? []) {
      if (!depth.has(target) && byId.has(target)) {
        depth.set(target, currentDepth + 1)
        queue.push(target)
      }
    }
  }

  let maxDepth = 0
  for (const node of nodes) {
    if (!depth.has(node.node_id)) {
      // A node reached only by inbound-only edges (never happens for the
      // V2.21 edge set) is pinned to the deepest layer — still deterministic.
      depth.set(node.node_id, maxDepth)
    } else {
      maxDepth = Math.max(maxDepth, depth.get(node.node_id) as number)
    }
  }

  const columns = new Map<number, AttackPathNode[]>()
  for (const node of nodes) {
    const layer = depth.get(node.node_id) ?? maxDepth
    const list = columns.get(layer) ?? []
    list.push(node)
    columns.set(layer, list)
  }
  const sortedLayers = [...columns.keys()].sort((a, b) => a - b)
  const position = new Map<string, Position>()
  let height = NODE_H
  for (const layer of sortedLayers) {
    const column = columns.get(layer) ?? []
    column.sort((a, b) =>
      TYPE_ORDER[a.node_type] - TYPE_ORDER[b.node_type] !== 0
        ? TYPE_ORDER[a.node_type] - TYPE_ORDER[b.node_type]
        : a.node_id.localeCompare(b.node_id),
    )
    column.forEach((node, index) => {
      position.set(node.node_id, {
        x: layer * (NODE_W + GAP_X),
        y: index * (NODE_H + GAP_Y),
      })
    })
    height = Math.max(height, column.length * (NODE_H + GAP_Y) - GAP_Y + NODE_H)
  }
  const width = (sortedLayers.length - 1) * (NODE_W + GAP_X) + NODE_W
  return { position, width, height }
}

export function AttackPathGraph({
  graph,
  selectedNodeId,
  onSelectNode,
}: {
  graph: AttackPathGraph
  selectedNodeId: string | null
  onSelectNode: (nodeId: string | null) => void
}) {
  const { position, width, height } = useMemo(() => layoutGraph(graph), [graph])
  const [zoom, setZoom] = useState(1)
  const [offset, setOffset] = useState({ x: 24, y: 24 })
  const drag = useRef<{ startX: number; startY: number; ox: number; oy: number } | null>(null)

  const orderedNodes = [...graph.nodes].sort((a, b) => a.node_id.localeCompare(b.node_id))
  const orderedEdges = [...graph.edges].sort((a, b) => a.edge_id.localeCompare(b.edge_id))

  if (orderedNodes.length === 0) return null

  const edgePath = (edge: AttackPathEdge): string => {
    const source = position.get(edge.source_node_id)
    const target = position.get(edge.target_node_id)
    if (!source || !target) return ''
    const x1 = source.x + NODE_W
    const y1 = source.y + NODE_H / 2
    const x2 = target.x
    const y2 = target.y + NODE_H / 2
    return `M ${x1} ${y1} C ${x1 + 70} ${y1}, ${x2 - 70} ${y2}, ${x2} ${y2}`
  }

  return (
    <div className="overflow-hidden rounded border border-edge-soft bg-surface-1">
      <div className="flex items-center justify-between border-b border-edge-soft px-2 py-1.5">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">
          Deterministic layered projection · {orderedNodes.length} nodes · {orderedEdges.length} edges
        </div>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" className="h-6 w-6" aria-label="Zoom in" onClick={() => setZoom((z) => Math.min(3, z + 0.25))}>
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
          </Button>
          <Button variant="ghost" size="icon" className="h-6 w-6" aria-label="Zoom out" onClick={() => setZoom((z) => Math.max(0.25, z - 0.25))}>
            <Minus className="h-3.5 w-3.5" aria-hidden="true" />
          </Button>
          <Button variant="ghost" size="icon" className="h-6 w-6" aria-label="Reset view" onClick={() => { setZoom(1); setOffset({ x: 24, y: 24 }) }}>
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
          </Button>
        </div>
      </div>
      <div className="max-h-[560px] overflow-auto p-2">
        <svg
          role="img"
          aria-label="Attack path graph"
          data-testid="attack-path-graph"
          className="h-auto w-full min-w-[760px] select-none"
          style={{ aspectRatio: `${width} / ${height}` }}
          viewBox={`0 0 ${width + 96} ${height + 48}`}
          preserveAspectRatio="xMidYMid meet"
          onWheel={(event) => {
            event.preventDefault()
            setZoom((z) => Math.max(0.25, Math.min(3, z - event.deltaY * 0.001)))
          }}
          onPointerDown={(event) => {
            if (typeof event.currentTarget.setPointerCapture === 'function') {
              event.currentTarget.setPointerCapture(event.pointerId)
            }
            drag.current = { startX: event.clientX, startY: event.clientY, ox: offset.x, oy: offset.y }
          }}
          onPointerMove={(event) => {
            if (!drag.current) return
            setOffset({
              x: drag.current.ox + (event.clientX - drag.current.startX),
              y: drag.current.oy + (event.clientY - drag.current.startY),
            })
          }}
          onPointerUp={() => {
            drag.current = null
          }}
        >
          <defs>
            <marker
              id="attack-path-arrow"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#4a5a6e" />
            </marker>
          </defs>
          <rect x="0" y="0" width={width + 96} height={height + 48} fill="transparent" />
          <g transform={`translate(${offset.x} ${offset.y}) scale(${zoom})`}>
            {orderedEdges.map((edge) => (
              <g key={edge.edge_id}>
                <path
                  data-testid={`attack-path-edge-${edge.edge_id}`}
                  d={edgePath(edge)}
                  fill="none"
                  stroke="#4a5a6e"
                  strokeWidth={1.5}
                  markerEnd="url(#attack-path-arrow)"
                />
                <title>{`${edge.relationship_type} · ${edge.provenance} · ${edge.source_reference}`}</title>
              </g>
            ))}
            {orderedNodes.map((node) => {
              const pos = position.get(node.node_id)
              if (!pos) return null
              const color = NODE_COLORS[node.node_type]
              const selected = selectedNodeId === node.node_id
              return (
                <g
                  key={node.node_id}
                  data-testid={`attack-path-node-${node.node_id}`}
                  className="cursor-pointer"
                  onClick={(event) => {
                    event.stopPropagation()
                    onSelectNode(selected ? null : node.node_id)
                  }}
                  aria-label={`${NODE_LABELS[node.node_type]} node ${node.label}`}
                >
                  <rect
                    x={pos.x}
                    y={pos.y}
                    width={NODE_W}
                    height={NODE_H}
                    rx={7}
                    fill="#161d26"
                    stroke={color}
                    strokeWidth={selected ? 2.5 : 1.25}
                  />
                  <circle cx={pos.x + 16} cy={pos.y + 16} r={3.5} fill={color} />
                  <text
                    x={pos.x + 26}
                    y={pos.y + 19}
                    fontSize="9.5"
                    letterSpacing="0.08em"
                    fill={color}
                  >
                    {NODE_LABELS[node.node_type].toUpperCase()}
                  </text>
                  <text
                    x={pos.x + 12}
                    y={pos.y + 34}
                    fontSize="11"
                    fill="#d6dde7"
                  >
                    {node.label.length > 22 ? `${node.label.slice(0, 21)}…` : node.label}
                  </text>
                  <title>
                    {`${shortId(node.node_id)} · ${node.label}${node.severity ? ` · ${node.severity}` : ''}`}
                  </title>
                </g>
              )
            })}
          </g>
        </svg>
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-edge-soft px-3 py-1.5 text-[10px] text-ink-faint">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <span key={type} className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
            {NODE_LABELS[type as AttackPathNodeType]}
          </span>
        ))}
      </div>
    </div>
  )
}