import { useMemo, useRef, useState } from 'react'
import { Minus, Plus, RotateCcw } from 'lucide-react'
import { Button } from './ui/button'
import {
  KG_NODE_COLORS,
  KG_NODE_LABELS,
  KG_RELATIONSHIP_LABELS,
  KG_TYPE_ORDER,
} from '../lib/labels'
import type {
  KnowledgeEdge,
  KnowledgeNode,
  KnowledgeNodeType,
} from '../types/api'

/**
 * V3.22 knowledge-graph renderer.
 *
 * Self-contained SVG — no graph library, matching the V2.21 renderer. The
 * layout is deterministic: a breadth-first traversal from the root node (the
 * correlation, or the first node by id) assigns each node a layer, and within
 * a layer nodes are ordered by (node type, node id). The same payload always
 * renders the same diagram.
 *
 * Layout reads left to right along the direction of the relationships, so an
 * arrow points the way the evidence actually flows: correlation → detection →
 * the records that reference it.
 */

const NODE_W = 176
const NODE_H = 52
const GAP_X = 116
const GAP_Y = 22

interface Position {
  x: number
  y: number
}

function layoutGraph(nodes: KnowledgeNode[], edges: KnowledgeEdge[], rootId: string | null): {
  position: Map<string, Position>
  width: number
  height: number
} {
  if (nodes.length === 0) {
    return { position: new Map(), width: 0, height: 0 }
  }

  const byId = new Map(nodes.map((node) => [node.id, node]))
  const outgoing = new Map<string, string[]>()
  for (const edge of edges) {
    const list = outgoing.get(edge.source_node_id) ?? []
    list.push(edge.target_node_id)
    outgoing.set(edge.source_node_id, list)
  }

  // Prefer the correlation as the root so the diagram reads from the incident
  // outward. Fall back to the lowest node id, never array order, so the root
  // does not depend on how the database happened to return rows.
  const root =
    nodes.find((node) => node.node_type === 'CORRELATION') ??
    nodes.find((node) => node.id === rootId) ??
    [...nodes].sort((a, b) => a.id.localeCompare(b.id))[0]

  const depth = new Map<string, number>([[root.id, 0]])
  const queue = [root.id]
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
    if (!depth.has(node.id)) {
      // A node reachable only through inbound edges is pinned to the deepest
      // layer. Deterministic, and visibly separated rather than hidden.
      depth.set(node.id, maxDepth)
    } else {
      maxDepth = Math.max(maxDepth, depth.get(node.id) as number)
    }
  }

  const columns = new Map<number, KnowledgeNode[]>()
  for (const node of nodes) {
    const layer = depth.get(node.id) ?? maxDepth
    const list = columns.get(layer) ?? []
    list.push(node)
    columns.set(layer, list)
  }

  const sortedLayers = [...columns.keys()].sort((a, b) => a - b)
  const position = new Map<string, Position>()
  let height = NODE_H
  for (const layer of sortedLayers) {
    const column = columns.get(layer) ?? []
    column.sort((a, b) => {
      const orderA = KG_TYPE_ORDER[a.node_type as KnowledgeNodeType] ?? 99
      const orderB = KG_TYPE_ORDER[b.node_type as KnowledgeNodeType] ?? 99
      return orderA !== orderB ? orderA - orderB : a.id.localeCompare(b.id)
    })
    column.forEach((node, index) => {
      position.set(node.id, {
        x: layer * (NODE_W + GAP_X),
        y: index * (NODE_H + GAP_Y),
      })
    })
    height = Math.max(height, column.length * (NODE_H + GAP_Y) - GAP_Y + NODE_H)
  }
  const width = (sortedLayers.length - 1) * (NODE_W + GAP_X) + NODE_W
  return { position, width, height }
}

export function KnowledgeGraphView({
  nodes,
  edges,
  rootNodeId,
  selectedNodeId,
  onSelectNode,
}: {
  nodes: KnowledgeNode[]
  edges: KnowledgeEdge[]
  rootNodeId: string | null
  selectedNodeId: string | null
  onSelectNode: (nodeId: string | null) => void
}) {
  const { position, width, height } = useMemo(
    () => layoutGraph(nodes, edges, rootNodeId),
    [nodes, edges, rootNodeId],
  )
  const [zoom, setZoom] = useState(1)
  const [offset, setOffset] = useState({ x: 24, y: 24 })
  const drag = useRef<{ startX: number; startY: number; ox: number; oy: number } | null>(null)

  const orderedNodes = [...nodes].sort((a, b) => a.id.localeCompare(b.id))
  const orderedEdges = [...edges].sort((a, b) => a.id.localeCompare(b.id))

  if (orderedNodes.length === 0) return null

  const edgePath = (edge: KnowledgeEdge): string => {
    const source = position.get(edge.source_node_id)
    const target = position.get(edge.target_node_id)
    if (!source || !target) return ''
    const x1 = source.x + NODE_W
    const y1 = source.y + NODE_H / 2
    const x2 = target.x
    const y2 = target.y + NODE_H / 2
    return `M ${x1} ${y1} C ${x1 + 60} ${y1}, ${x2 - 60} ${y2}, ${x2} ${y2}`
  }

  return (
    <div className="overflow-hidden rounded border border-edge-soft bg-surface-1">
      <div className="flex items-center justify-between border-b border-edge-soft px-2 py-1.5">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">
          Deterministic layered layout · {orderedNodes.length} nodes ·{' '}
          {orderedEdges.length} edges
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            aria-label="Zoom in"
            onClick={() => setZoom((z) => Math.min(3, z + 0.25))}
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            aria-label="Zoom out"
            onClick={() => setZoom((z) => Math.max(0.25, z - 0.25))}
          >
            <Minus className="h-3.5 w-3.5" aria-hidden="true" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            aria-label="Reset view"
            onClick={() => {
              setZoom(1)
              setOffset({ x: 24, y: 24 })
            }}
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
          </Button>
        </div>
      </div>
      <div className="max-h-[560px] overflow-auto p-2">
        <svg
          role="img"
          aria-label="Knowledge graph"
          data-testid="knowledge-graph"
          className="h-auto w-full min-w-[780px] select-none"
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
            drag.current = {
              startX: event.clientX,
              startY: event.clientY,
              ox: offset.x,
              oy: offset.y,
            }
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
              id="knowledge-graph-arrow"
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
              <g key={edge.id}>
                <path
                  data-testid={`knowledge-edge-${edge.id}`}
                  d={edgePath(edge)}
                  fill="none"
                  stroke="#4a5a6e"
                  strokeWidth={1.5}
                  markerEnd="url(#knowledge-graph-arrow)"
                />
                {/* The auditor's first question about an edge is what proves
                    it, so the citation is the edge's tooltip. */}
                <title>
                  {`${KG_RELATIONSHIP_LABELS[edge.relationship_type]} · ${edge.source_reference}`}
                </title>
              </g>
            ))}
            {orderedNodes.map((node) => {
              const pos = position.get(node.id)
              if (!pos) return null
              const color = KG_NODE_COLORS[node.node_type] ?? '#8fa3bd'
              const label = KG_NODE_LABELS[node.node_type] ?? node.node_type
              const selected = selectedNodeId === node.id
              return (
                <g
                  key={node.id}
                  data-testid={`knowledge-node-${node.id}`}
                  className="cursor-pointer"
                  onClick={(event) => {
                    event.stopPropagation()
                    onSelectNode(selected ? null : node.id)
                  }}
                  aria-label={`${label} node ${node.label}`}
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
                  <circle cx={pos.x + 16} cy={pos.y + 17} r={3.5} fill={color} />
                  <text
                    x={pos.x + 26}
                    y={pos.y + 20}
                    fontSize="9.5"
                    letterSpacing="0.08em"
                    fill={color}
                  >
                    {label.toUpperCase()}
                  </text>
                  <text x={pos.x + 12} y={pos.y + 36} fontSize="11" fill="#d6dde7">
                    {node.label.length > 24 ? `${node.label.slice(0, 23)}…` : node.label}
                  </text>
                  <text x={pos.x + 12} y={pos.y + 47} fontSize="8.5" fill="#6b7a8d">
                    {node.provenance.replace(/_/g, ' ')}
                  </text>
                  <title>{`${label} · ${node.label}\n${node.source_reference}\nprovenance: ${node.provenance}`}</title>
                </g>
              )
            })}
          </g>
        </svg>
      </div>
    </div>
  )
}