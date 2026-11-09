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
 * Self-contained SVG — no graph library. The layout is deterministic and
 * direction-preserving: a topological layering (longest path over the graph
 * with cycle-closing edges removed by a deterministic depth-first pass) gives
 * every record its own column, so all arrows point the way the evidence
 * actually flows — events on the left, assessments on the right — and a
 * relationship is never reversed to make the drawing tidy. Cycle members keep
 * their real edges, which are routed over a lane above the diagram.
 *
 * Within a column, nodes are ordered by barycentre sweeps seeded with
 * (node type, node id) to minimise crossings, then each column is vertically
 * centred. Identical payloads always render identical geometry regardless of
 * the order rows came back from the database.
 *
 * Node bodies are sized for readable text (two wrapped label lines plus
 * provenance); full identifiers always stay in the tooltip. Only the
 * selected node's one-hop neighbourhood stays lit — everything else dims —
 * and a glow is used exclusively for the selection.
 */

const NODE_W = 240
const NODE_H = 76
const GAP_X = 76
const GAP_Y = 18
const PAD_X = 64
const PAD_TOP = 72
const PAD_BOTTOM = 56
const MIN_VIEW_W = 960
const MIN_VIEW_H = 480
const LANE_Y = -40
const LANE_STEP = 9
const MAX_LANES = 4
const TITLE_MAX = 30
const PROVENANCE_MAX = 40

const EDGE_BASE = '#55677e'
const EDGE_ACTIVE = '#a8bcd2'
const EDGE_DIM = '#39434f'
const FILL_BASE = '#161d26'
const FILL_ROOT = '#172130'
const FILL_SELECTED = '#1a2430'

interface Position {
  x: number
  y: number
}

interface GraphLayout {
  position: Map<string, Position>
  layer: Map<string, number>
  width: number
  height: number
}

function wrapLabel(text: string, maxChars: number, maxLines: number): string[] {
  const words = text.trim().split(/\s+/).filter((word) => word.length > 0)
  if (words.length === 0) return []
  const lines: string[] = []
  let current = ''
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word
    if (candidate.length <= maxChars) {
      current = candidate
      continue
    }
    if (current) {
      lines.push(current)
    }
    current = word.length <= maxChars ? word : `${word.slice(0, maxChars - 1)}…`
    if (lines.length >= maxLines) {
      current = ''
      break
    }
  }
  if (current) lines.push(current)
  const kept = lines.slice(0, maxLines)
  const shown = kept.join(' ')
  const expected = words.join(' ')
  if (kept.length > 0 && shown.length < expected.length) {
    const last = kept[kept.length - 1]
    if (!last.endsWith('…')) {
      kept[kept.length - 1] = `${last.slice(0, maxChars - 1)}…`
    }
  }
  return kept
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

function smoothWaypoints(points: Position[], radius = 10): string {
  const path: Position[] = []
  for (const point of points) {
    const last = path[path.length - 1]
    if (!last || last.x !== point.x || last.y !== point.y) path.push(point)
  }
  if (path.length === 0) return ''
  if (path.length === 1) return `M ${path[0].x} ${path[0].y}`
  let d = `M ${path[0].x} ${path[0].y}`
  for (let i = 1; i < path.length - 1; i += 1) {
    const prev = path[i - 1]
    const cur = path[i]
    const next = path[i + 1]
    const inLength = Math.hypot(cur.x - prev.x, cur.y - prev.y)
    const outLength = Math.hypot(next.x - cur.x, next.y - cur.y)
    const r = Math.min(radius, inLength / 2, outLength / 2)
    const inX = cur.x - ((cur.x - prev.x) / (inLength || 1)) * r
    const inY = cur.y - ((cur.y - prev.y) / (inLength || 1)) * r
    const outX = cur.x + ((next.x - cur.x) / (outLength || 1)) * r
    const outY = cur.y + ((next.y - cur.y) / (outLength || 1)) * r
    d += ` L ${inX} ${inY} Q ${cur.x} ${cur.y} ${outX} ${outY}`
  }
  const lastPoint = path[path.length - 1]
  d += ` L ${lastPoint.x} ${lastPoint.y}`
  return d
}

function layoutGraph(nodes: KnowledgeNode[], edges: KnowledgeEdge[]): GraphLayout {
  const empty: GraphLayout = {
    position: new Map(),
    layer: new Map(),
    width: 0,
    height: 0,
  }
  if (nodes.length === 0) return empty

  const sortedNodes = [...nodes].sort((a, b) => a.id.localeCompare(b.id))
  const known = new Set(sortedNodes.map((node) => node.id))
  const sortedEdges = [...edges]
    .sort((a, b) => a.id.localeCompare(b.id))
    .filter((edge) => known.has(edge.source_node_id) && known.has(edge.target_node_id))

  const adjacency = new Map<string, { target: string; edgeId: string }[]>()
  const incoming = new Map<string, string[]>()
  const outgoing = new Map<string, string[]>()
  for (const node of sortedNodes) {
    adjacency.set(node.id, [])
    incoming.set(node.id, [])
    outgoing.set(node.id, [])
  }
  for (const edge of sortedEdges) {
    adjacency.get(edge.source_node_id)?.push({
      target: edge.target_node_id,
      edgeId: edge.id,
    })
    outgoing.get(edge.source_node_id)?.push(edge.target_node_id)
    incoming.get(edge.target_node_id)?.push(edge.source_node_id)
  }

  const backEdges = new Set<string>()
  const visit = new Map<string, 'open' | 'done'>()
  for (const seed of sortedNodes) {
    if (visit.has(seed.id)) continue
    const stack: { id: string; cursor: number }[] = [{ id: seed.id, cursor: 0 }]
    visit.set(seed.id, 'open')
    while (stack.length > 0) {
      const frame = stack[stack.length - 1]
      const links = adjacency.get(frame.id) ?? []
      if (frame.cursor >= links.length) {
        visit.set(frame.id, 'done')
        stack.pop()
        continue
      }
      const link = links[frame.cursor]
      frame.cursor += 1
      if (link.target === frame.id) {
        backEdges.add(link.edgeId)
        continue
      }
      const state = visit.get(link.target)
      if (state === 'open') {
        backEdges.add(link.edgeId)
      } else if (state === undefined) {
        visit.set(link.target, 'open')
        stack.push({ id: link.target, cursor: 0 })
      }
    }
  }

  const dagOutgoing = new Map<string, string[]>()
  for (const node of sortedNodes) dagOutgoing.set(node.id, [])
  for (const edge of sortedEdges) {
    if (backEdges.has(edge.id)) continue
    dagOutgoing.get(edge.source_node_id)?.push(edge.target_node_id)
  }

  const indegree = new Map<string, number>()
  for (const node of sortedNodes) indegree.set(node.id, 0)
  for (const node of sortedNodes) {
    for (const target of dagOutgoing.get(node.id) ?? []) {
      indegree.set(target, (indegree.get(target) ?? 0) + 1)
    }
  }

  const layer = new Map<string, number>()
  const ready: string[] = []
  for (const node of sortedNodes) {
    if (indegree.get(node.id) === 0) {
      layer.set(node.id, 0)
      ready.push(node.id)
    }
  }
  let head = 0
  while (head < ready.length) {
    const current = ready[head]
    head += 1
    const nextLayer = (layer.get(current) ?? 0) + 1
    for (const target of dagOutgoing.get(current) ?? []) {
      if (nextLayer > (layer.get(target) ?? 0)) layer.set(target, nextLayer)
      const left = (indegree.get(target) ?? 0) - 1
      indegree.set(target, left)
      if (left === 0) ready.push(target)
    }
  }
  let deepest = 0
  for (const value of layer.values()) deepest = Math.max(deepest, value)
  for (const node of sortedNodes) {
    if (!layer.has(node.id)) layer.set(node.id, deepest + 1)
  }

  const columns = new Map<number, KnowledgeNode[]>()
  for (const node of sortedNodes) {
    const key = layer.get(node.id) ?? 0
    const column = columns.get(key) ?? []
    column.push(node)
    columns.set(key, column)
  }
  const layerKeys = [...columns.keys()].sort((a, b) => a - b)

  const typeRank = (node: KnowledgeNode) =>
    KG_TYPE_ORDER[node.node_type as KnowledgeNodeType] ?? 99
  const byTypeThenId = (a: KnowledgeNode, b: KnowledgeNode) =>
    typeRank(a) !== typeRank(b) ? typeRank(a) - typeRank(b) : a.id.localeCompare(b.id)

  const rank = new Map<string, number>()
  for (const key of layerKeys) {
    const column = columns.get(key) as KnowledgeNode[]
    column.sort(byTypeThenId)
    column.forEach((node, index) => rank.set(node.id, index))
  }

  const relax = (key: number, links: Map<string, string[]>) => {
    const column = columns.get(key) as KnowledgeNode[]
    const bary = new Map<string, number>()
    for (const node of column) {
      let sum = 0
      let count = 0
      for (const neighbour of links.get(node.id) ?? []) {
        const refColumn = columns.get(layer.get(neighbour) ?? -1)
        const at = rank.get(neighbour)
        if (!refColumn || at === undefined || refColumn === column) continue
        sum += at / Math.max(1, refColumn.length - 1)
        count += 1
      }
      const own = (rank.get(node.id) ?? 0) / Math.max(1, column.length - 1)
      bary.set(node.id, count > 0 ? sum / count : own)
    }
    column.sort((a, b) => {
      const ba = bary.get(a.id) as number
      const bb = bary.get(b.id) as number
      return ba !== bb ? ba - bb : byTypeThenId(a, b)
    })
    column.forEach((node, index) => rank.set(node.id, index))
  }

  for (let pass = 0; pass < 3; pass += 1) {
    for (let i = 1; i < layerKeys.length; i += 1) relax(layerKeys[i], incoming)
    for (let i = 0; i < layerKeys.length - 1; i += 1) relax(layerKeys[i], outgoing)
  }

  const spans = new Map<number, number>()
  let contentHeight = NODE_H
  for (const key of layerKeys) {
    const column = columns.get(key) as KnowledgeNode[]
    const span = column.length * NODE_H + Math.max(0, column.length - 1) * GAP_Y
    spans.set(key, span)
    contentHeight = Math.max(contentHeight, span)
  }

  const position = new Map<string, Position>()
  for (const key of layerKeys) {
    const column = columns.get(key) as KnowledgeNode[]
    const start = (contentHeight - (spans.get(key) as number)) / 2
    column.forEach((node, index) => {
      position.set(node.id, {
        x: key * (NODE_W + GAP_X),
        y: start + index * (NODE_H + GAP_Y),
      })
    })
  }

  const width =
    layerKeys.length > 0
      ? layerKeys[layerKeys.length - 1] * (NODE_W + GAP_X) + NODE_W
      : 0
  return { position, layer, width, height: contentHeight }
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
  const { position, layer, width, height } = useMemo(
    () => layoutGraph(nodes, edges),
    [nodes, edges],
  )
  const orderedNodes = useMemo(
    () => [...nodes].sort((a, b) => a.id.localeCompare(b.id)),
    [nodes],
  )
  const orderedEdges = useMemo(
    () => [...edges].sort((a, b) => a.id.localeCompare(b.id)),
    [edges],
  )

  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState<{ w: number; h: number; offset: Position } | null>(
    null,
  )
  const drag = useRef<{ startX: number; startY: number; ox: number; oy: number } | null>(
    null,
  )

  const viewW = Math.max(width + PAD_X * 2, MIN_VIEW_W)
  const viewH = Math.max(height + PAD_TOP + PAD_BOTTOM, MIN_VIEW_H)
  const centered = useMemo(
    () => ({
      x: (viewW - width) / 2,
      y: (viewH - height) / 2 + (PAD_TOP - PAD_BOTTOM) / 2,
    }),
    [viewW, viewH, width, height],
  )
  const offset = pan && pan.w === width && pan.h === height ? pan.offset : null
  const origin = offset ?? centered

  const neighbourhood = useMemo(() => {
    if (!selectedNodeId) return null
    const near = new Set<string>([selectedNodeId])
    for (const edge of orderedEdges) {
      if (edge.source_node_id === selectedNodeId) near.add(edge.target_node_id)
      else if (edge.target_node_id === selectedNodeId) near.add(edge.source_node_id)
    }
    return near
  }, [selectedNodeId, orderedEdges])

  const activeEdgeIds = useMemo(() => {
    if (!selectedNodeId) return null
    const ids = new Set<string>()
    for (const edge of orderedEdges) {
      if (
        edge.source_node_id === selectedNodeId ||
        edge.target_node_id === selectedNodeId
      ) {
        ids.add(edge.id)
      }
    }
    return ids
  }, [selectedNodeId, orderedEdges])

  const lanes = useMemo(() => {
    const map = new Map<string, { lane: number }>()
    let slot = 0
    for (const edge of orderedEdges) {
      const source = position.get(edge.source_node_id)
      const target = position.get(edge.target_node_id)
      if (!source || !target || edge.source_node_id === edge.target_node_id) continue
      const from = layer.get(edge.source_node_id) ?? 0
      const to = layer.get(edge.target_node_id) ?? 0
      if (to === from || to === from + 1) continue
      map.set(edge.id, { lane: slot % MAX_LANES })
      slot += 1
    }
    return map
  }, [orderedEdges, position, layer])

  if (orderedNodes.length === 0) return null

  const edgePath = (edge: KnowledgeEdge): string => {
    const source = position.get(edge.source_node_id)
    const target = position.get(edge.target_node_id)
    if (!source || !target) return ''

    if (edge.source_node_id === edge.target_node_id) {
      const x = source.x + NODE_W
      const y = source.y + NODE_H / 2
      return `M ${x} ${y} C ${x + 44} ${y - 34}, ${x + 44} ${y + 34}, ${x} ${y}`
    }

    const from = layer.get(edge.source_node_id) ?? 0
    const to = layer.get(edge.target_node_id) ?? 0
    const startX = source.x + NODE_W
    const startY = source.y + NODE_H / 2
    const endX = target.x
    const endY = target.y + NODE_H / 2

    if (to === from) {
      const mid = source.x + NODE_W / 2
      return target.y > source.y
        ? `M ${mid} ${source.y + NODE_H} L ${mid} ${target.y}`
        : `M ${mid} ${source.y} L ${mid} ${target.y + NODE_H}`
    }

    if (to === from + 1) {
      const reach = GAP_X * 0.45
      return `M ${startX} ${startY} C ${startX + reach} ${startY}, ${endX - reach} ${endY}, ${endX} ${endY}`
    }

    const slot = lanes.get(edge.id)?.lane ?? 0
    const laneY = LANE_Y - slot * LANE_STEP
    const nudge = slot * 5
    const exitX = startX + GAP_X / 2 + nudge
    const enterX = endX - GAP_X / 2 - nudge
    return smoothWaypoints([
      { x: startX, y: startY },
      { x: exitX, y: startY },
      { x: exitX, y: laneY },
      { x: enterX, y: laneY },
      { x: enterX, y: endY },
      { x: endX, y: endY },
    ])
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
              setPan(null)
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
          className="h-auto w-full min-w-[900px] select-none"
          style={{ aspectRatio: `${viewW} / ${viewH}` }}
          viewBox={`0 0 ${viewW} ${viewH}`}
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
              ox: origin.x,
              oy: origin.y,
            }
          }}
          onPointerMove={(event) => {
            if (!drag.current) return
            setPan({
              w: width,
              h: height,
              offset: {
                x: drag.current.ox + (event.clientX - drag.current.startX),
                y: drag.current.oy + (event.clientY - drag.current.startY),
              },
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
              <path d="M 0 0 L 10 5 L 0 10 z" fill={EDGE_BASE} />
            </marker>
            <marker
              id="knowledge-graph-arrow-active"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="8"
              markerHeight="8"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill={EDGE_ACTIVE} />
            </marker>
            <filter
              id="knowledge-graph-glow"
              x="-40%"
              y="-40%"
              width="180%"
              height="180%"
            >
              <feGaussianBlur in="SourceGraphic" stdDeviation="3.5" result="glow" />
              <feMerge>
                <feMergeNode in="glow" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <rect x="0" y="0" width={viewW} height={viewH} fill="transparent" />
          <g
            data-testid="knowledge-graph-content"
            transform={`translate(${origin.x} ${origin.y}) scale(${zoom})`}
          >
            {orderedEdges.map((edge) => {
              const active = activeEdgeIds?.has(edge.id) ?? false
              const dimmed = activeEdgeIds ? !active : false
              let stroke = EDGE_BASE
              let strokeWidth = 1.5
              let markerEnd: string | undefined = 'url(#knowledge-graph-arrow)'
              let opacity = 1
              if (active) {
                stroke = EDGE_ACTIVE
                strokeWidth = 2
                markerEnd = 'url(#knowledge-graph-arrow-active)'
              } else if (dimmed) {
                stroke = EDGE_DIM
                strokeWidth = 1
                markerEnd = undefined
                opacity = 0.4
              }
              return (
                <g key={edge.id}>
                  <path
                    data-testid={`knowledge-edge-${edge.id}`}
                    d={edgePath(edge)}
                    fill="none"
                    stroke={stroke}
                    strokeWidth={strokeWidth}
                    opacity={opacity}
                    markerEnd={markerEnd}
                  />
                  {/* The auditor's first question about an edge is what proves
                      it, so the citation is the edge's tooltip. */}
                  <title>
                    {`${KG_RELATIONSHIP_LABELS[edge.relationship_type]} · ${edge.source_reference}`}
                  </title>
                </g>
              )
            })}
            {orderedNodes.map((node) => {
              const pos = position.get(node.id)
              if (!pos) return null
              const color = KG_NODE_COLORS[node.node_type] ?? '#8fa3bd'
              const typeLabel = KG_NODE_LABELS[node.node_type] ?? node.node_type
              const selected = selectedNodeId === node.id
              const root = rootNodeId === node.id
              const lit = !neighbourhood || neighbourhood.has(node.id)
              const labelLines = wrapLabel(node.label, TITLE_MAX, 2)
              const provenance = truncate(
                node.provenance.replace(/_/g, ' '),
                PROVENANCE_MAX,
              )
              let bodyFill = FILL_BASE
              let bodyStroke = 1.5
              if (selected) {
                bodyFill = FILL_SELECTED
                bodyStroke = 2.6
              } else if (root) {
                bodyFill = FILL_ROOT
                bodyStroke = 2
              }
              return (
                <g
                  key={node.id}
                  data-testid={`knowledge-node-${node.id}`}
                  className="cursor-pointer"
                  opacity={lit ? 1 : 0.4}
                  filter={selected ? 'url(#knowledge-graph-glow)' : undefined}
                  onClick={(event) => {
                    event.stopPropagation()
                    onSelectNode(selected ? null : node.id)
                  }}
                  aria-label={`${typeLabel} node ${node.label}`}
                >
                  {selected && (
                    <rect
                      x={pos.x - 3}
                      y={pos.y - 3}
                      width={NODE_W + 6}
                      height={NODE_H + 6}
                      rx={9}
                      fill="none"
                      stroke={color}
                      strokeWidth={2}
                      opacity={0.7}
                    />
                  )}
                  <rect
                    x={pos.x}
                    y={pos.y}
                    width={NODE_W}
                    height={NODE_H}
                    rx={8}
                    fill={bodyFill}
                    stroke={color}
                    strokeWidth={bodyStroke}
                  />
                  <circle cx={pos.x + 16} cy={pos.y + 16} r={3.5} fill={color} />
                  <text
                    x={pos.x + 26}
                    y={pos.y + 20}
                    fontSize="9.5"
                    letterSpacing="0.12em"
                    fill={color}
                  >
                    {typeLabel.toUpperCase()}
                  </text>
                  {labelLines.map((line, index) => (
                    <text
                      key={`${node.id}-line-${index}`}
                      x={pos.x + 14}
                      y={pos.y + (index === 0 ? 40 : 55)}
                      fontSize="12.5"
                      fill="#d6dde7"
                    >
                      {line}
                    </text>
                  ))}
                  <text x={pos.x + 14} y={pos.y + 70} fontSize="9.5" fill="#6b7a8d">
                    {provenance}
                  </text>
                  <title>{`${typeLabel} · ${node.label}\n${node.source_reference}\nprovenance: ${node.provenance}`}</title>
                </g>
              )
            })}
          </g>
        </svg>
      </div>
    </div>
  )
}
