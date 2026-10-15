import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ChevronLeft, Network } from 'lucide-react'
import { knowledgeGraphApi } from '../api/knowledge-graph'
import { correlationsApi } from '../api/correlations'
import { KnowledgeGraphView } from '../components/knowledge-graph'
import {
  EmptyState,
  ErrorState,
  LoadingRows,
  NotAvailable,
} from '../components/states'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { MonoId } from '../components/ui/mono-id'
import { Td, Th, TRow, Table } from '../components/ui/table'
import { formatDateTime, shortId } from '../lib/formats'
import {
  KG_NODE_LABELS,
  KG_RELATIONSHIP_LABELS,
} from '../lib/labels'
import { ApiError } from '../api/client'
import type {
  KnowledgeEdge,
  KnowledgeNode,
  KnowledgeNodeType,
  KnowledgeRelationshipType,
} from '../types/api'

function isMissing(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404
}

export function KnowledgeGraphPage() {
  const { correlationId = '' } = useParams()
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null)

  const graphQuery = useQuery({
    queryKey: ['knowledge-graph', 'correlation', correlationId],
    queryFn: () => knowledgeGraphApi.correlationGraph(correlationId),
    enabled: correlationId.length > 0,
  })

  const traversal = graphQuery.data

  // The bare /knowledge-graph route is a real entry point rather than a dead
  // end: it lists persisted correlations so a graph can be opened without
  // hand-editing the URL.  Nothing is auto-selected, because silently
  // projecting an arbitrary correlation would misrepresent which incident the
  // graph describes.
  const correlations = useQuery({
    queryKey: ['correlations', 'recent', 50],
    queryFn: () => correlationsApi.recent(50),
    enabled: correlationId.length === 0,
  })
  const availableCorrelations = correlations.data ?? []

  if (!correlationId) {
    return (
      <div className="mx-auto max-w-7xl space-y-4">
        <PageHeader
          title="Knowledge Graph"
          description="V3.22 deterministic relationship layer over persisted V2 evidence — every node and edge cites the exact record that justifies it."
        >
          <Button asChild variant="outline" size="sm">
            <Link to="/correlations">
              <ChevronLeft className="h-3.5 w-3.5" />
              Correlations
            </Link>
          </Button>
        </PageHeader>
        <Panel
          title="Choose a correlation"
          subtitle="The graph is derived from recorded V2 rows only, so it is built for one correlation at a time."
          padded={false}
          data-testid="knowledge-graph-picker"
        >
          {correlations.isLoading ? (
            <LoadingRows rows={6} />
          ) : correlations.isError ? (
            <ErrorState
              message={String(correlations.error)}
              onRetry={() => void correlations.refetch()}
            />
          ) : availableCorrelations.length === 0 ? (
            <NotAvailable
              title="No correlations persisted"
              body="The knowledge graph reads already-persisted detections, correlations, risk assessments, hunts, approvals and reports. Nothing has been correlated yet, so there is no graph to derive."
            />
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Correlation</Th>
                  <Th>Status</Th>
                  <Th>Members</Th>
                  <Th>Observed</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {availableCorrelations.map((row) => (
                  <TRow key={row.correlation_id}>
                    <Td className="font-mono text-[11px] text-ink">
                      <MonoId id={row.correlation_id} />
                    </Td>
                    <Td className="text-[11px] text-ink-dim">{row.status}</Td>
                    <Td className="font-mono text-[11px] text-ink-dim">
                      {row.members.length}
                    </Td>
                    <Td className="text-[11px] text-ink-dim">
                      {formatDateTime(row.timestamp)}
                    </Td>
                    <Td>
                      <Button asChild size="sm" variant="outline">
                        <Link to={`/knowledge-graph/${row.correlation_id}`}>
                          <Network className="h-3 w-3" aria-hidden="true" />
                          View graph
                        </Link>
                      </Button>
                    </Td>
                  </TRow>
                ))}
              </tbody>
            </Table>
          )}
        </Panel>
      </div>
    )
  }

  if (graphQuery.isLoading) {
    return <LoadingRows rows={8} />
  }

  if (graphQuery.isError) {
    if (isMissing(graphQuery.error)) {
      return (
        <div className="mx-auto max-w-7xl space-y-4">
          <PageHeader title="Knowledge Graph" />
          <Panel>
            <NotAvailable
              title="No graph for this correlation"
              body="The graph is derived only from persisted V2 rows, and this correlation has none derived yet. Run `app.cli build-knowledge-graph --correlation-id <id>` to materialize it."
            />
          </Panel>
        </div>
      )
    }
    return (
      <ErrorState
        message={String(graphQuery.error)}
        onRetry={() => void graphQuery.refetch()}
      />
    )
  }

  if (!traversal) {
    return <EmptyState title="Knowledge graph not found" />
  }

  const nodeById = new Map(traversal.nodes.map((node) => [node.id, node]))
  const selectedNode = selectedNodeId
    ? nodeById.get(selectedNodeId) ?? null
    : null
  const selectedEdge = selectedEdgeId
    ? traversal.edges.find((edge) => edge.id === selectedEdgeId) ?? null
    : null

  // Edges touching the selected node, so selecting a node immediately shows
  // the evidence that connects it to the rest of the graph.
  const incidentEdges = selectedNode
    ? traversal.edges.filter(
        (edge) =>
          edge.source_node_id === selectedNode.id ||
          edge.target_node_id === selectedNode.id,
      )
    : []

  const counts = countBy(traversal.nodes)

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title={
          <span className="inline-flex items-center gap-2">
            <Network className="h-4 w-4 text-accent" aria-hidden="true" />
            Knowledge Graph{' '}
            <span className="font-mono text-sm text-accent">
              {shortId(correlationId)}
            </span>
          </span>
        }
        description="Deterministic relationship graph over persisted V2 evidence. Every node maps to a stored record and every edge cites the exact row that justifies it — nothing here is inferred, predicted, or generated."
      >
        <Button asChild variant="outline" size="sm">
          <Link to="/correlations">
            <ChevronLeft className="h-3.5 w-3.5" />
            Correlations
          </Link>
        </Button>
      </PageHeader>

      {traversal.truncated && (
        <div
          role="status"
          data-testid="knowledge-graph-truncation"
          className="flex items-start gap-2 rounded border border-edge-soft bg-surface-2 px-3 py-2"
        >
          <AlertTriangle
            className="mt-0.5 h-3.5 w-3.5 shrink-0 text-medium"
            aria-hidden="true"
          />
          <div className="text-[11px] text-ink-dim">
            This view is truncated at{' '}
            <span className="font-mono text-ink">
              {traversal.truncated_reason ?? 'a traversal bound'}
            </span>
            . Only {traversal.node_count} nodes and {traversal.edge_count} edges
            are shown out of a graph bounded at {traversal.bounds.max_nodes}{' '}
            nodes / {traversal.bounds.max_edges} edges / depth{' '}
            {traversal.bounds.max_depth}. Narrow with a node's neighbours to see
            less, not more.
          </div>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Nodes" value={traversal.node_count} />
        <Stat label="Edges" value={traversal.edge_count} />
        <Stat label="Detections" value={counts.DETECTION ?? 0} />
        <Stat label="Depth reached" value={traversal.max_depth_reached} />
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="space-y-4">
          <Panel
            title="Graph"
            subtitle="Select a node to inspect its provenance, or an edge to see what proves it."
            padded={false}
          >
            <KnowledgeGraphView
              nodes={traversal.nodes}
              edges={traversal.edges}
              rootNodeId={traversal.root_node_id}
              selectedNodeId={selectedNodeId}
              onSelectNode={(id) => {
                setSelectedNodeId(id)
                setSelectedEdgeId(null)
              }}
            />
          </Panel>

          <Panel
            title="Edges"
            subtitle="Every relationship, with the persisted row that justifies it."
            padded={false}
          >
            {traversal.edges.length === 0 ? (
              <div className="p-4">
                <EmptyState title="No edges derived for this correlation" />
              </div>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Relationship</Th>
                    <Th>Source record</Th>
                    <Th>Evidence</Th>
                    <Th />
                  </tr>
                </thead>
                <tbody>
                  {[...traversal.edges]
                    .sort((a, b) => a.id.localeCompare(b.id))
                    .map((edge) => (
                      <TRow key={edge.id}>
                        <Td className="text-[11px] text-ink">
                          {KG_RELATIONSHIP_LABELS[
                            edge.relationship_type as KnowledgeRelationshipType
                          ] ?? edge.relationship_type}
                        </Td>
                        <Td className="font-mono text-[10px] text-ink-dim">
                          {edge.source_reference}
                        </Td>
                        <Td className="font-mono text-[10px] text-ink-faint">
                          {edge.evidence_references.length}
                        </Td>
                        <Td>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setSelectedEdgeId(edge.id === selectedEdgeId ? null : edge.id)
                              setSelectedNodeId(null)
                            }}
                          >
                            {edge.id === selectedEdgeId ? 'Hide' : 'Inspect'}
                          </Button>
                        </Td>
                      </TRow>
                    ))}
                </tbody>
              </Table>
            )}
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel
            title="Node"
            subtitle={selectedNode ? 'Selected node and its provenance.' : 'Select a node in the graph.'}
          >
            {selectedNode ? (
              <NodeDetail node={selectedNode} edges={incidentEdges} />
            ) : (
              <div className="text-[11px] text-ink-faint">
                No node selected. Every node carries the persisted V2 record it
                was derived from — select one to read that citation.
              </div>
            )}
          </Panel>

          <Panel
            title="Edge evidence"
            subtitle={
              selectedEdge
                ? 'What proves this relationship.'
                : 'Select an edge, or a node, to see the rows behind it.'
            }
          >
            {selectedEdge ? (
              <EdgeDetail edge={selectedEdge} />
            ) : selectedNode && incidentEdges.length > 0 ? (
              <ul className="space-y-2">
                {incidentEdges.map((edge) => (
                  <li
                    key={edge.id}
                    data-testid={`knowledge-incident-${edge.id}`}
                    className="rounded border border-edge-soft bg-surface-2 px-2 py-1.5"
                  >
                    <div className="text-[11px] text-ink">
                      {KG_RELATIONSHIP_LABELS[
                        edge.relationship_type as KnowledgeRelationshipType
                      ] ?? edge.relationship_type}
                    </div>
                    <div className="mt-0.5 font-mono text-[10px] text-ink-faint">
                      {edge.source_reference}
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-[11px] text-ink-faint">
                Nothing selected. No relationship is ever shown without the
                persisted row that backs it.
              </div>
            )}
          </Panel>

          {traversal.unavailable_entity_types &&
            Object.keys(traversal.unavailable_entity_types).length > 0 && (
              <Panel
                title="Not representable"
                subtitle="V2 persists no identity for these, so the graph cannot show them."
              >
                <ul className="space-y-2" data-testid="knowledge-unavailable">
                  {Object.entries(traversal.unavailable_entity_types).map(
                    ([entity, reason]) => (
                      <li key={entity} className="text-[11px] text-ink-dim">
                        <span className="font-medium text-ink">{entity}</span>{' '}
                        — {reason}
                      </li>
                    ),
                  )}
                </ul>
              </Panel>
            )}
        </div>
      </div>
    </div>
  )
}

function NodeDetail({
  node,
  edges,
}: {
  node: KnowledgeNode
  edges: KnowledgeEdge[]
}) {
  const metadata = Object.entries(node.metadata)
  return (
    <div className="space-y-3" data-testid="knowledge-node-detail">
      <div>
        <Badge tone="neutral">
          {KG_NODE_LABELS[node.node_type as KnowledgeNodeType] ??
            node.node_type}
        </Badge>
        <div className="mt-1.5 text-[12px] text-ink">{node.label}</div>
      </div>
      <dl className="space-y-1.5 text-[11px]">
        <div className="flex justify-between gap-2">
          <dt className="text-ink-faint">V2 record</dt>
          <dd className="font-mono text-ink-dim">{node.source_reference}</dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-ink-faint">Provenance</dt>
          <dd className="font-mono text-ink-dim">
            {node.provenance.replace(/_/g, ' ')}
          </dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-ink-faint">Observed</dt>
          <dd className="text-ink-dim">
            {node.observed_at ? formatDateTime(node.observed_at) : '—'}
          </dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-ink-faint">Relationships</dt>
          <dd className="font-mono text-ink-dim">{edges.length}</dd>
        </div>
      </dl>
      {metadata.length > 0 && (
        <div>
          <div className="mb-1 text-[10px] uppercase tracking-wider text-ink-faint">
            Attributes
          </div>
          <dl className="space-y-1">
            {metadata.map(([key, value]) => (
              <div key={key} className="flex justify-between gap-2 text-[11px]">
                <dt className="text-ink-faint">{key.replace(/_/g, ' ')}</dt>
                <dd className="font-mono text-ink-dim">{String(value)}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  )
}

function EdgeDetail({ edge }: { edge: KnowledgeEdge }) {
  return (
    <div className="space-y-2" data-testid="knowledge-edge-detail">
      <div className="text-[12px] text-ink">
        {KG_RELATIONSHIP_LABELS[
          edge.relationship_type as KnowledgeRelationshipType
        ] ?? edge.relationship_type}
      </div>
      <div>
        <div className="mb-1 text-[10px] uppercase tracking-wider text-ink-faint">
          Justifying record
        </div>
        <div className="font-mono text-[10px] text-ink-dim">
          {edge.source_reference}
        </div>
      </div>
      <div>
        <div className="mb-1 text-[10px] uppercase tracking-wider text-ink-faint">
          Evidence references
        </div>
        <ul className="space-y-1">
          {edge.evidence_references.map((reference) => (
            <li
              key={reference}
              className="font-mono text-[10px] text-ink-dim"
              data-testid="knowledge-evidence-reference"
            >
              {reference}
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}

function countBy(nodes: KnowledgeNode[]): Partial<Record<KnowledgeNodeType, number>> {
  const counts: Partial<Record<KnowledgeNodeType, number>> = {}
  for (const node of nodes) {
    const type = node.node_type as KnowledgeNodeType
    counts[type] = (counts[type] ?? 0) + 1
  }
  return counts
}