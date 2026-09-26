import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ChevronLeft, Network } from 'lucide-react'
import { attackPathsApi } from '../api/attack-paths'
import { AttackPathGraph } from '../components/attack-path-graph'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { ProvenanceBadge } from '../components/badges'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { MonoId } from '../components/ui/mono-id'
import { Td, Th, TRow, Table } from '../components/ui/table'
import { formatDateTime, shortId } from '../lib/formats'
import { NODE_LABELS } from '../lib/labels'
import type { AttackPathAvailability, AttackPathNode, InputAvailability } from '../types/api'

const AVAILABILITY_LABELS: Record<InputAvailability, string> = {
  provided: 'provided',
  none_found: 'none found',
  not_provided: 'not provided',
}

function availabilityTone(value: InputAvailability): 'low' | 'muted' | 'accent' {
  if (value === 'provided') return 'low'
  if (value === 'none_found') return 'accent'
  return 'muted'
}

const AVAILABILITY_SECTIONS: Array<{ key: keyof AttackPathAvailability; label: string }> = [
  { key: 'correlation', label: 'Correlation' },
  { key: 'detections', label: 'Detections' },
  { key: 'indicators', label: 'Indicators' },
  { key: 'risk_assessment', label: 'Risk assessment' },
  { key: 'incident_memory', label: 'Incident memory' },
  { key: 'threat_hunts', label: 'Threat hunts' },
  { key: 'policy_decisions', label: 'Policy decisions' },
  { key: 'approvals', label: 'Approvals' },
  { key: 'soar_executions', label: 'SOAR executions' },
  { key: 'investigation', label: 'Investigation' },
  { key: 'attribution', label: 'Attribution' },
  { key: 'security_events', label: 'Security events' },
]

export function AttackPathPage() {
  const { correlationId = '' } = useParams()
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)

  const graphQuery = useQuery({
    queryKey: ['attack-paths', 'graph', correlationId],
    queryFn: () => attackPathsApi.graph(correlationId),
    enabled: correlationId.length > 0,
  })

  const response = graphQuery.data

  if (!correlationId) {
    return (
      <div className="mx-auto max-w-7xl space-y-4">
        <PageHeader
          title="Attack Path"
          description="V2.21 read-only attack-path projection — a deterministic graph of already-persisted relationships, never an inferred attack narrative."
        >
          <Button asChild variant="outline" size="sm">
            <Link to="/correlations">
              <ChevronLeft className="h-3.5 w-3.5" />
              Correlations
            </Link>
          </Button>
        </PageHeader>
        <Panel title="Open a correlation first">
          <NotAvailable
            title="No correlation selected"
            body="Open a correlation and choose View attack path to render its evidence-grounded projection of persisted detections, intelligence, risk, memory, hunts, policy and SOAR records."
          />
        </Panel>
      </div>
    )
  }

  if (graphQuery.isLoading) {
    return <LoadingRows rows={8} />
  }

  if (graphQuery.isError) {
    return (
      <ErrorState
        message={String(graphQuery.error)}
        onRetry={() => graphQuery.refetch()}
      />
    )
  }

  if (!response) {
    return <EmptyState title="Attack path not found" />
  }

  const { graph, metadata, availability } = response
  const selectedNode =
    graph.nodes.find((node) => node.node_id === selectedNodeId) ?? null

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title={
          <span className="inline-flex items-center gap-2">
            <Network className="h-4 w-4 text-accent" aria-hidden="true" />
            Attack Path{' '}
            <span className="font-mono text-sm text-accent">{shortId(metadata.correlation_id)}</span>
          </span>
        }
        description="Read-only, evidence-grounded graph of persisted relationships for this correlation — every node and edge cites its source record. V2.21 never fabricates an attack step."
      >
        <Button asChild variant="outline" size="sm">
          <Link to="/correlations">
            <ChevronLeft className="h-3.5 w-3.5" />
            Correlations
          </Link>
        </Button>
      </PageHeader>

      {metadata.truncated && (
        <div
          className="flex items-start gap-2 rounded border border-high/40 bg-high/10 px-3 py-2 text-[11px] leading-relaxed text-ink"
          data-testid="attack-path-truncated"
        >
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-high" aria-hidden="true" />
          <span>
            <span className="font-semibold">Projection truncated.</span>{' '}
            {metadata.limitation ?? 'A documented bound was reached; nodes were dropped deterministically.'}{' '}
            The graph stops at the bounded surface — it does not silently omit a step without saying so.
          </span>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Nodes" value={metadata.node_count} />
        <Stat label="Edges" value={metadata.edge_count} />
        <Stat label="Truncated" value={metadata.truncated ? 'yes' : 'no'} tone={metadata.truncated ? 'text-high' : 'text-low'} />
        <Stat label="Generated" value={formatDateTime(metadata.generated_at)} />
      </div>

      <Panel
        title="Persisted relationships"
        subtitle="Deterministic layered projection — click a node to inspect its provenance and evidence references."
        padded={false}
        className="overflow-visible"
      >
        {graph.nodes.length === 0 ? (
          <EmptyState
            title="No attack path to render"
            body="This correlation has no persisted relationship records to project."
          />
        ) : (
          <AttackPathGraph
            graph={graph}
            selectedNodeId={selectedNodeId}
            onSelectNode={setSelectedNodeId}
          />
        )}
      </Panel>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-1">
          <Panel title="Availability" subtitle="Per-surface input availability, mirroring the V2.20 report contract">
            <div className="grid grid-cols-2 gap-1.5" data-testid="attack-path-availability">
              {AVAILABILITY_SECTIONS.map(({ key, label }) => (
                <div
                  key={key}
                  className="flex items-center justify-between gap-2 rounded border border-edge-soft px-2 py-1.5"
                >
                  <span className="text-[10px] text-ink-dim">{label}</span>
                  <Badge tone={availabilityTone(availability[key])}>
                    {AVAILABILITY_LABELS[availability[key]]}
                  </Badge>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        <div className="space-y-4 xl:col-span-2">
          <Panel
            title="Selected record"
            subtitle={selectedNode ? 'Source record backing the selected node' : 'Select a node to inspect its provenance and persisted references.'}
            padded={false}
          >
            {selectedNode ? (
              <NodeDetail node={selectedNode} />
            ) : (
              <div className="p-4">
                <NotAvailable
                  title="Nothing selected"
                  body="Click any node in the projection to reveal its type, provenance, occurrence and the exact persisted references that ground it."
                />
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  )
}

function NodeDetail({ node }: { node: AttackPathNode }) {
  const fields = Object.entries(node.fields)
  return (
    <div className="space-y-3 p-4" data-testid="attack-path-node-detail">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="accent">{NODE_LABELS[node.node_type]}</Badge>
        <ProvenanceBadge provenance={node.provenance} />
        {node.severity && <Badge tone="medium">{node.severity}</Badge>}
        {node.status && <Badge tone="muted">{node.status}</Badge>}
      </div>

      <div>
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">Label</div>
        <div className="mt-0.5 text-xs font-medium text-ink">{node.label}</div>
      </div>

      <div className="grid grid-cols-1 gap-3 text-[11px] md:grid-cols-2">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Source reference</div>
          <div className="mt-0.5">
            <MonoId id={node.source_reference} />
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Node ID</div>
          <div className="mt-0.5">
            <MonoId id={node.node_id} />
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Occurrence</div>
          <div className="mt-0.5 font-mono text-ink-dim">
            {node.occurrence ? formatDateTime(node.occurrence) : '—'}
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Evidence references</div>
          <div className="mt-0.5 font-mono text-ink-dim">{node.evidence_references.length}</div>
        </div>
      </div>

      <div className="rounded border border-edge-soft">
        <Table>
          <thead>
            <tr className="border-b border-edge">
              <Th>Evidence reference</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-edge-soft">
            {node.evidence_references.length === 0 ? (
              <tr>
                <Td className="text-[11px] text-ink-faint">No evidence reference recorded.</Td>
              </tr>
            ) : (
              node.evidence_references.map((reference) => (
                <TRow key={reference}>
                  <Td>
                    <MonoId id={reference} />
                  </Td>
                </TRow>
              ))
            )}
          </tbody>
        </Table>
      </div>

      {fields.length > 0 && (
        <div className="rounded border border-edge-soft">
          <Table>
            <thead>
              <tr className="border-b border-edge">
                <Th>Field</Th>
                <Th>Value</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge-soft">
              {fields.map(([key, value]) => (
                <tr key={key}>
                  <Td className="w-40 font-mono text-[10px] text-ink-dim">{key}</Td>
                  <Td className="max-w-[320px] truncate text-[11px] text-ink" title={value}>
                    {value}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}
    </div>
  )
}