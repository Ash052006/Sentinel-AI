import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { detectionsApi } from '../api/detections'
import { correlationsApi } from '../api/correlations'
import { memoriesApi } from '../api/memories'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { MemoryTypeBadge, ProvenanceBadge, SeverityBadge, CorrelationStatusBadge } from '../components/badges'
import { ExplainabilityPanel } from '../components/explainability-panel'
import { MonoId } from '../components/ui/mono-id'
import { Button } from '../components/ui/button'
import { ConfidenceBar } from '../components/ui/progress'
import { formatTimestamp } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'

export function InvestigationsPage() {
  const [selectedCorrelationId, setSelectedCorrelationId] = useState<string | null>(
    null,
  )
  const detections = useQuery({
    queryKey: ['detections', 'recent', 50],
    queryFn: () => detectionsApi.recent(50),
  })
  const correlations = useQuery({
    queryKey: ['correlations', 'recent', 50],
    queryFn: () => correlationsApi.recent(50),
  })
  const memories = useQuery({
    queryKey: ['memories', 'recent', 50],
    queryFn: () => memoriesApi.recent(50),
  })

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Investigation"
        description="Strict provenance separation: current system evidence is never blended with historical incident memory. Everything below is a live composition of already-persisted detections, correlations and incident memories — V2 persists no investigation result, so none is shown as if one existed."
      />

      <Panel
        title="Current security evidence"
        subtitle="Provenance: observed · enriched · reconstructed · detected · correlated · risk_assessed"
      >
        {detections.isLoading || correlations.isLoading ? (
          <LoadingRows rows={6} />
        ) : detections.isError || correlations.isError ? (
          <ErrorState
            message="Current evidence could not be loaded."
            onRetry={() => {
              void detections.refetch()
              void correlations.refetch()
            }}
          />
        ) : (detections.data?.length ?? 0) === 0 && (correlations.data?.length ?? 0) === 0 ? (
          <EmptyState title="No current evidence" />
        ) : (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Severity</Th>
                  <Th>Rule</Th>
                  <Th>Confidence</Th>
                  <Th>Provenance</Th>
                  <Th>Detected at</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {(detections.data ?? []).slice(0, 10).map((item) => (
                  <TRow key={item.id}>
                    <Td>
                      <SeverityBadge severity={item.severity} />
                    </Td>
                    <Td data-mono className="text-[11px] text-ink">{item.rule_id}</Td>
                    <Td>
                      <ConfidenceBar value={item.confidence} />
                    </Td>
                    <Td>
                      <ProvenanceBadge provenance={item.provenance} />
                    </Td>
                    <Td className="text-xs text-ink-dim">{formatTimestamp(item.detected_at)}</Td>
                  </TRow>
                ))}
              </tbody>
            </Table>

            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Status</Th>
                  <Th>Members</Th>
                  <Th>Confidence</Th>
                  <Th>Provenance</Th>
                  <Th>Established</Th>
                  <Th>Explain</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {(correlations.data ?? []).slice(0, 10).map((item) => (
                  <TRow key={item.id}>
                    <Td>
                      <CorrelationStatusBadge status={item.status} />
                    </Td>
                    <Td>{item.members.length}</Td>
                    <Td>
                      <ConfidenceBar value={item.confidence} />
                    </Td>
                    <Td>
                      <ProvenanceBadge provenance={item.provenance} />
                    </Td>
                    <MonoCell>
                      <Link
                        to={`/incidents/${item.correlation_id}`}
                        className="text-accent hover:underline"
                      >
                        open
                      </Link>
                    </MonoCell>
                    <Td>
                      <Button
                        variant={
                          selectedCorrelationId === item.correlation_id
                            ? 'default'
                            : 'outline'
                        }
                        size="sm"
                        onClick={() =>
                          setSelectedCorrelationId(item.correlation_id)
                        }
                      >
                        Explain
                      </Button>
                    </Td>
                  </TRow>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </Panel>

      <ExplainabilityPanel correlationId={selectedCorrelationId} />

      <Panel
        title="Historical incident memory"
        subtitle="Provenance: recalled (never presentable as current telemetry)"
      >
        {memories.isLoading ? (
          <LoadingRows rows={6} />
        ) : memories.isError ? (
          <ErrorState message={String(memories.error)} onRetry={() => memories.refetch()} />
        ) : (memories.data ?? []).length === 0 ? (
          <EmptyState title="No incident memory" />
        ) : (
          <ul className="space-y-3">
            {(memories.data ?? []).map((memory) => (
              <li
                key={memory.id}
                className="flex items-start justify-between gap-4 rounded-md border border-edge-soft p-3"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <MemoryTypeBadge type={memory.memory_type} />
                    <ProvenanceBadge provenance={memory.provenance} />
                  </div>
                  <div className="mt-2 truncate text-xs font-medium text-ink">
                    {memory.title}
                  </div>
                  <div className="mt-1 text-[11px] text-ink-dim">{memory.summary}</div>
                </div>
                <div className="shrink-0">
                  <MonoId id={memory.memory_id} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel
        title="Persisted investigation results (Step 12A agent output)"
        subtitle="Provenance: ai_generated — results are produced on demand, never stored"
      >
        <NotAvailable
          body="Step 12A defines the InvestigationResult contract and the agent now runs on demand through the explanation panel above, but no InvestigationResult is persisted: each explanation is computed from the persisted records at request time. The evidence panels above are the real substrate the agent reasons over, and the AI narrative shown there is grounded in it — an unsupported statement is flagged, never presented as grounded."
        />
      </Panel>

      <Panel
        title="Threat attribution assessments (Step 14)"
        subtitle="Provenance: attribution_assessed — not available in V2"
      >
        <NotAvailable
          body="The Step 14 contract deliberately contains no attribution engine, no persistence and no API, so there is no stored attribution verdict to display. Threat Intelligence below lists persisted indicators of compromise only, which are not attributions and are never presented as one."
        />
      </Panel>

      <Panel title="Learned patterns" subtitle="Provenance: learned (Step 22 consolidation)">
        <NotAvailable
          body="The Step 22 incident-memory learning contract exists, but V1 defines no learning persistence and no read/query service or API. Learned patterns therefore cannot be surfaced as real data and nothing is shown."
        />
      </Panel>
    </div>
  )
}