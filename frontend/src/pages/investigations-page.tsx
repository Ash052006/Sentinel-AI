import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { detectionsApi } from '../api/detections'
import { correlationsApi } from '../api/correlations'
import { memoriesApi } from '../api/memories'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { MemoryTypeBadge, ProvenanceBadge, SeverityBadge, CorrelationStatusBadge } from '../components/badges'
import { MonoId } from '../components/ui/mono-id'
import { ConfidenceBar } from '../components/ui/progress'
import { formatTimestamp } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'

export function InvestigationsPage() {
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
        description="Strict provenance separation: current system evidence is never blended with historical incident memory, and learned patterns are only shown when a real learning surface exists (none in V1)."
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
                  </TRow>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </Panel>

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

      <Panel title="Learned patterns" subtitle="Provenance: learned (Step 22 consolidation)">
        <NotAvailable
          body="The Step 22 incident-memory learning contract exists, but V1 defines no learning persistence and no read/query service or API. Learned patterns therefore cannot be surfaced as real data and nothing is shown."
        />
      </Panel>
    </div>
  )
}