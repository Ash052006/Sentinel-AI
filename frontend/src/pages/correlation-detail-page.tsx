import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ChevronLeft, Network } from 'lucide-react'
import { correlationsApi } from '../api/correlations'
import { risksApi } from '../api/risks'
import { memoriesApi } from '../api/memories'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows } from '../components/states'
import { CorrelationStatusBadge, MemoryTypeBadge, ProvenanceBadge, RiskLevelBadge } from '../components/badges'
import { MonoId } from '../components/ui/mono-id'
import { ConfidenceBar, ScoreBar } from '../components/ui/progress'
import { JsonViewer } from '../components/ui/json-viewer'
import { Button } from '../components/ui/button'
import { formatTimestamp, shortId } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'

export function CorrelationDetailPage() {
  const { correlationId = '' } = useParams()

  const correlation = useQuery({
    queryKey: ['correlations', 'get', correlationId],
    queryFn: () => correlationsApi.get(correlationId),
    enabled: correlationId.length > 0,
  })

  const risks = useQuery({
    queryKey: ['risks', 'forCorrelation', correlationId],
    queryFn: () => risksApi.forCorrelation(correlationId, 1, 200),
    enabled: correlationId.length > 0,
  })

  const memories = useQuery({
    queryKey: ['memories', 'forCorrelation', correlationId],
    queryFn: () => memoriesApi.forCorrelation(correlationId, 1, 200),
    enabled: correlationId.length > 0,
  })

  const core = correlation.data

  if (correlation.isLoading) return <LoadingRows rows={6} />

  if (correlation.isError) {
    return <ErrorState message={String(correlation.error)} onRetry={() => correlation.refetch()} />
  }

  if (!core) {
    return <EmptyState title="Correlation not found" />
  }

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title={
          <span className="inline-flex items-center gap-2">
            Correlation{' '}
            <span className="font-mono text-sm text-accent">{shortId(core.correlation_id)}</span>
            <CorrelationStatusBadge status={core.status} />
          </span>
        }
        description={`Established ${formatTimestamp(core.timestamp)} · provenance ${core.provenance}.`}
      >
        <Button asChild variant="outline" size="sm">
          <Link to={`/attack-paths/${core.correlation_id}`}>
            <Network className="h-3.5 w-3.5" />
            View attack path
          </Link>
        </Button>
        <Button asChild variant="outline" size="sm">
          <Link to="/correlations">
            <ChevronLeft className="h-3.5 w-3.5" />
            Correlations
          </Link>
        </Button>
      </PageHeader>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Panel title="Evidence" subtitle="Persisted correlation evidence (JSONB)">
            {Object.keys(core.evidence).length === 0 ? (
              <EmptyState title="No evidence" body="The correlation carries no structured evidence." />
            ) : (
              <JsonViewer value={core.evidence} />
            )}
          </Panel>

          <Panel
            title="Risk assessment"
            subtitle="Persisted Step 11 assessments evaluating this correlation"
            padded={false}
          >
            {risks.isLoading ? (
              <LoadingRows rows={3} />
            ) : (risks.data?.items ?? []).length === 0 ? (
              <EmptyState title="No risk assessment" body="This correlation has no persisted assessment." />
            ) : (
              <Table>
                <thead>
                  <tr className="border-b border-edge">
                    <Th>Level</Th>
                    <Th>Score</Th>
                    <Th>Confidence</Th>
                    <Th>Assessed at</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge-soft">
                  {(risks.data?.items ?? []).map((assessment) => (
                    <TRow key={assessment.id}>
                      <Td>
                        <RiskLevelBadge level={assessment.level} />
                      </Td>
                      <Td>
                        <ScoreBar value={assessment.score} />
                      </Td>
                      <Td>
                        <ConfidenceBar value={assessment.confidence} />
                      </Td>
                      <Td className="text-xs text-ink-dim">
                        {formatTimestamp(assessment.timestamp)}
                      </Td>
                    </TRow>
                  ))}
                </tbody>
              </Table>
            )}
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel title="Members" subtitle="Persisted members in member_order" padded={false}>
            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Order</Th>
                  <Th>Detection</Th>
                  <Th>Event</Th>
                  <Th>Timeline</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {core.members.map((member) => (
                  <TRow key={member.id}>
                    <Td>{member.member_order}</Td>
                    <MonoCell>
                      <MonoId id={member.detection_id} />
                    </MonoCell>
                    <MonoCell>
                      <MonoId id={member.event_id} />
                    </MonoCell>
                    <Td className="text-xs text-ink-dim">{formatTimestamp(member.timestamp)}</Td>
                  </TRow>
                ))}
              </tbody>
            </Table>
          </Panel>

          <Panel title="Incident memory" subtitle="Historical recall linked to this correlation">
            {memories.isLoading ? (
              <LoadingRows rows={3} />
            ) : (memories.data?.items ?? []).length === 0 ? (
              <EmptyState title="No recalled memory" />
            ) : (
              <ul className="space-y-3">
                {(memories.data?.items ?? []).map((memory) => (
                  <li key={memory.id} className="rounded-md border border-edge-soft p-3">
                    <div className="flex items-center gap-2">
                      <MemoryTypeBadge type={memory.memory_type} />
                      <ProvenanceBadge provenance={memory.provenance} />
                    </div>
                    <div className="mt-2 text-xs font-medium text-ink">{memory.title}</div>
                    <div className="mt-1 text-[11px] text-ink-dim">{memory.summary}</div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </div>
  )
}