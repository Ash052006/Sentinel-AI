import { Link, useParams } from 'react-router-dom'
import { useQuery, useQueries } from '@tanstack/react-query'
import { ArrowRight, ChevronLeft } from 'lucide-react'
import { correlationsApi } from '../api/correlations'
import { risksApi } from '../api/risks'
import { memoriesApi } from '../api/memories'
import { detectionsApi } from '../api/detections'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import {
  CorrelationStatusBadge,
  MemoryTypeBadge,
  ProvenanceBadge,
  RiskLevelBadge,
  SeverityBadge,
} from '../components/badges'
import { MonoId } from '../components/ui/mono-id'
import { ConfidenceBar, ScoreBar } from '../components/ui/progress'
import { JsonViewer } from '../components/ui/json-viewer'
import { Button } from '../components/ui/button'
import { formatTimestamp, shortId } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'

export function IncidentDetailPage() {
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

  const memberDetections = useQueries({
    queries: (correlation.data?.members ?? []).map((member) => ({
      queryKey: ['detections', 'get', member.detection_id],
      queryFn: () => detectionsApi.get(member.detection_id),
      enabled: correlation.isSuccess,
      retry: false,
    })),
  })

  const core = correlation.data
  const riskAssessments = risks.data?.items ?? []

  if (correlation.isLoading) {
    return <LoadingRows rows={8} />
  }

  if (correlation.isError) {
    return (
      <ErrorState
        message={String(correlation.error)}
        onRetry={() => correlation.refetch()}
      />
    )
  }

  if (!core) {
    return <EmptyState title="Correlation not found" />
  }

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title={
          <span className="inline-flex items-center gap-2">
            Incident <span className="font-mono text-sm text-accent">{shortId(core.correlation_id)}</span>
            <CorrelationStatusBadge status={core.status} />
          </span>
        }
        description={`Correlation established ${formatTimestamp(core.timestamp)}. V1 reads an incident as a correlation plus its risk assessments; stages with no persistence API are labelled clearly.`}
      >
        <Button asChild variant="outline" size="sm">
          <Link to="/incidents">
            <ChevronLeft className="h-3.5 w-3.5" />
            Incidents
          </Link>
        </Button>
      </PageHeader>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Section>
            <ChainStep
              label="Event references"
              body="Persisted source events that fed this correlation. V1 exposes no standalone event API; event ids are displayed as recorded on each member."
            >
              <ul className="mt-2 space-y-1">
                {core.members.map((member) => (
                  <li key={member.id} className="flex items-center gap-2">
                    <MonoId id={member.event_id} />
                    <span className="text-[11px] text-ink-faint">
                      {formatTimestamp(member.timestamp)}
                    </span>
                  </li>
                ))}
              </ul>
            </ChainStep>

            <ChainStep
              label="Detections"
              body="The member detections, fetched by detection_id from the Detection API."
            >
              <Table>
                <thead>
                  <tr className="border-b border-edge">
                    <Th>Severity</Th>
                    <Th>Rule</Th>
                    <Th>Confidence</Th>
                    <Th>Detected at</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge-soft">
                  {memberDetections.map((detection, index) =>
                    detection.isSuccess && detection.data ? (
                      <TRow key={detection.data.id}>
                        <Td>
                          <SeverityBadge severity={detection.data.severity} />
                        </Td>
                        <Td>
                          <span data-mono className="text-[11px] text-ink">
                            {detection.data.rule_id}
                          </span>
                        </Td>
                        <Td>
                          <ConfidenceBar value={detection.data.confidence} />
                        </Td>
                        <Td className="text-xs text-ink-dim">
                          {formatTimestamp(detection.data.detected_at)}
                        </Td>
                      </TRow>
                    ) : (
                      <TRow key={`missing-${index}`}>
                        <Td colSpan={4} className="text-[11px] text-ink-faint">
                          Detection{' '}
                          <MonoId id={core.members[index]?.detection_id} /> could not be loaded
                          (returned an error from the Detection API).
                        </Td>
                      </TRow>
                    ),
                  )}
                </tbody>
              </Table>
            </ChainStep>

            <ChainStep
              label="Correlation"
              body="The persisted correlation read model — status, confidence, evidence."
            >
              <div className="mt-2 grid grid-cols-2 gap-3">
                <div>
                  <span className="text-[11px] uppercase tracking-wider text-ink-dim">Status</span>
                  <div className="mt-1">
                    <CorrelationStatusBadge status={core.status} />
                  </div>
                </div>
                <div>
                  <span className="text-[11px] uppercase tracking-wider text-ink-dim">
                    Confidence
                  </span>
                  <div className="mt-1">
                    <ConfidenceBar value={core.confidence} />
                  </div>
                </div>
              </div>
              <div className="mt-3">
                <span className="text-[11px] uppercase tracking-wider text-ink-dim">Evidence</span>
                <div className="mt-1">
                  <JsonViewer value={core.evidence} />
                </div>
              </div>
            </ChainStep>

            <ChainStep
              label="Risk assessment"
              body="Persisted Step 11 risk assessments carried by this correlation."
            >
              {risks.isLoading ? (
                <LoadingRows rows={3} />
              ) : riskAssessments.length === 0 ? (
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
                    {riskAssessments.map((assessment) => (
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
            </ChainStep>

            <ChainStep label="Investigation" body="Step 12/13 contracts exist but no investigation is persisted or served by an API in V1." unavailable />
            <ChainStep label="Attribution" body="Step 14 contract exists but no attribution assessment is persisted or served by an API in V1." unavailable />
            <ChainStep label="Policy decision" body="Step 24 decisions are produced in-memory and never persisted; no policy API exists in V1." unavailable />
            <ChainStep label="Response execution" body="Step 25 responses run against the simulated provider only and are never persisted or served by an API in V1." unavailable />
          </Section>
        </div>

        <div className="space-y-4">
          <Panel title="Incident memory" subtitle="Historical recall linked to this correlation">
            {memories.isLoading ? (
              <LoadingRows rows={4} />
            ) : (memories.data?.items ?? []).length === 0 ? (
              <EmptyState
                title="No recalled memory"
                body="No incident memories cite this correlation on their historical link."
              />
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
                    <div className="mt-1"><MonoId id={memory.memory_id} /></div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel title="Members" subtitle="Persisted correlation members">
            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Order</Th>
                  <Th>Detection</Th>
                  <Th>Timestamp</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {core.members.map((member) => (
                  <TRow key={member.id}>
                    <Td>{member.member_order}</Td>
                    <MonoCell>
                      <MonoId id={member.detection_id} />
                    </MonoCell>
                    <Td className="text-xs text-ink-dim">{formatTimestamp(member.timestamp)}</Td>
                  </TRow>
                ))}
              </tbody>
            </Table>
          </Panel>
        </div>
      </div>
    </div>
  )
}

function Section({ children }: { children: React.ReactNode }) {
  return <div className="space-y-0">{children}</div>
}

function ChainStep({
  label,
  body,
  children,
  unavailable = false,
}: {
  label: string
  body: string
  children?: React.ReactNode
  unavailable?: boolean
}) {
  return (
    <div className="relative border-l-2 border-edge bg-surface-1 px-4 py-3 first:rounded-t-lg last:rounded-b-lg">
      <div className="flex items-center gap-2">
        <ArrowRight className="h-3.5 w-3.5 text-ink-faint" aria-hidden="true" />
        <span className="text-xs font-semibold uppercase tracking-wider text-ink-dim">
          {label}
        </span>
      </div>
      {unavailable ? (
        <NotAvailable body={body} />
      ) : (
        <>
          <p className="mt-1 text-[11px] text-ink-faint">{body}</p>
          {children}
        </>
      )}
    </div>
  )
}