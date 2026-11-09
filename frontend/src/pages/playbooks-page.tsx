import { useState, useMemo } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ChevronLeft, MessagesSquare, Radar, RefreshCw, Workflow } from 'lucide-react'
import { playbooksApi } from '../api/playbooks'
import { correlationsApi } from '../api/correlations'
import { ApiError } from '../api/client'
import { ProvenanceBadge } from '../components/badges'
import { ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, PageHeader, Panel, Stat } from '../components/ui/card'
import { MonoId } from '../components/ui/mono-id'
import { Table, TRow, Th, Td } from '../components/ui/table'
import { formatDateTime } from '../lib/formats'
import {
  ACTION_CATEGORY_LABELS,
  ACTION_CONFIDENCE_BAND_LABELS,
  ACTION_PRIORITY_META,
  APPROVAL_REQUIREMENT_META,
  CAPABILITY_STATUS_META,
  GROUNDING_BASIS_LABELS,
  PLAYBOOK_EVIDENCE_SOURCE_LABELS,
  PLAYBOOK_LIMITATION_LABELS,
  PLAYBOOK_LIFECYCLE_LABELS,
  PLAYBOOK_STATUS_META,
  PLAYBOOK_TARGET_TYPE_LABELS,
  PREDICTION_STANCE_LABELS,
  PREDICTION_STANCE_TONES,
} from '../lib/labels'
import type {
  Playbook,
  PlaybookAction,
  PlaybookEvidence,
  PlaybookLimitation,
  PlaybookStep,
  PlaybookSummary,
  PlaybookUncertainty,
} from '../types/api'

function percent(value: number): string {
  return `${(value * 100).toFixed(0)}%`
}

/**
 * A citation is a resolvable pointer into persisted evidence, and its stance is
 * always visible. Suppressing the contradicting list would quietly turn a
 * contested proposal into a confident-looking one, which is the specific failure
 * mode this engine is built to avoid.
 */
function EvidenceList({ items }: { items: PlaybookEvidence[] }) {
  if (items.length === 0) {
    return (
      <div className="text-[11px] text-ink-faint">No citation was recorded.</div>
    )
  }
  return (
    <ul className="space-y-1.5" data-testid="playbook-evidence-list">
      {items.map((item) => (
        <li
          key={`${item.source}:${item.reference}:${item.stance}`}
          className="rounded border border-edge-soft px-3 py-2"
        >
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={PREDICTION_STANCE_TONES[item.stance]}>
              {PREDICTION_STANCE_LABELS[item.stance]}
            </Badge>
            <Badge tone="muted" title={item.source}>
              {item.reference}
            </Badge>
            <span className="text-[11px] text-ink-faint">
              {PLAYBOOK_EVIDENCE_SOURCE_LABELS[item.source]}
            </span>
          </div>
          <div className="mt-1 text-[11px] leading-relaxed text-ink-dim">
            {item.detail}
          </div>
        </li>
      ))}
    </ul>
  )
}

function LimitationsList({
  limitations,
  testId,
}: {
  limitations: PlaybookLimitation[]
  testId?: string
}) {
  if (limitations.length === 0) {
    return (
      <div className="text-[11px] text-ink-faint">
        No limitations were recorded for this proposal.
      </div>
    )
  }
  return (
    <ul className="space-y-1.5" data-testid={testId}>
      {limitations.map((limitation, index) => (
        <li
          key={`${limitation.kind}:${index}`}
          className="rounded border border-edge-soft px-3 py-2"
        >
          <Badge tone="muted">
            {PLAYBOOK_LIMITATION_LABELS[limitation.kind] ?? limitation.kind}
          </Badge>
          <div className="mt-1 text-[11px] leading-relaxed text-ink-faint">
            {limitation.detail}
          </div>
        </li>
      ))}
    </ul>
  )
}

/**
 * A missing debate or prediction is an actionable prerequisite, not a dead end.
 *
 * The playbook endpoint deliberately does not run either upstream step: a debate
 * invokes a model, and both are separate analytical decisions an analyst must
 * make explicitly. The UI therefore routes the analyst to the existing
 * correlation-scoped pages, which run or return the artifact for the current
 * graph, then offers an explicit regeneration.
 */
function MissingUpstreamInputs({
  correlationId,
  unavailableInputs,
  isStored,
  onRegenerate,
}: {
  correlationId: string
  unavailableInputs: Record<string, string>
  isStored: boolean
  onRegenerate: () => void
}) {
  const missingDebate = 'debate' in unavailableInputs
  const missingPrediction = 'prediction' in unavailableInputs
  if (!missingDebate && !missingPrediction) return null

  return (
    <Panel
      title="Missing upstream inputs"
      subtitle="The proposal cannot consume a debate or prediction from another graph state."
    >
      <div className="space-y-3" data-testid="playbook-prerequisites">
        <div className="text-[11px] leading-relaxed text-ink-faint">
          Playbook generation never runs these steps automatically. Re-run them
          for the current graph in order, then regenerate the proposal. A debate
          is a model-backed analysis and remains an explicit analyst action.
        </div>
        <div className="flex flex-wrap gap-2">
          {missingDebate && (
            <Button asChild size="sm" variant="outline">
              <Link to={`/debates/correlation/${correlationId}`}>
                <MessagesSquare className="h-3.5 w-3.5" aria-hidden="true" />
                Run agent debate
              </Link>
            </Button>
          )}
          {missingPrediction && (
            <Button asChild size="sm" variant="outline">
              <Link to={`/predictions/correlation/${correlationId}`}>
                <Radar className="h-3.5 w-3.5" aria-hidden="true" />
                Run attack prediction
              </Link>
            </Button>
          )}
          {isStored ? (
            <Button asChild size="sm">
              <Link to={`/playbooks/correlation/${correlationId}`}>
                <Workflow className="h-3.5 w-3.5" aria-hidden="true" />
                Generate current proposal
              </Link>
            </Button>
          ) : (
            <Button size="sm" onClick={onRegenerate}>
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              Regenerate proposal
            </Button>
          )}
        </div>
        <ul className="space-y-0.5 text-[11px] leading-relaxed text-ink-faint">
          {missingDebate && (
            <li>
              <span className="text-ink-dim">Debate</span> —{' '}
              {unavailableInputs.debate}
            </li>
          )}
          {missingPrediction && (
            <li>
              <span className="text-ink-dim">Prediction</span> —{' '}
              {unavailableInputs.prediction}
            </li>
          )}
        </ul>
      </div>
    </Panel>
  )
}

function ActionCard({ action }: { action: PlaybookAction }) {
  return (
    <Card className="px-4 py-3" data-testid="playbook-action">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={ACTION_PRIORITY_META[action.priority].tone}>
              {ACTION_PRIORITY_META[action.priority].label}
            </Badge>
            <Badge tone="neutral">
              {ACTION_CATEGORY_LABELS[action.category]}
            </Badge>
            <Badge tone="muted" data-testid="playbook-action-type">
              {action.action.replace(/_/g, ' ')}
            </Badge>
          </div>
          <div
            className="mt-1.5 font-mono text-sm font-semibold text-ink"
            data-testid="playbook-action-target"
          >
            {action.target_reference}
          </div>
        </div>
        <div className="text-right">
          <div className="font-mono text-lg leading-none text-ink">
            {percent(action.confidence)}
          </div>
          <div className="mt-0.5 text-[11px] text-ink-faint">
            {ACTION_CONFIDENCE_BAND_LABELS[action.confidence_band]}
          </div>
        </div>
      </div>

      <div className="mt-2 text-xs leading-relaxed text-ink-dim">
        {action.rationale.summary}
      </div>

      <dl className="mt-3 grid gap-x-4 gap-y-2 text-[11px] sm:grid-cols-2">
        <div>
          <dt className="text-ink-faint">Target basis</dt>
          <dd className="text-ink-dim">{action.target_basis}</dd>
        </div>
        <div>
          <dt className="text-ink-faint">Grounding</dt>
          <dd className="text-ink-dim">
            {GROUNDING_BASIS_LABELS[action.rationale.grounding]}
            <span className="text-ink-faint">
              {' · '}
              {action.rationale.grounding_detail}
            </span>
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint">Target type</dt>
          <dd className="text-ink-dim">
            {PLAYBOOK_TARGET_TYPE_LABELS[action.target_type]}
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint">Risk</dt>
          <dd className="text-ink-dim">{action.risk_level}</dd>
        </div>
        <div>
          <dt className="text-ink-faint">Approval</dt>
          <dd className="text-ink-dim">
            <Badge tone={APPROVAL_REQUIREMENT_META[action.approval.requirement].tone}>
              {APPROVAL_REQUIREMENT_META[action.approval.requirement].label}
            </Badge>
            <span className="text-ink-faint"> · {action.approval.reason}</span>
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint">Capability</dt>
          <dd className="text-ink-dim">
            <Badge tone={CAPABILITY_STATUS_META[action.capability].tone}>
              {CAPABILITY_STATUS_META[action.capability].label}
            </Badge>
            <span className="font-mono text-ink-faint">
              {' · '}
              {action.execution_backend}
            </span>
          </dd>
        </div>
      </dl>

      <div className="mt-3 rounded border border-edge-soft px-3 py-2">
        <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
          Rollback
        </div>
        <div className="mt-1 text-[11px] leading-relaxed text-ink-dim">
          {action.rollback.rollback_supported ? (
            <span data-testid="playbook-rollback-supported">
              Reversible via{' '}
              <span className="font-mono">
                {action.rollback.rollback_action?.replace(/_/g, ' ')}
              </span>
            </span>
          ) : (
            <span data-testid="playbook-rollback-unsupported">
              No rollback is proposed.
            </span>
          )}
          <span className="text-ink-faint"> — {action.rollback.reason}</span>
        </div>
      </div>

      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <div>
          <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-dim">
            Supporting
          </div>
          <EvidenceList
            items={action.evidence.filter((e) => e.stance === 'supporting')}
          />
        </div>
        <div>
          <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-dim">
            Contradicting
          </div>
          <EvidenceList
            items={action.evidence.filter((e) => e.stance === 'contradicting')}
          />
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-edge-soft pt-2 text-[11px] text-ink-faint">
        <span>Priority reason: {action.rationale.priority_reason}</span>
        <MonoId id={action.action_id} />
      </div>
    </Card>
  )
}

function StepPanel({ step }: { step: PlaybookStep }) {
  return (
    <Panel
      title={`Step ${step.step_number} — ${step.name}`}
      subtitle={step.purpose}
      padded={false}
    >
      {step.actions.length === 0 ? (
        <div className="p-4 text-[11px] text-ink-faint">
          This step proposes no actions.
        </div>
      ) : (
        <ul className="divide-y divide-edge-soft">
          {step.actions.map((action) => (
            <li key={action.action_id} className="px-4 py-3">
              <ActionCard action={action} />
            </li>
          ))}
        </ul>
      )}
      {step.depends_on_steps.length > 0 && (
        <div className="border-t border-edge-soft px-4 py-2 text-[11px] text-ink-faint">
          Depends on steps:{' '}
          <span className="font-mono text-ink-dim">
            {step.depends_on_steps.join(', ')}
          </span>
        </div>
      )}
    </Panel>
  )
}

function UncertaintyPanel({
  uncertainty,
  isInsufficient,
  graphEntityCount,
}: {
  uncertainty: PlaybookUncertainty
  isInsufficient: boolean
  graphEntityCount: number
}) {
  const supporting = isInsufficient ? 0 : uncertainty.supporting_evidence_count
  const contradicting = isInsufficient
    ? 0
    : uncertainty.contradicting_evidence_count

  return (
    <Panel
      title="Confidence & uncertainty"
      subtitle="A proposal is never returned without its uncertainty."
    >
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Confidence"
          value={percent(uncertainty.confidence)}
        />
        <Stat
          label="Band"
          value={
            <Badge tone="neutral">
              {ACTION_CONFIDENCE_BAND_LABELS[uncertainty.confidence_band]}
            </Badge>
          }
        />
        <Stat label="Supporting" value={supporting} />
        <Stat label="Contradicting" value={contradicting} />
      </div>

      {isInsufficient && (
        <div
          className="mt-3 text-[11px] leading-relaxed text-ink-faint"
          data-testid="playbook-uncertainty-note"
        >
          No actions were proposed, so no evidence is counted as supporting an
          action. The graph snapshot's {graphEntityCount}{' '}
          {graphEntityCount === 1 ? 'entity was' : 'entities were'} reviewed as
          input, not as action support.
        </div>
      )}

      <dl
        className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] sm:grid-cols-4"
        data-testid="playbook-confidence-basis"
      >
        {Object.entries(uncertainty.confidence_basis).map(([key, value]) => (
          <div key={key}>
            <dt className="text-ink-faint">{key.replace(/_/g, ' ')}</dt>
            <dd className="font-mono text-ink-dim">{value.toFixed(2)}</dd>
          </div>
        ))}
      </dl>

      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        {uncertainty.evidence_gaps.length > 0 && (
          <div>
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-ink-dim">
              Evidence gaps
            </div>
            <ul
              className="list-disc space-y-0.5 pl-4 text-[11px] leading-relaxed text-ink-faint"
              data-testid="playbook-evidence-gaps"
            >
              {uncertainty.evidence_gaps.map((gap) => (
                <li key={gap}>{gap}</li>
              ))}
            </ul>
          </div>
        )}
        {uncertainty.unresolved_questions.length > 0 && (
          <div>
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-ink-dim">
              Unresolved
            </div>
            <ul
              className="list-disc space-y-0.5 pl-4 text-[11px] leading-relaxed text-ink-faint"
              data-testid="playbook-unresolved"
            >
              {uncertainty.unresolved_questions.map((question) => (
                <li key={question}>{question}</li>
              ))}
            </ul>
          </div>
        )}
        {uncertainty.conflicting_claims.length > 0 && (
          <div className="sm:col-span-2">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-ink-dim">
              Conflicting claims
            </div>
            <ul
              className="list-disc space-y-0.5 pl-4 text-[11px] leading-relaxed text-ink-faint"
              data-testid="playbook-conflicting-claims"
            >
              {uncertainty.conflicting_claims.map((claim) => (
                <li key={claim}>{claim}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Panel>
  )
}

function StoredList({ summaries }: { summaries: PlaybookSummary[] }) {
  if (summaries.length === 0) return null
  return (
    <Panel
      title="Stored proposals"
      subtitle="Every proposal recorded for this correlation, newest first."
      padded={false}
    >
      <ul className="divide-y divide-edge-soft" data-testid="playbook-list">
        {summaries.map((summary) => (
          <li
            key={summary.playbook_id}
            className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5"
          >
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={PLAYBOOK_STATUS_META[summary.status].tone}>
                {PLAYBOOK_STATUS_META[summary.status].label}
              </Badge>
              <Badge tone="muted">
                {PLAYBOOK_LIFECYCLE_LABELS[summary.lifecycle]}
              </Badge>
              <MonoId id={summary.playbook_id} />
            </div>
            <div className="flex items-center gap-3 text-[11px] text-ink-faint">
              <span>{summary.action_count} actions</span>
              <span>{summary.step_count} steps</span>
              <span>{summary.approval_required_count} need approval</span>
              <span className="font-mono text-ink-dim">
                {percent(summary.confidence)}
              </span>
              <Button asChild variant="outline" size="sm">
                <Link to={`/playbooks/${summary.playbook_id}`}>Open</Link>
              </Button>
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  )
}

/**
 * `POST /api/playbooks/{correlation_id}` runs or returns the proposal;
 * `GET /api/playbooks/{playbook_id}` reads a stored one back. The route
 * parameter decides which, mirroring the V3.22/V3.23/V3.24 correlation-scoped
 * pages. Nothing on this page approves and nothing executes: the backend surface
 * cannot do either, so the UI never offers a control that pretends otherwise.
 */
export function PlaybooksPage() {
  const { correlationId = '', playbookId = '' } = useParams()
  const targetId = playbookId || correlationId
  const isStored = playbookId.length > 0

  const query = useQuery({
    queryKey: ['playbooks', isStored ? 'stored' : 'correlation', targetId],
    queryFn: () =>
      isStored ? playbooksApi.get(targetId) : playbooksApi.generate(targetId),
    enabled: targetId.length > 0,
    // The POST runs deterministic analysis over the current graph. It is not
    // re-fired implicitly by a refetch, so window focus cannot silently change
    // what is on screen; re-running is an explicit user action.
    refetchOnWindowFocus: false,
    retry: false,
  })

  const listQuery = useQuery({
    queryKey: ['playbooks', 'list', correlationId],
    queryFn: () => playbooksApi.listForCorrelation(correlationId),
    enabled: correlationId.length > 0 && !isStored,
    refetchOnWindowFocus: false,
    retry: false,
  })

  const [filterMultiOnly, setFilterMultiOnly] = useState(true)

  const correlationsQuery = useQuery({
    queryKey: ['correlations', 'recent', 50],
    queryFn: () => correlationsApi.recent(50),
    enabled: !targetId,
  })
  const availableCorrelations = correlationsQuery.data ?? []

  const displayCorrelations = useMemo(() => {
    if (!filterMultiOnly) return availableCorrelations
    const multi = availableCorrelations.filter((c) => c.members.length > 1)
    return multi.length > 0 ? multi : availableCorrelations
  }, [availableCorrelations, filterMultiOnly])

  const result = query.data
  const playbook: Playbook | undefined = result?.playbook
  const correlation = result?.correlation_id ?? correlationId
  const statusMeta = result ? PLAYBOOK_STATUS_META[result.status] : null
  const steps = playbook?.steps ?? []
  const actions = steps.flatMap((step) => step.actions)

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="AI Playbook"
        description="Evidence-grounded automated mitigation proposals synthesized from knowledge graph telemetry, multi-agent debate consensus, and predictive attack modeling. Proposals enforce human-in-the-loop policy governance prior to execution."
      >
        <Button asChild variant="outline" size="sm">
          <Link to={correlation ? `/correlations/${correlation}` : '/correlations'}>
            <ChevronLeft className="h-3.5 w-3.5" />
            Correlation
          </Link>
        </Button>
      </PageHeader>

      {!targetId ? (
        <div className="space-y-4">
          <Panel
            title="Choose a correlation"
            subtitle="Select an active security correlation to synthesize automated mitigation proposals"
            padded={false}
          >
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-edge px-4 py-3 bg-surface-2/40">
              <div className="text-[11px] leading-relaxed text-ink-dim">
                Automated response planning requires multiple correlated telemetry alerts to identify targets. Multi-incident correlations provide the evidence needed to ground containment actions.
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <Button
                  size="sm"
                  variant={filterMultiOnly ? 'default' : 'outline'}
                  onClick={() => setFilterMultiOnly(true)}
                  className="text-xs h-7 px-2.5"
                >
                  Multi-Incident Only (&gt;1)
                </Button>
                <Button
                  size="sm"
                  variant={!filterMultiOnly ? 'default' : 'outline'}
                  onClick={() => setFilterMultiOnly(false)}
                  className="text-xs h-7 px-2.5"
                >
                  All
                </Button>
              </div>
            </div>

            <div className="border-b border-edge px-4 py-2.5 text-[11px] leading-relaxed text-ink-faint">
              A playbook is always scoped to a single correlation, because every
              action it proposes must cite resolvable persisted evidence from that
              correlation's graph. Select an active correlation below to generate or review response proposals.
            </div>

            {correlationsQuery.isLoading ? (
              <LoadingRows rows={6} />
            ) : correlationsQuery.isError ? (
              <ErrorState
                message={String(correlationsQuery.error)}
                onRetry={() => void correlationsQuery.refetch()}
              />
            ) : displayCorrelations.length === 0 ? (
              <div className="p-8 text-center text-xs text-ink-dim">
                No active correlations recorded yet. Ingest telemetry or execute demo scenarios to produce correlation events.
              </div>
            ) : (
              <Table>
                <thead>
                  <tr className="border-b border-edge">
                    <Th>Correlation</Th>
                    <Th>Status</Th>
                    <Th>Detections / Scope</Th>
                    <Th>Observed At</Th>
                    <Th className="text-right">Action</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge-soft">
                  {displayCorrelations.map((row) => (
                    <TRow key={row.correlation_id}>
                      <Td className="font-mono text-xs text-ink">
                        <MonoId id={row.correlation_id} />
                      </Td>
                      <Td>
                        <Badge tone={row.status === 'active' ? 'accent' : 'muted'}>
                          {row.status.toUpperCase()}
                        </Badge>
                      </Td>
                      <Td>
                        {row.members.length > 1 ? (
                          <Badge tone="accent">{row.members.length} alerts (Multi-Stage)</Badge>
                        ) : (
                          <Badge tone="muted">1 alert (Standalone)</Badge>
                        )}
                      </Td>
                      <Td className="text-xs text-ink-dim">
                        {formatDateTime(row.timestamp)}
                      </Td>
                      <Td className="text-right">
                        <Button asChild size="sm" variant="outline" className="gap-1.5">
                          <Link to={`/playbooks/correlation/${row.correlation_id}`}>
                            <Workflow className="h-3.5 w-3.5 text-accent" />
                            {row.members.length > 1 ? 'Generate Playbook' : 'Generate (Single Event)'}
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
      ) : query.isLoading ? (
        <LoadingRows rows={8} />
      ) : query.isError ? (
        <Panel title="Proposal unavailable" data-testid="playbook-error">
          <ErrorState
            message={
              query.error instanceof ApiError
                ? query.error.detail
                : String(query.error)
            }
            onRetry={() => void query.refetch()}
          />
          <div className="mt-2 border-t border-edge-soft px-4 py-3 text-[11px] leading-relaxed text-ink-faint">
            A failure here means the engine could not produce a proposal at all.
            It never substitutes a fabricated plan: when it cannot justify one it
            reports insufficient evidence instead.
          </div>
        </Panel>
      ) : result && playbook ? (
        <>
          <Panel
            title="Proposal"
            subtitle={
              isStored
                ? 'Stored proposal, read back exactly as recorded.'
                : 'Run or returned for this correlation.'
            }
            action={
              <div className="flex flex-wrap items-center justify-end gap-2 text-[11px] text-ink-faint">
                <MonoId id={result.playbook_id} />
                {result.status === 'insufficient_evidence' && (
                  <span>returned without speculation</span>
                )}
              </div>
            }
          >
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Stat
                label="Status"
                value={
                  statusMeta ? (
                    <Badge tone={statusMeta.tone}>{statusMeta.label}</Badge>
                  ) : (
                    '—'
                  )
                }
              />
              <Stat
                label="Lifecycle"
                value={<span className="text-base">{PLAYBOOK_LIFECYCLE_LABELS[result.lifecycle]}</span>}
              />
              <Stat label="Actions" value={actions.length} />
              <Stat label="Steps" value={steps.length} />
            </div>

            <dl className="mt-4 grid gap-x-4 gap-y-2 text-[11px] sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-ink-faint">Engine version</dt>
                <dd className="font-mono text-ink-dim">
                  {result.metadata.engine_version}
                </dd>
              </div>
              <div>
                <dt className="text-ink-faint">Debate consumed</dt>
                <dd className="text-ink-dim">
                  <MonoId id={result.metadata.debate_id} />
                </dd>
              </div>
              <div>
                <dt className="text-ink-faint">Prediction consumed</dt>
                <dd className="text-ink-dim">
                  <MonoId id={result.metadata.prediction_session_id} />
                </dd>
              </div>
              <div>
                <dt className="text-ink-faint">Graph snapshot</dt>
                <dd className="text-ink-dim">
                  <MonoId id={result.metadata.graph_snapshot_digest} />
                </dd>
              </div>
            </dl>

            <div className="mt-3 border-t border-edge-soft pt-3">
              <div
                className="text-[11px] leading-relaxed text-ink-faint"
                data-testid="playbook-execution-note"
              >
                {result.execution_note}
              </div>
            </div>
          </Panel>

          <MissingUpstreamInputs
            correlationId={correlation}
            unavailableInputs={result.metadata.unavailable_inputs}
            isStored={isStored}
            onRegenerate={() => void query.refetch()}
          />

          {actions.length === 0 ? (
            <Panel title="Proposed actions">
              <div data-testid="playbook-insufficient">
                <NotAvailable
                  title="No actions proposed"
                  body="The engine found no resolvable, evidence-grounded actions to propose for this correlation. Declining to propose is the correct result: a plan without a resolvable basis would be speculation, and a failure here is never covered by a thinner plan."
                />
              </div>
            </Panel>
          ) : (
            <div className="space-y-4">
              {steps.map((step) => (
                <StepPanel key={step.step_number} step={step} />
              ))}
            </div>
          )}

          <UncertaintyPanel
            uncertainty={result.uncertainty}
            isInsufficient={result.status === 'insufficient_evidence'}
            graphEntityCount={result.metadata.graph_node_count}
          />

          {result.current_state.length > 0 && (
            <Panel
              title="Current state"
              subtitle="The persisted facts this proposal starts from. These are evidence; nothing above them is."
              padded={false}
            >
              <ul className="divide-y divide-edge-soft">
                {result.current_state.map((item) => (
                  <li
                    key={`${item.source}:${item.reference}`}
                    className="px-4 py-3"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="muted">{item.reference}</Badge>
                      <span className="text-[11px] text-ink-faint">
                        {PLAYBOOK_EVIDENCE_SOURCE_LABELS[item.source]}
                      </span>
                    </div>
                    <div className="mt-1 text-[11px] leading-relaxed text-ink-dim">
                      {item.detail}
                    </div>
                  </li>
                ))}
              </ul>
            </Panel>
          )}

          <Panel
            title="Proposal limitations"
            subtitle="Everything that shaped this proposal, including inputs that were unavailable."
          >
            <LimitationsList
              limitations={result.limitations}
              testId="playbook-limitations"
            />
            {Object.keys(result.metadata.unavailable_inputs).length > 0 && (
              <div className="mt-3 border-t border-edge-soft pt-3">
                <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
                  Unavailable inputs
                </div>
                <ul
                  className="mt-1 space-y-0.5 text-[11px] leading-relaxed text-ink-faint"
                  data-testid="playbook-unavailable-inputs"
                >
                  {Object.entries(result.metadata.unavailable_inputs).map(
                    ([source, reason]) => (
                      <li key={source}>
                        <span className="text-ink-dim">{source}</span> — {reason}
                      </li>
                    ),
                  )}
                </ul>
              </div>
            )}
            <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-edge-soft pt-2 text-[11px] text-ink-faint">
              <ProvenanceBadge provenance={result.provenance} />
            </div>
          </Panel>

          {!isStored && listQuery.data && (
            <StoredList summaries={listQuery.data.playbooks} />
          )}
        </>
      ) : (
        <Panel title="No proposal">
          <NotAvailable
            title="No proposal returned"
            body="The engine completed without producing a proposal to display."
          />
        </Panel>
      )}
    </div>
  )
}
