import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ChevronLeft, MessagesSquare, Scale } from 'lucide-react'
import { debatesApi } from '../api/debates'
import { ApiError } from '../api/client'
import { ProvenanceBadge } from '../components/badges'
import { ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, PageHeader, Panel, Stat } from '../components/ui/card'
import { MonoId } from '../components/ui/mono-id'
import { formatDateTime } from '../lib/formats'
import {
  DEBATE_CONSENSUS_META,
  DEBATE_ROLE_LABELS,
  DEBATE_ROUND_LABELS,
  DEBATE_STANCE_LABELS,
  DEBATE_WEAKNESS_LABELS,
  KG_NODE_LABELS,
} from '../lib/labels'
import type {
  AgentAssessment,
  DebateArgument,
  DebateConsensus,
  DebateCounterargument,
  DebateSession,
  EvidenceReference,
  KnowledgeNodeType,
} from '../types/api'

function percent(value: number): string {
  return `${(value * 100).toFixed(0)}%`
}

/**
 * Evidence citations are the whole point of the view, so they are rendered as
 * resolvable references rather than plain text: an analyst must be able to see
 * that every claim points at a real V2 record in the graph.
 */
function EvidenceCitations({
  references,
}: {
  references: EvidenceReference[]
}) {
  if (references.length === 0) {
    return <span className="text-[11px] text-ink-faint">no citations</span>
  }
  return (
    <ul className="flex flex-wrap gap-1">
      {references.map((reference) => (
        <li key={`${reference.node_id}:${reference.reference}`}>
          <Badge
            tone="muted"
            title={`${reference.entity_kind} · node ${reference.node_id}`}
          >
            {reference.reference}
          </Badge>
        </li>
      ))}
    </ul>
  )
}

function ConsensusPanel({
  consensus,
}: {
  consensus: DebateConsensus
}) {
  const meta = DEBATE_CONSENSUS_META[consensus.state]
  const supporting = consensus.supporting_arguments.length
  const opposing = consensus.opposing_arguments.length

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-3">
        <Stat
          label="Consensus state"
          value={<Badge tone={meta.tone}>{meta.label}</Badge>}
        />
        <Stat label="Consensus strength" value={percent(consensus.consensus_strength)} />
        <Stat label="Confidence" value={percent(consensus.confidence)} />
      </div>

      <Card className="px-4 py-3">
        <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
          Leading hypothesis
        </div>
        {consensus.leading_hypothesis ? (
          <div
            data-testid="debate-leading-hypothesis"
            className="mt-1 text-sm leading-relaxed text-ink"
          >
            {consensus.leading_hypothesis}
          </div>
        ) : (
          <div className="mt-1 text-sm text-ink-faint">
            No hypothesis was raised from the available evidence.
          </div>
        )}
        <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-ink-faint">
          <span className="font-mono">
            {supporting} supporting · {opposing} opposing
          </span>
          <ProvenanceBadge provenance={consensus.provenance} />
        </div>
      </Card>

      {consensus.dissent.length > 0 && (
        <Panel
          title="Dissent"
          subtitle="Positions that did not carry the consensus. Retained, because a debate that hides the losing argument is not auditable."
          padded={false}
        >
          <ul className="divide-y divide-edge-soft">
            {consensus.dissent.map((entry) => (
              <li key={entry.dissent_id} className="px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="muted">
                    {DEBATE_ROLE_LABELS[entry.raised_by_role]}
                  </Badge>
                  <span className="text-[11px] text-ink-faint">{entry.reason}</span>
                </div>
                <div className="mt-1 text-xs leading-relaxed text-ink-dim">
                  {entry.position}
                </div>
                <div className="mt-1.5">
                  <EvidenceCitations references={entry.evidence_references} />
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <div className="grid gap-3 lg:grid-cols-2">
        <Panel
          title="Unresolved questions"
          subtitle="What the debate could not settle from the evidence supplied."
        >
          {consensus.unresolved_questions.length === 0 ? (
            <div className="text-[11px] text-ink-faint">
              No unresolved questions were recorded.
            </div>
          ) : (
            <ul
              data-testid="debate-unresolved"
              className="list-disc space-y-1 pl-4 text-xs leading-relaxed text-ink-dim"
            >
              {consensus.unresolved_questions.map((question) => (
                <li key={question}>{question}</li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel
          title="Evidence gaps"
          subtitle="Evidence the debate needed and the graph could not supply."
        >
          {consensus.evidence_gaps.length === 0 ? (
            <div className="text-[11px] text-ink-faint">
              No evidence gaps were recorded.
            </div>
          ) : (
            <ul
              data-testid="debate-evidence-gaps"
              className="list-disc space-y-1 pl-4 text-xs leading-relaxed text-ink-dim"
            >
              {consensus.evidence_gaps.map((gap) => (
                <li key={gap}>{gap}</li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  )
}

function AssessmentsPanel({
  assessments,
}: {
  assessments: AgentAssessment[]
}) {
  return (
    <div className="space-y-3">
      {assessments.map((assessment) => (
        <Card key={assessment.agent_id} className="px-4 py-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="accent">
                {DEBATE_ROLE_LABELS[assessment.role]}
              </Badge>
              <ProvenanceBadge provenance={assessment.provenance} />
            </div>
            <span className="font-mono text-[11px] text-ink-dim">
              confidence {percent(assessment.confidence)}
            </span>
          </div>
          <div className="mt-1 text-[11px] leading-relaxed text-ink-faint">
            {assessment.objective}
          </div>

          {assessment.observations.length > 0 && (
            <div className="mt-3">
              <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
                Observations
              </div>
              <ul className="mt-1 space-y-2">
                {assessment.observations.map((claim) => (
                  <li
                    key={claim.claim_id}
                    data-testid="debate-observation"
                    className="rounded border border-edge-soft px-3 py-2"
                  >
                    <div className="text-xs leading-relaxed text-ink">
                      {claim.statement}
                    </div>
                    <div className="mt-1.5">
                      <EvidenceCitations references={claim.evidence_references} />
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {assessment.hypotheses.length > 0 && (
            <div className="mt-3">
              <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
                Hypotheses
              </div>
              <ul className="mt-1 space-y-2">
                {assessment.hypotheses.map((claim) => (
                  <li
                    key={claim.claim_id}
                    data-testid="debate-hypothesis"
                    className="rounded border border-edge-soft px-3 py-2"
                  >
                    <div className="text-xs leading-relaxed text-ink">
                      {claim.statement}
                    </div>
                    <div className="mt-1.5">
                      <EvidenceCitations references={claim.evidence_references} />
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {assessment.limitations.length > 0 && (
            <div className="mt-3">
              <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
                Limitations
              </div>
              <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px] leading-relaxed text-ink-faint">
                {assessment.limitations.map((limitation) => (
                  <li key={limitation}>{limitation}</li>
                ))}
              </ul>
            </div>
          )}

          {assessment.evidence_references.length > 0 && (
            <div className="mt-3">
              <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
                Evidence reviewed
              </div>
              <div className="mt-1">
                <EvidenceCitations references={assessment.evidence_references} />
              </div>
            </div>
          )}
        </Card>
      ))}
    </div>
  )
}

function ArgumentsPanel({
  arguments: debateArguments,
  counterarguments,
}: {
  arguments: DebateArgument[]
  counterarguments: DebateCounterargument[]
}) {
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Panel
        title="Arguments"
        subtitle="Cross-agent positions on the hypotheses raised in round 1."
        padded={false}
      >
        {debateArguments.length === 0 ? (
          <div className="px-4 py-4 text-[11px] text-ink-faint">
            No arguments were raised.
          </div>
        ) : (
          <ul className="divide-y divide-edge-soft">
            {debateArguments.map((argument) => (
              <li key={argument.argument_id} className="px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge
                    tone={argument.stance === 'supports' ? 'low' : 'high'}
                  >
                    {DEBATE_STANCE_LABELS[argument.stance]}
                  </Badge>
                  <span className="text-[11px] text-ink-faint">
                    {DEBATE_ROLE_LABELS[argument.author_role]} →{' '}
                    {DEBATE_ROLE_LABELS[argument.target_role]}
                  </span>
                </div>
                <div className="mt-1 text-xs leading-relaxed text-ink-dim">
                  {argument.statement}
                </div>
                <div className="mt-1.5">
                  <EvidenceCitations references={argument.evidence_references} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel
        title="Counterarguments"
        subtitle="Challenges raised against existing arguments, each naming the weakness it found."
        padded={false}
      >
        {counterarguments.length === 0 ? (
          <div className="px-4 py-4 text-[11px] text-ink-faint">
            No counterarguments were raised.
          </div>
        ) : (
          <ul className="divide-y divide-edge-soft">
            {counterarguments.map((counterargument) => (
              <li key={counterargument.counterargument_id} className="px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="medium">
                    {DEBATE_WEAKNESS_LABELS[counterargument.weakness]}
                  </Badge>
                  <span className="text-[11px] text-ink-faint">
                    {DEBATE_ROLE_LABELS[counterargument.author_role]}
                  </span>
                </div>
                <div className="mt-1 text-xs leading-relaxed text-ink-dim">
                  {counterargument.statement}
                </div>
                <div className="mt-1.5">
                  <EvidenceCitations references={counterargument.evidence_references} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}

/**
 * `POST /api/debates/{correlation_id}` runs or returns the debate; `GET
 * /api/debates/{debate_id}` reads a stored one back verbatim. The route
 * parameter decides which, mirroring the V3.22 correlation-scoped pages.
 */
export function DebatePage() {
  const { correlationId = '', debateId = '' } = useParams()
  const targetId = debateId || correlationId
  const isStored = debateId.length > 0

  const query = useQuery({
    queryKey: ['debates', isStored ? 'stored' : 'correlation', targetId],
    queryFn: () =>
      isStored ? debatesApi.get(targetId) : debatesApi.run(targetId),
    enabled: targetId.length > 0,
    // The POST is a model-invoking action, so it is never re-fired implicitly
    // by a refetch on window focus. Re-running is an explicit user action.
    refetchOnWindowFocus: false,
    retry: false,
  })

  const session = query.data
  const correlation = session?.correlation_id ?? correlationId

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Multi-Agent Debate"
        description="V3.23 — five specialized agents assess one correlation's evidence independently, argue across roles, and are reconciled deterministically. Conclusions are AI reasoning over persisted evidence, never evidence itself."
      >
        <Button asChild variant="outline" size="sm">
          <Link to={correlation ? `/correlations/${correlation}` : '/correlations'}>
            <ChevronLeft className="h-3.5 w-3.5" />
            Correlation
          </Link>
        </Button>
      </PageHeader>

      {!targetId ? (
        <Panel title="Choose a correlation">
          <div className="text-[11px] leading-relaxed text-ink-faint">
            A debate is always scoped to a single correlation, because its
            evidence surface is the bounded graph around that correlation. Open
            a correlation and start a debate from there.
          </div>
          <div className="mt-3">
            <Button asChild size="sm" variant="outline">
              <Link to="/correlations">
                <MessagesSquare className="h-3 w-3" aria-hidden="true" />
                Browse correlations
              </Link>
            </Button>
          </div>
        </Panel>
      ) : query.isLoading ? (
        <LoadingRows rows={8} />
      ) : query.isError ? (
        <Panel title="Debate unavailable" data-testid="debate-error">
          <ErrorState
            message={
              query.error instanceof ApiError
                ? query.error.detail
                : String(query.error)
            }
            onRetry={() => void query.refetch()}
          />
          <div className="mt-2 border-t border-edge-soft px-4 py-3 text-[11px] leading-relaxed text-ink-faint">
            The engine does not substitute a fabricated conclusion when the model
            provider is unavailable or returns unvalidated output. A debate that
            failed is reported as failed.
          </div>
        </Panel>
      ) : session ? (
        <>
          <Panel
            title="Session"
            subtitle={
              isStored
                ? 'Stored debate, read back exactly as recorded.'
                : 'Run or returned for this correlation.'
            }
            action={
              <div className="flex flex-wrap items-center justify-end gap-2 text-[11px] text-ink-faint">
                <span className="font-mono">
                  <MonoId id={session.debate_id} />
                </span>
                <span>{formatDateTime(session.metadata.created_at)}</span>
              </div>
            }
          >
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Stat
                label="Consensus"
                value={
                  <Badge tone={DEBATE_CONSENSUS_META[session.consensus.state].tone}>
                    {DEBATE_CONSENSUS_META[session.consensus.state].label}
                  </Badge>
                }
              />
              <Stat label="Confidence" value={percent(session.consensus.confidence)} />
              <Stat label="Agents" value={session.metadata.agent_count} />
              <Stat label="Rounds" value={session.rounds.length} />
            </div>

            <dl className="mt-4 grid gap-x-4 gap-y-2 text-[11px] sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-ink-faint">Provider</dt>
                <dd className="font-mono text-ink-dim">
                  {session.metadata.provider}
                  {session.metadata.model ? ` · ${session.metadata.model}` : ''}
                </dd>
              </div>
              <div>
                <dt className="text-ink-faint">Engine version</dt>
                <dd className="font-mono text-ink-dim">
                  {session.metadata.engine_version}
                </dd>
              </div>
              <div>
                <dt className="text-ink-faint">Graph snapshot</dt>
                <dd>
                  <MonoId id={session.metadata.graph_snapshot_digest} />
                </dd>
              </div>
              <div>
                <dt className="text-ink-faint">Configuration</dt>
                <dd>
                  <MonoId id={session.metadata.configuration_digest} />
                </dd>
              </div>
            </dl>

            <div className="mt-4 border-t border-edge-soft pt-3">
              <div className="flex flex-wrap items-center gap-2">
                <Scale className="h-3.5 w-3.5 text-ink-faint" aria-hidden="true" />
                <span className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
                  Evidence scope
                </span>
                <span className="font-mono text-[11px] text-ink-faint">
                  {session.evidence_scope.graph_node_count} nodes ·{' '}
                  {session.evidence_scope.graph_edge_count} edges ·{' '}
                  {session.evidence_scope.evidence_reference_count} references
                </span>
                {session.evidence_scope.graph_truncated && (
                  <Badge tone="medium">
                    graph truncated
                    {session.evidence_scope.graph_truncated_reason
                      ? ` · ${session.evidence_scope.graph_truncated_reason}`
                      : ''}
                  </Badge>
                )}
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {Object.entries(session.evidence_scope.node_type_counts).map(
                  ([nodeType, count]) => (
                    <Badge key={nodeType} tone="muted">
                      {KG_NODE_LABELS[nodeType as KnowledgeNodeType] ?? nodeType}{' '}
                      {count}
                    </Badge>
                  ),
                )}
              </div>
              {Object.keys(
                session.evidence_scope.unavailable_entity_types,
              ).length > 0 && (
                <div className="mt-2 text-[11px] leading-relaxed text-ink-faint">
                  Not represented in the evidence graph:{' '}
                  {Object.entries(
                    session.evidence_scope.unavailable_entity_types,
                  )
                    .map(([kind, reason]) => `${kind} (${reason})`)
                    .join(', ')}
                </div>
              )}
            </div>

            {session.limitations.length > 0 && (
              <div className="mt-4 border-t border-edge-soft pt-3">
                <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
                  Session limitations
                </div>
                <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px] leading-relaxed text-ink-faint">
                  {session.limitations.map((limitation) => (
                    <li key={limitation}>{limitation}</li>
                  ))}
                </ul>
              </div>
            )}
          </Panel>

          <Panel title="Consensus" subtitle="Deterministically reconciled from the arguments above — not a second model opinion.">
            <ConsensusPanel consensus={session.consensus} />
          </Panel>

          <Panel
            title="Agents and rounds"
            subtitle={`${session.agents.length} specialized agents over ${session.rounds.length} bounded rounds.`}
          >
            <div className="mb-4 flex flex-wrap gap-1">
              {session.rounds.map((round) => (
                <Badge key={round.round_number} tone="neutral">
                  {round.round_number} · {DEBATE_ROUND_LABELS[round.round_kind]}
                </Badge>
              ))}
            </div>
            <ul className="mb-4 space-y-1">
              {session.rounds.map((round) => (
                <li key={round.round_number} className="text-[11px] leading-relaxed text-ink-faint">
                  <span className="text-ink-dim">
                    {DEBATE_ROUND_LABELS[round.round_kind]}
                  </span>{' '}
                  — {round.summary}
                </li>
              ))}
            </ul>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
              {session.agents.map((agent) => (
                <Card key={agent.agent_id} className="px-3 py-2">
                  <div className="text-[11px] font-semibold text-ink">
                    {agent.display_name}
                  </div>
                  <div className="mt-0.5 text-[11px] leading-relaxed text-ink-faint">
                    {agent.objective}
                  </div>
                  {agent.focus_node_types.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {agent.focus_node_types.map((nodeType) => (
                        <Badge key={nodeType} tone="muted">
                          {KG_NODE_LABELS[nodeType as KnowledgeNodeType] ?? nodeType}
                        </Badge>
                      ))}
                    </div>
                  )}
                </Card>
              ))}
            </div>
          </Panel>

          <Panel
            title="Independent assessments"
            subtitle="Round 1. Each agent saw the same evidence and formed its own view before seeing any other's."
          >
            <AssessmentsPanel assessments={session.assessments} />
          </Panel>

          <ArgumentsPanel
            arguments={session.arguments}
            counterarguments={session.counterarguments}
          />

          {session.facts.length > 0 && (
            <Panel
              title="Engine-derived facts"
              subtitle="Computed deterministically from the graph. No model authored these, so they can be re-derived exactly."
            >
              <ul className="space-y-2" data-testid="debate-facts">
                {session.facts.map((fact) => (
                  <li
                    key={fact.fact_id}
                    className="rounded border border-edge-soft px-3 py-2"
                  >
                    <div className="text-xs leading-relaxed text-ink">
                      {fact.statement}
                    </div>
                    <div className="mt-1.5 flex flex-wrap items-center gap-2">
                      <EvidenceCitations references={fact.evidence_references} />
                      {fact.provenance && (
                        <ProvenanceBadge provenance={fact.provenance} />
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </>
      ) : (
        <Panel title="No debate">
          <NotAvailable
            title="No debate returned"
            body="The engine completed without producing a session to display."
          />
        </Panel>
      )}
    </div>
  )
}

export type { DebateSession }