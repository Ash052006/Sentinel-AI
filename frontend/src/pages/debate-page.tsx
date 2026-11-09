import { useState, useMemo } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  ChevronDown,
  ChevronLeft,
  ChevronUp,
  Eye,
  EyeOff,
  HelpCircle,
  MessagesSquare,
  Scale,
  Sparkles,
} from 'lucide-react'
import { debatesApi } from '../api/debates'
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
 * Evidence citations are rendered as resolvable references rather than plain text.
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
  session,
}: {
  consensus: DebateConsensus
  session?: DebateSession
}) {
  const meta = DEBATE_CONSENSUS_META[consensus.state]
  const supporting = consensus.supporting_arguments.length
  const opposing = consensus.opposing_arguments.length

  // Operational triage synthesis based on deterministic consensus state
  const triageGuidance = {
    consensus: {
      badge: 'Confirmed Incident · High Confidence',
      badgeTone: 'critical' as const,
      summary:
        'Unanimous agreement across specialized security models. The evidence aligns with an active adversary campaign rather than benign activity.',
      recommendedAction:
        'Initiate Host Containment (Isolate Endpoint & Revoke Session Credentials). Execute rapid response playbook.',
      playbookLink: '/responses',
    },
    partial_consensus: {
      badge: 'Probable Threat · Secondary Verification',
      badgeTone: 'high' as const,
      summary:
        'Majority consensus established among specialist agents. Core indicators show malicious telemetry with minor limitations noted.',
      recommendedAction:
        'Review correlated process trees and target user session context before triggering disruptive isolation.',
      playbookLink: '/responses',
    },
    contested: {
      badge: 'Contested · High False-Positive Risk',
      badgeTone: 'medium' as const,
      summary:
        'Active disagreement within the committee. Security Skeptic and peer models identified plausible benign operational causes (e.g. sysadmin scripts, test tooling, or high false-positive alert sensitivity).',
      recommendedAction:
        'Perform manual host verification and check change management logs before taking destructive mitigation.',
      playbookLink: '/responses',
    },
    insufficient_evidence: {
      badge: 'Inconclusive · Telemetry Visibility Gap',
      badgeTone: 'muted' as const,
      summary:
        'The bounded knowledge graph lacks critical log types or endpoint entities needed to prove or refute the attack chain.',
      recommendedAction:
        'Expand sensor logging and collect missing telemetry for the unrepresented entity types below.',
      playbookLink: '/responses',
    },
  }[consensus.state] ?? {
    badge: 'Under Review',
    badgeTone: 'muted' as const,
    summary: 'Deliberation concluded.',
    recommendedAction: 'Proceed with standard operational triage.',
    playbookLink: '/responses',
  }

  return (
    <div className="space-y-4">
      {/* SECTION 1: EXECUTIVE CONCLUSION & ACTIONABLE TRIAGE BANNER */}
      <div className="rounded-lg border border-accent/30 bg-surface-2/40 p-4 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-edge-soft pb-3">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <Sparkles className="h-4 w-4" />
            Executive Consensus & Threat Verdict
          </div>
          <Badge tone={triageGuidance.badgeTone}>
            {triageGuidance.badge}
          </Badge>
        </div>

        {/* Leading Hypothesis Display */}
        <div className="mt-3">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-dim">
            Leading Hypothesis
          </div>
          {consensus.leading_hypothesis ? (
            <div
              data-testid="debate-leading-hypothesis"
              className="mt-1.5 text-base font-semibold leading-relaxed text-ink"
            >
              {consensus.leading_hypothesis}
            </div>
          ) : (
            <div className="mt-1.5 text-sm text-ink-faint">
              No hypothesis was raised from the available evidence.
            </div>
          )}
        </div>

        {/* Operational Interpretation & Action Guidance */}
        <div className="mt-3.5 grid gap-3 rounded-lg border border-edge bg-surface-1 p-3 sm:grid-cols-2">
          <div>
            <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
              Triage Assessment
            </div>
            <p className="mt-1 text-xs leading-relaxed text-ink-dim">
              {triageGuidance.summary}
            </p>
          </div>
          <div>
            <div className="flex items-center justify-between text-[11px] font-medium uppercase tracking-wider text-ink-dim">
              <span>Recommended SOC Action</span>
              <Button asChild variant="ghost" size="sm" className="h-5 px-1 text-[11px] text-accent">
                <Link to={triageGuidance.playbookLink}>
                  SOAR Console <ArrowRight className="ml-1 h-3 w-3" />
                </Link>
              </Button>
            </div>
            <p className="mt-1 text-xs font-medium leading-relaxed text-ink">
              {triageGuidance.recommendedAction}
            </p>
          </div>
        </div>

        {/* Metadata Footer */}
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-edge-soft pt-2.5 text-[11px] text-ink-dim">
          <span className="font-mono">
            {supporting} supporting arguments · {opposing} opposing arguments
          </span>
          <ProvenanceBadge provenance={consensus.provenance} />
        </div>
      </div>

      {/* SECTION 2: CONSENSUS METRICS */}
      <div className="grid gap-3 sm:grid-cols-3">
        <Stat
          label="Consensus State"
          value={<Badge tone={meta.tone}>{meta.label}</Badge>}
        />
        <Stat
          label="Agent Agreement Strength"
          value={percent(consensus.consensus_strength)}
        />
        <Stat
          label="Computed Confidence"
          value={percent(consensus.confidence)}
        />
      </div>

      {/* SECTION 3: 5-AGENT SPECIALIST PERSPECTIVES MATRIX */}
      {session && session.agents.length > 0 && (
        <Panel
          title="Specialist AI Committee Positions"
          subtitle="Distinct assessments and threat interpretations from 5 autonomous SOC domain agents."
        >
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {session.agents.map((agent) => {
              const assessment = session.assessments.find(
                (a) => a.agent_id === agent.agent_id,
              )
              const topHypothesis =
                assessment?.hypotheses[0]?.statement ??
                assessment?.observations[0]?.statement ??
                'No hypothesis raised.'
              const isSkeptic = agent.role === 'skeptic'

              return (
                <div
                  key={agent.agent_id}
                  className="flex flex-col justify-between rounded-lg border border-edge bg-surface-1 p-3.5"
                >
                  <div>
                    <div className="flex items-center justify-between gap-1.5">
                      <div className="flex items-center gap-1.5">
                        <Bot className="h-3.5 w-3.5 text-accent" />
                        <span className="text-xs font-semibold text-ink">
                          {DEBATE_ROLE_LABELS[agent.role]}
                        </span>
                      </div>
                      {assessment && (
                        <span className="font-mono text-[10px] text-ink-faint">
                          {percent(assessment.confidence)}
                        </span>
                      )}
                    </div>
                    <div className="mt-1 text-[11px] text-ink-faint">
                      {agent.objective}
                    </div>
                    <div className="mt-2.5 rounded bg-surface-2/60 p-2 text-xs leading-relaxed text-ink">
                      <div className="text-[10px] font-medium uppercase tracking-wider text-ink-dim">
                        {isSkeptic ? 'Contrarian Challenge' : 'Primary Hypothesis'}
                      </div>
                      <div className="mt-0.5 line-clamp-3">
                        {topHypothesis}
                      </div>
                    </div>
                  </div>

                  {assessment && assessment.limitations.length > 0 && (
                    <div className="mt-2 text-[10px] text-ink-faint">
                      Limitation: {assessment.limitations[0]}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </Panel>
      )}

      {/* SECTION 4: CORROBORATING EVIDENCE VS SKEPTIC CHALLENGES */}
      <div className="grid gap-3 lg:grid-cols-2">
        {/* Supporting Arguments */}
        <Panel
          title="Corroborating Evidence & Arguments"
          subtitle="Key arguments validating the malicious hypothesis with telemetry citations."
        >
          {consensus.supporting_arguments.length === 0 ? (
            <div className="text-[11px] text-ink-faint">
              No corroborating arguments were raised for the leading hypothesis.
            </div>
          ) : (
            <ul className="space-y-2.5">
              {consensus.supporting_arguments.slice(0, 4).map((arg) => (
                <li
                  key={arg.argument_id}
                  className="rounded border border-edge-soft bg-surface-1 p-2.5"
                >
                  <div className="flex items-center gap-2">
                    <Badge tone="low">
                      {DEBATE_ROLE_LABELS[arg.author_role]}
                    </Badge>
                    <span className="text-[10px] text-ink-faint">
                      supports hypothesis
                    </span>
                  </div>
                  <div className="mt-1.5 text-xs leading-relaxed text-ink">
                    {arg.statement}
                  </div>
                  <div className="mt-1.5">
                    <EvidenceCitations references={arg.evidence_references} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        {/* Counterarguments & Skepticism */}
        <Panel
          title="Skeptic Challenges & Alternative Causes"
          subtitle="Identified false-positive risks, missing evidence, or benign operational explanations."
        >
          {consensus.opposing_arguments.length === 0 &&
          (!session || session.counterarguments.length === 0) ? (
            <div className="text-[11px] text-ink-faint">
              No formal counterarguments or objections were sustained.
            </div>
          ) : (
            <ul className="space-y-2.5">
              {[
                ...consensus.opposing_arguments,
                ...(session?.counterarguments.slice(0, 3) ?? []),
              ].slice(0, 4).map((item) => {
                const isOpposing = 'stance' in item
                const label = isOpposing
                  ? `opposes · ${DEBATE_ROLE_LABELS[item.author_role]}`
                  : `${DEBATE_WEAKNESS_LABELS[item.weakness]} · ${DEBATE_ROLE_LABELS[item.author_role]}`

                return (
                  <li
                    key={'argument_id' in item ? item.argument_id : item.counterargument_id}
                    className="rounded border border-edge-soft bg-surface-1 p-2.5"
                  >
                    <div className="flex items-center gap-2">
                      <Badge tone="medium">{label}</Badge>
                    </div>
                    <div className="mt-1.5 text-xs leading-relaxed text-ink">
                      {item.statement}
                    </div>
                    <div className="mt-1.5">
                      <EvidenceCitations references={item.evidence_references} />
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </Panel>
      </div>

      {/* SECTION 5: DISSENTING POSITIONS IF ANY */}
      {consensus.dissent.length > 0 && (
        <Panel
          title="Dissenting Positions"
          subtitle="Alternative viewpoints that challenged the leading consensus."
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

      {/* SECTION 6: UNRESOLVED QUESTIONS & EVIDENCE GAPS (Investigative Checklist) */}
      <div className="grid gap-3 lg:grid-cols-2">
        <Panel
          title="Investigative Checklist / Unresolved Questions"
          subtitle="Concrete questions the analyst must verify next with host or network logs."
        >
          {consensus.unresolved_questions.length === 0 ? (
            <div className="text-[11px] text-ink-faint">
              No unresolved questions were recorded.
            </div>
          ) : (
            <ul
              data-testid="debate-unresolved"
              className="space-y-2 text-xs leading-relaxed text-ink"
            >
              {consensus.unresolved_questions.map((question) => (
                <li key={question} className="flex items-start gap-2">
                  <HelpCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" />
                  <span>{question}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="Telemetry Visibility Gaps"
          subtitle="Missing log sources or unrepresented entities that would clarify the incident."
        >
          {consensus.evidence_gaps.length === 0 ? (
            <div className="text-[11px] text-ink-faint">
              No telemetry gaps were identified. Telemetry was sufficient.
            </div>
          ) : (
            <ul
              data-testid="debate-evidence-gaps"
              className="space-y-2 text-xs leading-relaxed text-ink"
            >
              {consensus.evidence_gaps.map((gap) => (
                <li key={gap} className="flex items-start gap-2">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" />
                  <span>{gap}</span>
                </li>
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

function RoundsTimeline({
  session,
}: {
  session: DebateSession
}) {
  return (
    <Panel
      title="Debate Rounds Lifecycle"
      subtitle="The fixed five-round process, from evidence grounding through reconciliation."
      padded={false}
    >
      <ol className="divide-y divide-edge-soft">
        {session.rounds.map((round) => (
          <li key={round.round_number} className="px-4 py-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone="accent">Round {round.round_number}</Badge>
                <span className="text-xs font-medium text-ink">
                  {DEBATE_ROUND_LABELS[round.round_kind]}
                </span>
              </div>
              <span className="font-mono text-[11px] text-ink-faint">
                {round.agent_ids.length > 0 &&
                  `${round.agent_ids.length} agents · `}
                {round.argument_ids.length > 0 &&
                  `${round.argument_ids.length} arguments · `}
                {round.counterargument_ids.length > 0 &&
                  `${round.counterargument_ids.length} counterarguments`}
              </span>
            </div>
            <div className="mt-1 text-xs leading-relaxed text-ink-dim">
              {round.summary}
            </div>
          </li>
        ))}
      </ol>
    </Panel>
  )
}

/**
 * `POST /api/debates/{correlation_id}` runs or returns the debate; `GET
 * /api/debates/{debate_id}` reads a stored one back verbatim.
 */
export function DebatePage() {
  const { correlationId = '', debateId = '' } = useParams()
  const targetId = debateId || correlationId
  const isStored = debateId.length > 0
  const [showEvidence, setShowEvidence] = useState(false)

  const query = useQuery({
    queryKey: ['debates', isStored ? 'stored' : 'correlation', targetId],
    queryFn: () =>
      isStored ? debatesApi.get(targetId) : debatesApi.run(targetId),
    enabled: targetId.length > 0,
    refetchOnWindowFocus: false,
    retry: false,
  })

  const session = query.data
  const correlation = session?.correlation_id ?? correlationId
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

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Multi-Agent Debate"
        description="Collaborative threat reasoning: specialized SOC AI agents evaluate correlated telemetry and reconcile hypotheses deterministically."
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
            subtitle="Select an active security correlation to evaluate threat telemetry with the multi-agent committee"
            padded={false}
          >
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-edge px-4 py-3 bg-surface-2/40">
              <div className="text-[11px] leading-relaxed text-ink-dim">
                Multi-agent debate deliberates across multiple correlated signals to reach consensus. Multi-incident correlations provide rich evidence for analysis.
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
              A debate is always scoped to a single correlation, because its
              evidence surface is the bounded graph around that correlation. Select an active correlation below to initiate or inspect debate consensus.
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
                No active correlations recorded yet. Ingest telemetry or run demo scenarios to produce correlation events.
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
                          <Link to={`/debates/correlation/${row.correlation_id}`}>
                            <MessagesSquare className="h-3.5 w-3.5 text-accent" />
                            {row.members.length > 1 ? 'Run Debate' : 'Run (Single Event)'}
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
        <Panel title="Multi-Agent Security Committee Deliberating">
          <div className="space-y-4 py-4 text-center">
            <div className="flex justify-center">
              <div className="relative flex h-14 w-14 items-center justify-center rounded-full bg-accent/10 border border-accent/30">
                <Sparkles className="h-7 w-7 text-accent animate-pulse" />
              </div>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-ink">
                Autonomous Cross-Agent Threat Deliberation In Progress
              </h3>
              <p className="mt-1 text-xs text-ink-dim max-w-lg mx-auto">
                5 specialized SOC AI agents (Detection, Behavioral, Incident Investigator, Threat Intel, and Security Skeptic) are evaluating telemetry, challenging hypotheses, and reconciling deterministic consensus.
              </p>
            </div>
            {/* Step progress pills */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 max-w-2xl mx-auto text-left">
              <div className="rounded border border-edge bg-surface-2/60 p-2 text-xs">
                <div className="font-semibold text-ink">Round 0: Grounding</div>
                <div className="text-[10px] text-ink-faint">Bounded graph facts extraction</div>
              </div>
              <div className="rounded border border-edge bg-surface-2/60 p-2 text-xs">
                <div className="font-semibold text-ink">Round 1: Assessments</div>
                <div className="text-[10px] text-ink-faint">5 parallel independent claims</div>
              </div>
              <div className="rounded border border-edge bg-surface-2/60 p-2 text-xs">
                <div className="font-semibold text-ink">Round 2 & 3: Cross-Exam</div>
                <div className="text-[10px] text-ink-faint">Skeptic challenges & rebuttals</div>
              </div>
              <div className="rounded border border-edge bg-surface-2/60 p-2 text-xs">
                <div className="font-semibold text-ink">Round 4: Consensus</div>
                <div className="text-[10px] text-ink-faint">Deterministic reconciliation</div>
              </div>
            </div>
            <div className="text-[11px] text-ink-faint pt-2">
              Executing live reasoning pipeline... Typically completes within 10–15 seconds.
            </div>
          </div>
        </Panel>
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
          {/* SECTION 1: PRIMARY EXECUTIVE CONCLUSION & CONSENSUS (Always visible) */}
          <Panel
            title="Debate Findings & Consensus"
            subtitle="Executive summary, specialist positions, and operational triage synthesized from cross-agent deliberations."
            action={
              <div className="flex flex-wrap items-center justify-end gap-2 text-[11px] text-ink-faint">
                <span className="font-mono">
                  <MonoId id={session.debate_id} />
                </span>
                <span>{formatDateTime(session.metadata.created_at)}</span>
              </div>
            }
          >
            <ConsensusPanel consensus={session.consensus} session={session} />
          </Panel>

          {/* SECTION 2: EVIDENCE & DETAILED TRACE TOGGLE BAR */}
          <div className="flex flex-col gap-3 rounded-lg border border-edge bg-surface-1 p-3.5 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2.5">
              <div className="rounded bg-surface-2 p-1.5 text-ink">
                <Scale className="h-4 w-4" />
              </div>
              <div>
                <div className="text-xs font-semibold text-ink">
                  Detailed Evidence Citations & Raw Deliberation Trace
                </div>
                <div className="text-[11px] text-ink-faint">
                  {session.evidence_scope.evidence_reference_count} evidence citations ·{' '}
                  {session.agents.length} agent perspectives ·{' '}
                  {session.rounds.length} deliberation rounds
                </div>
              </div>
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowEvidence((prev) => !prev)}
              className="gap-1.5 self-start sm:self-auto"
            >
              {showEvidence ? (
                <>
                  <EyeOff className="h-3.5 w-3.5" />
                  Hide Detailed Evidence
                  <ChevronUp className="h-3.5 w-3.5" />
                </>
              ) : (
                <>
                  <Eye className="h-3.5 w-3.5" />
                  View All Evidence & Debate Trace
                  <ChevronDown className="h-3.5 w-3.5" />
                </>
              )}
            </Button>
          </div>

          {/* SECTION 3: DETAILED TRACE & CITATIONS (Collapsible / toggleable) */}
          <div className={showEvidence ? 'space-y-4' : 'hidden'}>
            {/* Engine Derived Facts */}
            {session.facts.length > 0 && (
              <Panel
                title="Engine-Derived Facts"
                subtitle="Deterministic facts computed directly from the correlation knowledge graph."
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

            {/* Evidence Scope & Node Breakdown */}
            <Panel
              title="Evidence Graph Scope"
              subtitle="The exact subset of knowledge-graph nodes and relationships reviewed by the debate."
            >
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-ink-dim">
                <span className="font-mono">
                  {session.evidence_scope.graph_node_count} nodes ·{' '}
                  {session.evidence_scope.graph_edge_count} edges ·{' '}
                  {session.evidence_scope.evidence_reference_count} citations
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
              <div className="mt-2.5 flex flex-wrap gap-1.5">
                {Object.entries(session.evidence_scope.node_type_counts).map(
                  ([nodeType, count]) => (
                    <Badge key={nodeType} tone="muted">
                      {KG_NODE_LABELS[nodeType as KnowledgeNodeType] ?? nodeType}{' '}
                      {count}
                    </Badge>
                  ),
                )}
              </div>
              {Object.keys(session.evidence_scope.unavailable_entity_types).length > 0 && (
                <div className="mt-2 text-[11px] text-ink-faint">
                  Not represented in evidence graph:{' '}
                  {Object.entries(session.evidence_scope.unavailable_entity_types)
                    .map(([type, reason]) => `${type} (${reason})`)
                    .join(', ')}
                </div>
              )}
            </Panel>

            {/* Full Agent Assessments */}
            <Panel
              title="Full Agent Assessments (Round 1)"
              subtitle="Independent observations, hypotheses, and limitations from each specialist agent."
            >
              <AssessmentsPanel assessments={session.assessments} />
            </Panel>

            {/* Cross-Agent Arguments & Counterarguments */}
            <ArgumentsPanel
              arguments={session.arguments}
              counterarguments={session.counterarguments}
            />

            {/* 5-Round Lifecycle Trace */}
            <RoundsTimeline session={session} />
          </div>
        </>
      ) : (
        <NotAvailable
          title="No debate recorded"
          body="No multi-agent debate session has been conducted for this correlation yet."
        />
      )}
    </div>
  )
}
