import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ChevronLeft, Radar } from 'lucide-react'
import { predictionsApi } from '../api/predictions'
import { ApiError } from '../api/client'
import { ProvenanceBadge } from '../components/badges'
import { ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, PageHeader, Panel, Stat } from '../components/ui/card'
import { MonoId } from '../components/ui/mono-id'
import {
  KG_NODE_LABELS,
  PREDICTION_BASIS_LABELS,
  PREDICTION_CONFIDENCE_BAND_LABELS,
  PREDICTION_DEPTH_LABELS,
  PREDICTION_EVIDENCE_SUPPORT_LABELS,
  PREDICTION_KIND_LABELS,
  PREDICTION_LIMITATION_LABELS,
  PREDICTION_STANCE_LABELS,
  PREDICTION_STANCE_TONES,
  PREDICTION_STATUS_META,
  PREDICTION_TARGET_BASIS_LABELS,
} from '../lib/labels'
import type {
  AttackPrediction,
  KnowledgeNodeType,
  PredictionEvidence,
  PredictionLimitation,
} from '../types/api'

function percent(value: number): string {
  return `${(value * 100).toFixed(0)}%`
}

function nodeLabel(kind: string): string {
  return KG_NODE_LABELS[kind as KnowledgeNodeType] ?? kind
}

/**
 * Citations are rendered as resolvable pointers, and the stance is always
 * visible. Suppressing the contradicting list would quietly turn a contested
 * projection into a confident-looking one, which is the specific failure mode
 * this engine is built to avoid.
 */
function EvidenceList({
  items,
  emptyLabel,
}: {
  items: PredictionEvidence[]
  emptyLabel: string
}) {
  if (items.length === 0) {
    return <div className="text-[11px] text-ink-faint">{emptyLabel}</div>
  }
  return (
    <ul className="space-y-1.5" data-testid="prediction-evidence-list">
      {items.map((item) => (
        <li
          key={`${item.node_id}:${item.reference}:${item.stance}`}
          className="rounded border border-edge-soft px-3 py-2"
        >
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={PREDICTION_STANCE_TONES[item.stance]}>
              {PREDICTION_STANCE_LABELS[item.stance]}
            </Badge>
            <Badge tone="muted" title={`${item.entity_kind} · node ${item.node_id}`}>
              {item.reference}
            </Badge>
            <span className="text-[11px] text-ink-faint">{nodeLabel(item.entity_kind)}</span>
          </div>
          <div className="mt-1 text-[11px] leading-relaxed text-ink-dim">{item.detail}</div>
        </li>
      ))}
    </ul>
  )
}

function LimitationsList({
  limitations,
  testId,
}: {
  limitations: PredictionLimitation[]
  testId?: string
}) {
  if (limitations.length === 0) {
    return (
      <div className="text-[11px] text-ink-faint">
        No limitations were recorded for this run.
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
            {PREDICTION_LIMITATION_LABELS[limitation.kind] ?? limitation.kind}
          </Badge>
          <div className="mt-1 text-[11px] leading-relaxed text-ink-faint">
            {limitation.detail}
          </div>
        </li>
      ))}
    </ul>
  )
}

function PredictionCard({ prediction }: { prediction: AttackPrediction }) {
  const { uncertainty } = prediction
  const contradictionPenalty =
    uncertainty.confidence_basis.contradiction_penalty

  return (
    <Card className="px-4 py-3" data-testid="prediction-card">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={PREDICTION_STATUS_META[prediction.status].tone}>
              {PREDICTION_STATUS_META[prediction.status].label}
            </Badge>
            <Badge tone="neutral">{PREDICTION_KIND_LABELS[prediction.prediction_kind]}</Badge>
            <Badge tone="muted">{PREDICTION_DEPTH_LABELS[prediction.depth]}</Badge>
          </div>
          <div
            className="mt-1.5 text-sm font-semibold text-ink"
            data-testid="prediction-target"
          >
            {prediction.target}
          </div>
        </div>
        <div className="text-right">
          <div className="font-mono text-lg leading-none text-ink">
            {percent(uncertainty.confidence)}
          </div>
          <div className="mt-0.5 text-[11px] text-ink-faint">
            {PREDICTION_CONFIDENCE_BAND_LABELS[uncertainty.confidence_band]}
          </div>
        </div>
      </div>

      <div className="mt-2 text-xs leading-relaxed text-ink-dim">
        {prediction.rationale.summary}
      </div>

      <dl className="mt-3 grid gap-x-4 gap-y-2 text-[11px] sm:grid-cols-2">
        <div>
          <dt className="text-ink-faint">Target basis</dt>
          <dd className="text-ink-dim">
            {PREDICTION_TARGET_BASIS_LABELS[prediction.target_basis]}
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint">Basis</dt>
          <dd className="text-ink-dim">
            {PREDICTION_BASIS_LABELS[prediction.rationale.basis]}
            <span className="text-ink-faint">
              {' · '}
              {prediction.rationale.basis_detail}
            </span>
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint">Evidence support</dt>
          <dd className="text-ink-dim">
            {PREDICTION_EVIDENCE_SUPPORT_LABELS[uncertainty.evidence_support]}
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint">Debate agreement</dt>
          <dd className="font-mono text-ink-dim">
            {prediction.rationale.debate_agreement === null
              ? 'no debate consumed'
              : percent(prediction.rationale.debate_agreement)}
          </dd>
        </div>
      </dl>

      <div className="mt-3 rounded border border-edge-soft px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
            ATT&CK target
          </span>
          {prediction.technique.technique_id ? (
            <>
              <Badge tone="accent" data-testid="prediction-technique-id">
                {prediction.technique.technique_id}
              </Badge>
              <span className="text-[11px] text-ink-dim">
                {prediction.technique.technique_name}
              </span>
            </>
          ) : (
            <Badge tone="muted" data-testid="prediction-technique-absent">
              no persisted technique
            </Badge>
          )}
          {prediction.technique.tactic && (
            <Badge tone="neutral">{prediction.technique.tactic}</Badge>
          )}
        </div>
        <div className="mt-1 text-[11px] leading-relaxed text-ink-faint">
          {prediction.technique.technique_id_reason}
        </div>
      </div>

      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <div>
          <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-dim">
            Supporting
          </div>
          <EvidenceList
            items={uncertainty.supporting_evidence}
            emptyLabel="No supporting citation was available."
          />
        </div>
        <div>
          <div className="mb-1.5 flex items-center gap-2">
            <span className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
              Contradicting
            </span>
            {contradictionPenalty > 0 && (
              <Badge tone="high">penalty −{contradictionPenalty.toFixed(2)}</Badge>
            )}
          </div>
          <EvidenceList
            items={uncertainty.contradicting_evidence}
            emptyLabel="No contradicting citation was available."
          />
        </div>
      </div>

      <div className="mt-3">
        <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-ink-dim">
          Confidence basis
        </div>
        <dl
          className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] sm:grid-cols-5"
          data-testid="prediction-confidence-basis"
        >
          {(
            [
              ['evidence_support', 'Evidence'],
              ['evidence_diversity', 'Diversity'],
              ['debate_support', 'Debate'],
              ['target_specificity', 'Specificity'],
              ['contradiction_penalty', 'Penalty'],
            ] as const
          ).map(([key, label]) => (
            <div key={key}>
              <dt className="text-ink-faint">{label}</dt>
              <dd className="font-mono text-ink-dim">
                {uncertainty.confidence_basis[key].toFixed(2)}
              </dd>
            </div>
          ))}
        </dl>
      </div>

      {(uncertainty.evidence_gaps.length > 0 ||
        uncertainty.unresolved_questions.length > 0 ||
        uncertainty.limitations.length > 0) && (
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          {uncertainty.evidence_gaps.length > 0 && (
            <div>
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-ink-dim">
                Evidence gaps
              </div>
              <ul
                className="list-disc space-y-0.5 pl-4 text-[11px] leading-relaxed text-ink-faint"
                data-testid="prediction-evidence-gaps"
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
                data-testid="prediction-unresolved"
              >
                {uncertainty.unresolved_questions.map((question) => (
                  <li key={question}>{question}</li>
                ))}
              </ul>
            </div>
          )}
          {uncertainty.limitations.length > 0 && (
            <div className="sm:col-span-2">
              <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-ink-dim">
                Limitations
              </div>
              <LimitationsList limitations={uncertainty.limitations} />
            </div>
          )}
        </div>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-edge-soft pt-2 text-[11px] text-ink-faint">
        <ProvenanceBadge provenance={prediction.provenance} />
        <MonoId id={prediction.prediction_id} />
        {prediction.rationale.observed_techniques.length > 0 && (
          <span>
            observed:{' '}
            <span className="font-mono text-ink-dim">
              {prediction.rationale.observed_techniques.join(', ')}
            </span>
          </span>
        )}
      </div>
    </Card>
  )
}

/**
 * `POST /api/attack-predictions/{correlation_id}` runs or returns the prediction;
 * `GET /api/attack-predictions/{prediction_id}` reads a stored one back. The
 * route parameter decides which, mirroring the V3.22/V3.23 correlation-scoped
 * pages.
 */
export function PredictionPage() {
  const { correlationId = '', predictionId = '' } = useParams()
  const targetId = predictionId || correlationId
  const isStored = predictionId.length > 0

  const query = useQuery({
    queryKey: ['attack-predictions', isStored ? 'stored' : 'correlation', targetId],
    queryFn: () =>
      isStored ? predictionsApi.get(targetId) : predictionsApi.run(targetId),
    enabled: targetId.length > 0,
    // The POST runs deterministic analysis over the current graph. It is not
    // re-fired implicitly by a refetch, so window focus cannot silently change
    // what is on screen; re-running is an explicit user action.
    refetchOnWindowFocus: false,
    retry: false,
  })

  const result = query.data
  const correlation = result?.correlation_id ?? correlationId
  const statusMeta = result ? PREDICTION_STATUS_META[result.status] : null

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Attack Prediction"
        description="V3.24 — deterministic projection of plausible next stages from persisted evidence, the V3.22 graph and the V3.23 debate. A prediction is AI reasoning, never evidence, and the engine declines to speculate when nothing supports a stage."
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
            A prediction is always scoped to a single correlation, because its
            inputs are the bounded graph and the persisted evidence around that
            correlation. Open a correlation and run a prediction from there.
          </div>
          <div className="mt-3">
            <Button asChild size="sm" variant="outline">
              <Link to="/correlations">
                <Radar className="h-3 w-3" aria-hidden="true" />
                Browse correlations
              </Link>
            </Button>
          </div>
        </Panel>
      ) : query.isLoading ? (
        <LoadingRows rows={8} />
      ) : query.isError ? (
        <Panel title="Prediction unavailable" data-testid="prediction-error">
          <ErrorState
            message={
              query.error instanceof ApiError
                ? query.error.detail
                : String(query.error)
            }
            onRetry={() => void query.refetch()}
          />
          <div className="mt-2 border-t border-edge-soft px-4 py-3 text-[11px] leading-relaxed text-ink-faint">
            A failure here means the engine could not run at all. It never
            substitutes a fabricated projection: when inputs are missing it
            answers successfully with insufficient evidence instead.
          </div>
        </Panel>
      ) : result ? (
        <>
          <Panel
            title="Session"
            subtitle={
              isStored
                ? 'Stored prediction, read back exactly as recorded.'
                : 'Run or returned for this correlation.'
            }
            action={
              <div className="flex flex-wrap items-center justify-end gap-2 text-[11px] text-ink-faint">
                <MonoId id={result.prediction_session_id} />
                {result.status === 'INSUFFICIENT_EVIDENCE' && (
                  <span>returned without speculation</span>
                )}
              </div>
            }
          >
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Stat
                label="Outcome"
                value={
                  statusMeta ? (
                    <Badge tone={statusMeta.tone}>{statusMeta.label}</Badge>
                  ) : (
                    '—'
                  )
                }
              />
              <Stat label="Predictions" value={result.predictions.length} />
              <Stat label="Observed techniques" value={result.observed_techniques.length} />
              <Stat label="Graph inputs" value={`${result.metadata.graph_node_count} / ${result.metadata.graph_edge_count}`} />
            </div>

            <dl className="mt-4 grid gap-x-4 gap-y-2 text-[11px] sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-ink-faint">Engine version</dt>
                <dd className="font-mono text-ink-dim">{result.metadata.engine_version}</dd>
              </div>
              <div>
                <dt className="text-ink-faint">Max depth</dt>
                <dd className="font-mono text-ink-dim">{result.metadata.max_depth}</dd>
              </div>
              <div>
                <dt className="text-ink-faint">Debate consumed</dt>
                <dd className="text-ink-dim">
                  <MonoId id={result.metadata.debate_id} />
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
              <div className="text-[11px] leading-relaxed text-ink-faint">
                {result.limitations_note}
              </div>
            </div>
          </Panel>

          {result.predictions.length === 0 ? (
            <Panel title="Projections">
              <div data-testid="prediction-insufficient">
                <NotAvailable
                  title="No prediction made"
                  body="The engine found no persisted evidence naming a plausible next stage. Returning nothing is the correct result: a prediction without a resolvable basis would be speculation."
                />
              </div>
            </Panel>
          ) : (
            <Panel
              title="Projections"
              subtitle={`${result.predictions.length} bounded projection(s), depth at most ${result.metadata.max_depth}. Deterministic — the same inputs always produce the same output.`}
              padded={false}
            >
              <ul className="divide-y divide-edge-soft" data-testid="prediction-list">
                {result.predictions.map((prediction) => (
                  <li key={prediction.prediction_id} className="px-4 py-3">
                    <PredictionCard prediction={prediction} />
                  </li>
                ))}
              </ul>
            </Panel>
          )}

          {result.current_state.length > 0 && (
            <Panel
              title="Current observed state"
              subtitle="The persisted facts this projection starts from. These are evidence; nothing above them is."
              padded={false}
            >
              <ul className="divide-y divide-edge-soft">
                {result.current_state.map((item) => (
                  <li key={`${item.node_id}:${item.reference}`} className="px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="muted">{item.reference}</Badge>
                      <span className="text-[11px] text-ink-faint">
                        {nodeLabel(item.entity_kind)}
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
            title="Session limitations"
            subtitle="Everything that shaped this run, including inputs that were unavailable. An empty list means nothing was constrained."
          >
            <LimitationsList
              limitations={result.limitations}
              testId="prediction-limitations"
            />
            {Object.keys(result.metadata.unavailable_inputs).length > 0 && (
              <div className="mt-3 border-t border-edge-soft pt-3">
                <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
                  Unavailable inputs
                </div>
                <ul
                  className="mt-1 space-y-0.5 text-[11px] leading-relaxed text-ink-faint"
                  data-testid="prediction-unavailable-inputs"
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
          </Panel>
        </>
      ) : (
        <Panel title="No prediction">
          <NotAvailable
            title="No prediction returned"
            body="The engine completed without producing a session to display."
          />
        </Panel>
      )}
    </div>
  )
}