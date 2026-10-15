import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { investigationsApi } from '../api/investigations'
import { ApiError } from '../api/client'
import type {
  DimensionCoverage,
  DimensionExplanation,
  ExplainabilityResult,
  ExplanationStatus,
} from '../types/api'
import type { Tone } from '../lib/labels'
import { Panel } from './ui/card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { MonoId } from './ui/mono-id'
import { ConfidenceBar } from './ui/progress'
import { EmptyState, ErrorState, LoadingRows } from './states'
import { ProvenanceBadge } from './badges'
import { formatTimestamp } from '../lib/formats'

const COVERAGE_TONE: Record<DimensionCoverage, Tone> = {
  grounded: 'low',
  none_found: 'muted',
  unavailable: 'high',
}

const COVERAGE_LABEL: Record<DimensionCoverage, string> = {
  grounded: 'grounded',
  none_found: 'none found',
  unavailable: 'unavailable',
}

const STATUS_TONE: Record<ExplanationStatus, Tone> = {
  explained: 'low',
  insufficient_evidence: 'muted',
  ai_unavailable: 'high',
}

const STATUS_LABEL: Record<ExplanationStatus, string> = {
  explained: 'explained',
  insufficient_evidence: 'insufficient evidence',
  ai_unavailable: 'AI unavailable',
}

function DimensionCard({ dimension }: { dimension: DimensionExplanation }) {
  return (
    <li
      className="rounded-md border border-edge-soft p-3"
      data-testid={`dimension-${dimension.dimension}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-ink">{dimension.title}</span>
        <Badge tone={COVERAGE_TONE[dimension.coverage]}>
          {COVERAGE_LABEL[dimension.coverage]}
        </Badge>
        <ProvenanceBadge provenance={dimension.provenance} />
      </div>
      <p className="mt-1 text-[11px] text-ink-dim">{dimension.summary}</p>

      {dimension.unavailable_reason && (
        <p className="mt-1 text-[11px] text-high">
          Not available: {dimension.unavailable_reason}
        </p>
      )}

      {dimension.claims.length > 0 && (
        <ul className="mt-2 space-y-1">
          {dimension.claims.map((claim, index) => (
            <li key={index} className="text-[11px] text-ink">
              <span>{claim.text}</span>
              {claim.evidence_ids.length > 0 && (
                <span className="ml-1 font-mono text-[10px] text-ink-faint">
                  ({claim.evidence_ids.length} evidence)
                </span>
              )}
            </li>
          ))}
        </ul>
      )}

      {dimension.reference_ids.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <span className="text-[10px] uppercase tracking-wider text-ink-faint">
            Sources
          </span>
          {dimension.reference_ids.map((id) => (
            <MonoId key={id} id={id} copy={false} />
          ))}
        </div>
      )}
    </li>
  )
}

function ResultView({ result }: { result: ExplainabilityResult }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={STATUS_TONE[result.status]}>
          {STATUS_LABEL[result.status]}
        </Badge>
        {result.ai_provider && (
          <Badge tone="accent">
            {result.ai_provider}
            {result.ai_model ? ` · ${result.ai_model}` : ''}
          </Badge>
        )}
        <span className="text-[11px] text-ink-faint">
          generated {formatTimestamp(result.generated_at)}
        </span>
      </div>

      <ul
        className="grid grid-cols-1 gap-2 lg:grid-cols-2"
        data-testid="explanation-dimensions"
      >
        {result.dimensions.map((dimension) => (
          <DimensionCard key={dimension.dimension} dimension={dimension} />
        ))}
      </ul>

      {result.narrative.length > 0 && (
        <div data-testid="explanation-narrative">
          <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
            AI narrative
          </div>
          <ul className="mt-2 space-y-2">
            {result.narrative.map((finding, index) => (
              <li
                key={index}
                className="rounded-md border border-edge-soft p-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-semibold text-ink">
                    {finding.title}
                  </span>
                  <ConfidenceBar value={finding.confidence} />
                </div>
                {finding.summary && (
                  <p className="mt-1 text-[11px] text-ink-dim">
                    {finding.summary}
                  </p>
                )}
                <div className="mt-1 text-[10px] text-ink-faint">
                  {finding.evidence_ids.length} referenced evidence record(s)
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.observations.length > 0 && (
        <div>
          <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
            Observations
          </div>
          <ul className="mt-2 space-y-1">
            {result.observations.map((observation, index) => (
              <li key={index} className="text-[11px] text-ink-dim">
                {observation.observation_text}
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.unsupported_claims.length > 0 && (
        <div
          data-testid="unsupported-claims"
          className="rounded-md border border-high/40 bg-high/10 p-3"
        >
          <div className="text-[11px] font-medium text-high">
            Flagged: AI statements without supporting evidence
          </div>
          <ul className="mt-1 list-disc pl-4 text-[11px] text-high">
            {result.unsupported_claims.map((claim, index) => (
              <li key={index}>{claim}</li>
            ))}
          </ul>
        </div>
      )}

      {result.limitations.length > 0 && (
        <div data-testid="explanation-limitations">
          <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
            What could not be grounded
          </div>
          <ul className="mt-1 list-disc pl-4 text-[11px] text-ink-faint">
            {result.limitations.map((limitation, index) => (
              <li key={index}>{limitation}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

/**
 * Evidence-grounded explanation of *why* SentinelAI reached a conclusion about
 * one correlation.
 *
 * The deterministic GET is the default view; the AI narrative is opt-in and
 * failures degrade to status `ai_unavailable` (never a fabricated narrative),
 * so the panel always shows the source-backed dimensions regardless.
 */
export function ExplainabilityPanel({
  correlationId,
}: {
  correlationId: string | null
}) {
  const [aiResult, setAiResult] = useState<{
    correlationId: string
    result: ExplainabilityResult
  } | null>(null)

  const query = useQuery({
    queryKey: ['explanation', correlationId],
    queryFn: () => investigationsApi.explain(correlationId as string),
    enabled: Boolean(correlationId),
  })

  const aiMutation = useMutation({
    mutationFn: (id: string) => investigationsApi.explainWithAi(id, true),
    onSuccess: (result, id) => setAiResult({ correlationId: id, result }),
  })

  const displayed =
    correlationId && aiResult?.correlationId === correlationId
      ? aiResult.result
      : query.data

  return (
    <Panel
      title="Why SentinelAI reached this conclusion"
      subtitle="Evidence-grounded explanation — deterministic facts first, optional AI narrative that may only reference real evidence"
      action={
        correlationId ? (
          <Button
            variant="outline"
            size="sm"
            disabled={aiMutation.isPending}
            onClick={() => {
              aiMutation.mutate(correlationId)
            }}
          >
            {aiMutation.isPending ? 'Reasoning…' : 'Add AI narrative'}
          </Button>
        ) : undefined
      }
    >
      {!correlationId ? (
        <EmptyState
          title="Select a correlation"
          body="Choose a correlation above to explain why SentinelAI grouped its detections, what risk it assessed, and which policy and response actions were recorded."
        />
      ) : query.isLoading ? (
        <LoadingRows rows={6} />
      ) : query.isError ? (
        <ErrorState
          message={
            query.error instanceof ApiError
              ? query.error.detail
              : 'The explanation could not be loaded.'
          }
          onRetry={() => query.refetch()}
        />
      ) : displayed ? (
        <div className="space-y-3">
          {aiMutation.isError && (
            <div className="rounded-md border border-high/40 bg-high/10 p-2 text-[11px] text-high">
              {aiMutation.error instanceof ApiError
                ? aiMutation.error.detail
                : 'The AI narrative could not be produced.'}
            </div>
          )}
          <ResultView result={displayed} />
        </div>
      ) : (
        <EmptyState title="No explanation" />
      )}
    </Panel>
  )
}
