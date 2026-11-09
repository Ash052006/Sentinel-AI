import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { CheckCircle2, ChevronRight, Search, Sparkles } from 'lucide-react'
import { socApi } from '../api/soc'
import { ApiError } from '../api/client'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { CorrelationStatusBadge, MemoryTypeBadge, RiskLevelBadge, SeverityBadge } from '../components/badges'
import { MonoId } from '../components/ui/mono-id'
import { ScoreBar } from '../components/ui/progress'
import { formatTimestamp } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'
import { synthesizeSocResponse } from '../lib/soc-assistant'

const SEARCH_ERROR_FALLBACK = 'The SOC query did not return an answer. Try again.'

function searchErrorMessage(error: unknown): string {
  if (typeof error === 'string' && error.trim().length > 0) return error.trim()
  if (error && typeof error === 'object') {
    if (error instanceof ApiError) return error.detail
    const detail = (error as { detail?: unknown }).detail
    if (typeof detail === 'string' && detail.trim().length > 0) {
      return detail.trim()
    }
    if (error instanceof Error && error.message.trim().length > 0) {
      return error.message.trim()
    }
  }
  return SEARCH_ERROR_FALLBACK
}

export function SearchResultsPage() {
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''

  const result = useQuery({
    queryKey: ['soc', 'query', q],
    queryFn: () => socApi.query(q),
    enabled: q.length > 0,
  })

  const analysis = result.data ? synthesizeSocResponse(q, result.data) : null

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="SOC search"
        description="Autonomous SOC AI Assistant delivering evidence-grounded threat synthesis, triage recommendations, and live telemetry correlation."
      />

      <form
        className="flex gap-2"
        onSubmit={(event) => {
          event.preventDefault()
          const form = new FormData(event.currentTarget)
          const next = String(form.get('q') ?? '').trim()
          if (next.length > 0) setParams({ q: next }, { replace: true })
        }}
      >
        <input
          name="q"
          key={q}
          defaultValue={q}
          data-testid="search-input"
          className="flex h-9 w-full max-w-md rounded-md border border-edge bg-surface-0 px-3 text-xs text-ink outline-none transition focus:border-accent"
          placeholder={q.length > 0 ? q : 'Ask SOC — e.g. "show recent detections"'}
        />
        <button
          type="submit"
          className="inline-flex h-9 items-center gap-1.5 rounded-md border border-edge bg-surface-1 px-3 text-xs text-ink transition hover:border-accent hover:text-accent"
        >
          <Search className="h-3.5 w-3.5" />
          Ask
        </button>
      </form>

      {q.length === 0 ? (
        <Panel>
          <EmptyState
            title="Ask the SOC querier"
            body="Try: recent detections · recent correlations · critical risk assessments · correlations for event 8f9c…"
          />
        </Panel>
      ) : result.isLoading ? (
        <LoadingRows rows={6} />
      ) : result.isError ? (
        <ErrorState message={searchErrorMessage(result.error)} onRetry={() => result.refetch()} />
      ) : !result.data ? (
        <EmptyState title="No answer" body="The querier returned no response." />
      ) : result.data.found === false ? (
        <Panel>
          <NotAvailable
            body={`${result.data.note ?? 'The requester chose not to prepare this result.'} The SOC querier is read-only and will never fabricate data.`}
          />
        </Panel>
      ) : (
        <div className="space-y-4">
          {/* SOC Copilot AI Briefing & Recommendations */}
          {analysis && (
            <Panel
              title="SOC Assistant Triage Briefing"
              subtitle="Autonomous synthesis grounded in verified live telemetry"
            >
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-edge-soft pb-3">
                  <div className="flex items-center gap-2">
                    <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-accent/20 text-accent">
                      <Sparkles className="h-4 w-4" />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-ink">{analysis.verdict}</h3>
                      <p className="text-xs text-accent font-mono">{analysis.headline}</p>
                    </div>
                  </div>
                  {analysis.tactics.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {analysis.tactics.map((tactic) => (
                        <span
                          key={tactic}
                          className="rounded-full border border-edge bg-surface-2 px-2.5 py-0.5 text-[10px] font-mono text-ink-dim uppercase"
                        >
                          {tactic}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <p className="text-xs text-ink-dim leading-relaxed bg-surface-2/40 p-3 rounded-lg border border-edge-soft">
                  {analysis.summary}
                </p>

                {analysis.recommendations.length > 0 && (
                  <div className="space-y-2">
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-ink-faint">
                      Recommended Tactical Actions
                    </span>
                    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                      {analysis.recommendations.map((rec, idx) => (
                        <div
                          key={idx}
                          className="flex items-start gap-2 rounded-lg border border-edge-soft bg-surface-2/50 p-2.5 text-xs text-ink-dim"
                        >
                          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                          <span>{rec}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {analysis.followUps.length > 0 && (
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-faint">
                      Follow-up prompts:
                    </span>
                    {analysis.followUps.map((prompt) => (
                      <button
                        key={prompt}
                        type="button"
                        onClick={() => setParams({ q: prompt }, { replace: true })}
                        className="inline-flex items-center gap-1 rounded-full border border-edge bg-surface-2 px-2.5 py-1 text-[11px] text-ink-dim hover:border-accent hover:text-accent transition"
                      >
                        <span>{prompt}</span>
                        <ChevronRight className="h-3 w-3" />
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </Panel>
          )}

          <Panel title="Query metadata" subtitle="Intent pipeline output">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs md:grid-cols-4">
              <div>
                <dt className="text-ink-faint">Resource</dt>
                <dd className="font-mono text-ink">{result.data.metadata.resource}</dd>
              </div>
              <div>
                <dt className="text-ink-faint">Operation</dt>
                <dd className="font-mono text-ink">{result.data.metadata.operation}</dd>
              </div>
              <div>
                <dt className="text-ink-faint">Mode</dt>
                <dd className="font-mono text-ink">{result.data.metadata.mode}</dd>
              </div>
              <div>
                <dt className="text-ink-faint">Count</dt>
                <dd className="font-mono text-ink">
                  {result.data.count} of {result.data.total}
                </dd>
              </div>
            </dl>
          </Panel>

          <Panel title={`Results · ${result.data.metadata.resource}`} padded={false}>
            {result.data.items.length === 0 ? (
              <EmptyState
                title="No matches"
                body={`The backend searched ${result.data.total} records in the ${result.data.metadata.resource} collection and found none.`}
              />
            ) : result.data.metadata.resource === 'detections' ? (
              <Table>
                <thead>
                  <tr className="border-b border-edge">
                    <Th>Severity</Th>
                    <Th>Rule</Th>
                    <Th>Confidence</Th>
                    <Th>Provenance</Th>
                    <Th>Detected at</Th>
                    <Th>Id</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge-soft">
                  {result.data.items.map((row) => (
                    <TRow key={String(row.id)}>
                      <Td>
                        <SeverityBadge severity={String(row.severity) as never} />
                      </Td>
                      <Td data-mono className="text-[11px] text-ink">{String(row.rule_id)}</Td>
                      <Td>
                        <ScoreBar value={Number(row.confidence)} />
                      </Td>
                      <Td data-mono className="text-[11px] text-ink-dim">
                        {String(row.provenance)}
                      </Td>
                      <Td className="text-xs text-ink-dim">
                        {formatTimestamp(String(row.detected_at))}
                      </Td>
                      <MonoCell>
                        <MonoId id={String(row.detection_id)} />
                      </MonoCell>
                    </TRow>
                  ))}
                </tbody>
              </Table>
            ) : result.data.metadata.resource === 'correlations' ? (
              <Table>
                <thead>
                  <tr className="border-b border-edge">
                    <Th>Status</Th>
                    <Th>Members</Th>
                    <Th>Confidence</Th>
                    <Th>Established</Th>
                    <Th>Open</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge-soft">
                  {result.data.items.map((row) => (
                    <TRow key={String(row.id)}>
                      <Td>
                        <CorrelationStatusBadge status={String(row.status) as never} />
                      </Td>
                      <Td>{Number(row.members_count ?? (Array.isArray(row.members) ? row.members.length : 0))}</Td>
                      <Td>
                        <ScoreBar value={Number(row.confidence)} />
                      </Td>
                      <Td className="text-xs text-ink-dim">
                        {formatTimestamp(String(row.timestamp))}
                      </Td>
                      <MonoCell>
                        <Link
                          to={`/incidents/${String(row.correlation_id)}`}
                          className="text-accent hover:underline"
                        >
                          open
                        </Link>
                      </MonoCell>
                    </TRow>
                  ))}
                </tbody>
              </Table>
            ) : result.data.metadata.resource === 'risk_assessments' ? (
              <Table>
                <thead>
                  <tr className="border-b border-edge">
                    <Th>Level</Th>
                    <Th>Score</Th>
                    <Th>Confidence</Th>
                    <Th>Assessed</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge-soft">
                  {result.data.items.map((row) => (
                    <TRow key={String(row.id)}>
                      <Td>
                        <RiskLevelBadge level={String(row.level) as never} />
                      </Td>
                      <Td>
                        <ScoreBar value={Number(row.score)} />
                      </Td>
                      <Td>
                        <ScoreBar value={Number(row.confidence)} />
                      </Td>
                      <Td className="text-xs text-ink-dim">
                        {formatTimestamp(String(row.timestamp))}
                      </Td>
                    </TRow>
                  ))}
                </tbody>
              </Table>
            ) : (
              <Table>
                <thead>
                  <tr className="border-b border-edge">
                    <Th>Type</Th>
                    <Th>Title</Th>
                    <Th>Provenance</Th>
                    <Th>Recorded</Th>
                    <Th>Id</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge-soft">
                  {result.data.items.map((row) => (
                    <TRow key={String(row.id)}>
                      <Td>
                        <MemoryTypeBadge type={String(row.memory_type) as never} />
                      </Td>
                      <Td className="text-xs text-ink">{String(row.title)}</Td>
                      <Td data-mono className="text-[11px] text-ink-dim">
                        {String(row.provenance)}
                      </Td>
                      <Td className="text-xs text-ink-dim">
                        {formatTimestamp(String(row.created_at))}
                      </Td>
                      <MonoCell>
                        <MonoId id={String(row.memory_id)} />
                      </MonoCell>
                    </TRow>
                  ))}
                </tbody>
              </Table>
            )}
          </Panel>
        </div>
      )}
    </div>
  )
}