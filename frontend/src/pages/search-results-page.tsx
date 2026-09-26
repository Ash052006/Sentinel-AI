import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { socApi } from '../api/soc'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { CorrelationStatusBadge, MemoryTypeBadge, RiskLevelBadge, SeverityBadge } from '../components/badges'
import { MonoId } from '../components/ui/mono-id'
import { ScoreBar } from '../components/ui/progress'
import { formatTimestamp } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'

export function SearchResultsPage() {
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''

  const result = useQuery({
    queryKey: ['soc', 'query', q],
    queryFn: () => socApi.query(q),
    enabled: q.length > 0,
  })

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="SOC search"
        description="Request triaged by the SOC-querier intent pipeline and answered against the read-only API surface."
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
            body="Try: recent detections · highest risk correlations · active incidents · critical event traffic · search event 8f9c…"
          />
        </Panel>
      ) : result.isLoading ? (
        <LoadingRows rows={6} />
      ) : result.isError ? (
        <ErrorState message={String(result.error)} onRetry={() => result.refetch()} />
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