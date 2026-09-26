import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { risksApi } from '../api/risks'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows } from '../components/states'
import { RiskLevelBadge } from '../components/badges'
import { MonoId } from '../components/ui/mono-id'
import { ConfidenceBar, ScoreBar } from '../components/ui/progress'
import { Select } from '../components/ui/input'
import { formatTimestamp } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'
import type { RiskLevel } from '../types/api'

export function RiskPage() {
  const [limit, setLimit] = useState(100)
  const [level, setLevel] = useState<'all' | RiskLevel>('all')

  const risks = useQuery({
    queryKey: ['risks', 'recent', limit],
    queryFn: () => risksApi.recent(limit),
  })

  const rows = useMemo(() => {
    const items = risks.data ?? []
    if (level === 'all') return items
    return items.filter((item) => item.level === level)
  }, [risks.data, level])

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Risk"
        description="Persisted risk assessments produced by the Step 11B engine over correlations."
      >
        <Select
          aria-label="Filter by risk level"
          value={level}
          onChange={(event) => setLevel(event.target.value as typeof level)}
        >
          <option value="all">All levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </Select>
        <Select
          aria-label="Feed size"
          value={String(limit)}
          onChange={(event) => setLimit(Number(event.target.value))}
        >
          {[25, 50, 100, 200].map((size) => (
            <option key={size} value={size}>
              {size} shown
            </option>
          ))}
        </Select>
      </PageHeader>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel padded={false} className="xl:col-span-2">
          {risks.isLoading ? (
            <LoadingRows rows={8} />
          ) : risks.isError ? (
            <ErrorState message={String(risks.error)} onRetry={() => risks.refetch()} />
          ) : rows.length === 0 ? (
            <EmptyState
              title="No risk assessments"
              body="No persisted assessments matched the selected filters within the bounded feed."
            />
          ) : (
            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Level</Th>
                  <Th>Score</Th>
                  <Th>Confidence</Th>
                  <Th>Correlation</Th>
                  <Th>Assessed at</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {rows.map((item) => (
                  <TRow key={item.id}>
                    <Td>
                      <RiskLevelBadge level={item.level} />
                    </Td>
                    <Td>
                      <ScoreBar value={item.score} />
                    </Td>
                    <Td>
                      <ConfidenceBar value={item.confidence} />
                    </Td>
                    <MonoCell>
                      <Link
                        to={`/incidents/${item.correlation_id}`}
                        className="text-accent hover:underline"
                      >
                        inspect
                      </Link>
                      <span className="mx-1 text-ink-faint">·</span>
                      <MonoId id={item.correlation_id} />
                    </MonoCell>
                    <Td className="text-xs text-ink-dim">
                      {formatTimestamp(item.timestamp)}
                    </Td>
                  </TRow>
                ))}
              </tbody>
            </Table>
          )}
        </Panel>

        <div className="space-y-4">
          <Panel title="How risk is scored" subtitle="Step 11 engine semantics">
            <p className="text-[11px] leading-relaxed text-ink-dim">
              A persistent assessment binds a normalized score (0.0–1.0) and a
              controlled level (low / medium / high / critical) to one
              correlation. Confidence is independent of score and level.
              Factors and evidence are preserved verbatim from the engine.
            </p>
          </Panel>
        </div>
      </div>
    </div>
  )
}