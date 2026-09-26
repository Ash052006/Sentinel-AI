import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { correlationsApi } from '../api/correlations'
import { risksApi } from '../api/risks'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows } from '../components/states'
import { RiskLevelBadge, CorrelationStatusBadge } from '../components/badges'
import { MonoId } from '../components/ui/mono-id'
import { ScoreBar, ConfidenceBar } from '../components/ui/progress'
import { Select } from '../components/ui/input'
import { formatTimestamp } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'
import type { CorrelationResult, RiskAssessment } from '../types/api'

const FEED = 200

const levelRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }

interface IncidentRow {
  risk: RiskAssessment
  correlation: CorrelationResult | null
}

export function IncidentsPage() {
  const [level, setLevel] = useState<'all' | 'low' | 'medium' | 'high' | 'critical'>('all')

  const correlations = useQuery({
    queryKey: ['correlations', 'recent', FEED],
    queryFn: () => correlationsApi.recent(FEED),
  })
  const risks = useQuery({
    queryKey: ['risks', 'recent', FEED],
    queryFn: () => risksApi.recent(FEED),
  })

  const rows = useMemo<IncidentRow[]>(() => {
    const byId = new Map((correlations.data ?? []).map((c) => [c.correlation_id, c]))
    const joined = (risks.data ?? []).map((risk) => ({
      risk,
      correlation: byId.get(risk.correlation_id) ?? null,
    }))
    return joined.sort((a, b) => {
      const rankDiff = levelRank[b.risk.level] - levelRank[a.risk.level]
      if (rankDiff !== 0) return rankDiff
      return b.risk.timestamp.localeCompare(a.risk.timestamp)
    })
  }, [correlations.data, risks.data])

  const filtered = level === 'all' ? rows : rows.filter((row) => row.risk.level === level)

  const isLoading = correlations.isLoading || risks.isLoading
  const hasError = correlations.isError || risks.isError

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Incidents"
        description="V1 has no separate incident entity or API: an incident is represented by a correlation together with its risk assessment. Rows are the joined risk assessments (bounded recent feed, limit 200)."
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
      </PageHeader>

      <Panel padded={false}>
        {isLoading ? (
          <LoadingRows rows={8} />
        ) : hasError ? (
          <ErrorState
            message="Incident data is unavailable."
            onRetry={() => {
              void correlations.refetch()
              void risks.refetch()
            }}
          />
        ) : filtered.length === 0 ? (
          <EmptyState
            title="No incidents"
            body="No risk assessments exist in the bounded recent feed for the selected filter."
          />
        ) : (
          <Table>
            <thead>
              <tr className="border-b border-edge">
                <Th>Level</Th>
                <Th>Correlation</Th>
                <Th>Status</Th>
                <Th>Score</Th>
                <Th>Confidence</Th>
                <Th>Members</Th>
                <Th>Assessed at</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge-soft">
              {filtered.map((row) => (
                <TRow key={row.risk.id}>
                  <Td>
                    <RiskLevelBadge level={row.risk.level} />
                  </Td>
                  <MonoCell>
                    <Link
                      to={`/incidents/${row.risk.correlation_id}`}
                      className="text-accent hover:underline"
                    >
                      inspect
                    </Link>
                    <span className="mx-1 text-ink-faint">·</span>
                    <MonoId id={row.risk.correlation_id} />
                  </MonoCell>
                  <Td>
                    {row.correlation ? (
                      <CorrelationStatusBadge status={row.correlation.status} />
                    ) : (
                      <span className="text-[11px] text-ink-faint">—</span>
                    )}
                  </Td>
                  <Td>
                    <ScoreBar value={row.risk.score} />
                  </Td>
                  <Td>
                    <ConfidenceBar value={row.risk.confidence} />
                  </Td>
                  <Td>{row.correlation?.members.length ?? '—'}</Td>
                  <Td className="text-xs text-ink-dim">
                    {formatTimestamp(row.risk.timestamp)}
                  </Td>
                </TRow>
              ))}
            </tbody>
          </Table>
        )}
      </Panel>
    </div>
  )
}