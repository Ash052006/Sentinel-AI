import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { correlationsApi } from '../api/correlations'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows } from '../components/states'
import { CorrelationStatusBadge } from '../components/badges'
import { MonoId } from '../components/ui/mono-id'
import { ConfidenceBar } from '../components/ui/progress'
import { Select } from '../components/ui/input'
import { formatTimestamp } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'
import type { CorrelationStatus } from '../types/api'

export function CorrelationsPage() {
  const [limit, setLimit] = useState(100)
  const [status, setStatus] = useState<'all' | CorrelationStatus>('all')

  const correlations = useQuery({
    queryKey: ['correlations', 'recent', limit],
    queryFn: () => correlationsApi.recent(limit),
  })

  const rows = useMemo(() => {
    const items = correlations.data ?? []
    if (status === 'all') return items
    return items.filter((item) => item.status === status)
  }, [correlations.data, status])

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Correlations"
        description="Persisted correlations that group related detections and events (bounded recent feed)."
      >
        <Select
          aria-label="Filter by status"
          value={status}
          onChange={(event) => setStatus(event.target.value as typeof status)}
        >
          <option value="all">All statuses</option>
          <option value="candidate">Candidate</option>
          <option value="active">Active</option>
          <option value="closed">Closed</option>
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

      <Panel padded={false}>
        {correlations.isLoading ? (
          <LoadingRows rows={8} />
        ) : correlations.isError ? (
          <ErrorState message={String(correlations.error)} onRetry={() => correlations.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            title="No correlations"
            body="No correlations matched the selected filter within the bounded feed."
          />
        ) : (
          <Table>
            <thead>
              <tr className="border-b border-edge">
                <Th>Status</Th>
                <Th>Confidence</Th>
                <Th>Members</Th>
                <Th>Established at</Th>
                <Th>Detail</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge-soft">
              {rows.map((item) => (
                <TRow key={item.id}>
                  <Td>
                    <CorrelationStatusBadge status={item.status} />
                  </Td>
                  <Td>
                    <ConfidenceBar value={item.confidence} />
                  </Td>
                  <Td>{item.members.length}</Td>
                  <Td className="text-xs text-ink-dim">{formatTimestamp(item.timestamp)}</Td>
                  <MonoCell>
                    <Link
                      to={`/correlations/${item.correlation_id}`}
                      className="text-accent hover:underline"
                    >
                      open
                    </Link>
                    <span className="mx-1 text-ink-faint">·</span>
                    <MonoId id={item.correlation_id} />
                  </MonoCell>
                </TRow>
              ))}
            </tbody>
          </Table>
        )}
      </Panel>
    </div>
  )
}