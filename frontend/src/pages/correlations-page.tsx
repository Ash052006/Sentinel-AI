import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { correlationsApi } from '../api/correlations'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows } from '../components/states'
import { CorrelationStatusBadge } from '../components/badges'
import { Badge } from '../components/ui/badge'
import { MonoId } from '../components/ui/mono-id'
import { ConfidenceBar } from '../components/ui/progress'
import { Select } from '../components/ui/input'
import { formatTimestamp } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'
import type { CorrelationStatus } from '../types/api'

export function CorrelationsPage() {
  const [limit, setLimit] = useState(100)
  const [status, setStatus] = useState<'all' | CorrelationStatus>('all')
  const [scope, setScope] = useState<'all' | 'multi'>('multi')

  const correlations = useQuery({
    queryKey: ['correlations', 'recent', limit],
    queryFn: () => correlationsApi.recent(limit),
  })

  const rows = useMemo(() => {
    let items = correlations.data ?? []
    if (status !== 'all') {
      items = items.filter((item) => item.status === status)
    }
    if (scope === 'multi') {
      items = items.filter((item) => item.members.length > 1)
    }
    return items
  }, [correlations.data, status, scope])

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Correlations"
        description="Persisted correlations grouping related telemetry and detections. Multi-incident correlations (>1 alerts) establish progression sequences necessary for attack forecasting and playbooks."
      >
        <Select
          aria-label="Filter by incident scope"
          value={scope}
          onChange={(event) => setScope(event.target.value as typeof scope)}
        >
          <option value="multi">Multi-Incident Only (&gt;1)</option>
          <option value="all">All (including standalone)</option>
        </Select>
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

      <Panel
        padded={false}
        title="Persisted correlations"
        subtitle="Grouped by the Step 10B engine on shared source event. Correlations with >1 members indicate multi-stage attack progressions."
      >
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
                <Th>Detections / Members</Th>
                <Th>Established at</Th>
                <Th>Detail & Actions</Th>
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
                  <Td>
                    {item.members.length > 1 ? (
                      <Badge tone="accent">{item.members.length} members (Multi-Stage)</Badge>
                    ) : (
                      <span className="font-mono text-xs text-ink-dim">1 (standalone)</span>
                    )}
                  </Td>
                  <Td className="text-xs text-ink-dim">{formatTimestamp(item.timestamp)}</Td>
                  <MonoCell>
                    <div className="flex items-center gap-2">
                      <MonoId id={item.correlation_id} />
                      <span className="text-ink-faint">·</span>
                      <Link
                        to={`/correlations/${item.correlation_id}`}
                        className="text-accent hover:underline font-medium"
                      >
                        Inspect
                      </Link>
                      <span className="text-ink-faint">·</span>
                      <Link
                        to={`/predictions/correlation/${item.correlation_id}`}
                        className="text-ink-dim hover:text-ink text-[11px]"
                      >
                        Predict
                      </Link>
                      <span className="text-ink-faint">·</span>
                      <Link
                        to={`/playbooks/correlation/${item.correlation_id}`}
                        className="text-ink-dim hover:text-ink text-[11px]"
                      >
                        Playbook
                      </Link>
                    </div>
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