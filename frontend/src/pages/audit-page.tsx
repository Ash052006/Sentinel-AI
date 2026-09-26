import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { auditApi } from '../api/audit'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows } from '../components/states'
import { MonoId } from '../components/ui/mono-id'
import { Pagination } from '../components/ui/pagination'
import { formatTimestamp, shorten } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'

export function AuditPage() {
  const [limit, setLimit] = useState(50)
  const [page, setPage] = useState(1)

  const skip = (page - 1) * limit

  const logs = useQuery({
    queryKey: ['audit', 'logs', skip, limit],
    queryFn: () => auditApi.logs(skip, limit),
  })

  const data = logs.data

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Audit log"
        description="Authorization and auth lifecycle actions, recorded by the audit service. Readable by the admin role only."
      />

      <Panel padded={false}>
        {logs.isLoading ? (
          <LoadingRows rows={10} />
        ) : logs.isError ? (
          <ErrorState message={String(logs.error)} onRetry={() => logs.refetch()} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState title="No audit entries" />
        ) : (
          <>
            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Time</Th>
                  <Th>Action</Th>
                  <Th>Resource</Th>
                  <Th>User</Th>
                  <Th>IP</Th>
                  <Th>Details</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {data.items.map((item) => (
                  <TRow key={item.id}>
                    <Td className="text-xs text-ink-dim">{formatTimestamp(item.created_at)}</Td>
                    <Td data-mono className="text-[11px] text-ink">{item.action}</Td>
                    <Td className="text-[11px] text-ink-dim">{item.resource ?? '—'}</Td>
                    <MonoCell>
                      <MonoId id={item.user_id} copy={false} />
                    </MonoCell>
                    <Td data-mono className="text-[11px] text-ink-dim">
                      {item.ip_address ?? '—'}
                    </Td>
                    <Td className="text-xs text-ink-dim">{shorten(item.details, 80)}</Td>
                  </TRow>
                ))}
              </tbody>
            </Table>
            <Pagination
              page={page}
              pageSize={limit}
              total={data.total}
              onPage={setPage}
              onPageSize={(size) => {
                setLimit(size)
                setPage(1)
              }}
            />
          </>
        )}
      </Panel>
    </div>
  )
}