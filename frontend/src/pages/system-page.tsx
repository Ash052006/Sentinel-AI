import { useQuery } from '@tanstack/react-query'
import { healthApi } from '../api/health'
import { PageHeader, Panel } from '../components/ui/card'
import { ErrorState, LoadingRows } from '../components/states'
import { Button } from '../components/ui/button'

export function SystemPage() {
  const db = useQuery({
    queryKey: ['health', 'database'],
    queryFn: healthApi.database,
    refetchInterval: 30_000,
  })
  const kafka = useQuery({
    queryKey: ['health', 'kafka'],
    queryFn: healthApi.kafka,
    refetchInterval: 30_000,
  })

  const isLoading = db.isLoading || kafka.isLoading

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="System health"
        description="Live dependency probes. Backend: FastAPI on :8000; Postgres + Kafka via docker-compose."
      >
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            void db.refetch()
            void kafka.refetch()
          }}
        >
          Refresh
        </Button>
      </PageHeader>

      {isLoading ? (
        <LoadingRows rows={4} />
      ) : db.isError || kafka.isError ? (
        <ErrorState message="One or both dependency probes failed to respond." />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Panel title="PostgreSQL" subtitle="GET /api/health/database" padded={false}>
            {db.data ? (
              <dl className="space-y-2 p-4 text-xs">
                <div className="flex justify-between gap-3">
                  <dt className="text-ink-faint">Status</dt>
                  <dd
                    data-testid="system-db"
                    className={
                      db.data.status === 'connected' ? 'font-mono text-low' : 'font-mono text-critical'
                    }
                  >
                    {db.data.status}
                  </dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-ink-faint">Database</dt>
                  <dd className="font-mono text-ink">{db.data.database ?? '—'}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-ink-faint">User</dt>
                  <dd className="font-mono text-ink">{db.data.user ?? '—'}</dd>
                </div>
              </dl>
            ) : null}
          </Panel>

          <Panel title="Kafka" subtitle="GET /api/health/kafka" padded={false}>
            {kafka.data ? (
              <dl className="space-y-2 p-4 text-xs">
                <div className="flex justify-between gap-3">
                  <dt className="text-ink-faint">Status</dt>
                  <dd
                    data-testid="system-kafka"
                    className={
                      kafka.data.status === 'healthy' ? 'font-mono text-low' : 'font-mono text-critical'
                    }
                  >
                    {kafka.data.status}
                  </dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-ink-faint">Broker</dt>
                  <dd className="font-mono text-ink">{kafka.data.kafka ?? '—'}</dd>
                </div>
              </dl>
            ) : null}
          </Panel>
        </div>
      )}
    </div>
  )
}