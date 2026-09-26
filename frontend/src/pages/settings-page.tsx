import { useQuery } from '@tanstack/react-query'
import { authApi } from '../api/auth'
import { PageHeader, Panel } from '../components/ui/card'
import { LoadingRows } from '../components/states'
import { useAuthStore } from '../store/auth'

export function SettingsPage() {
  const user = useAuthStore((state) => state.user)
  const me = useQuery({
    queryKey: ['users', 'me'],
    queryFn: authApi.me,
    enabled: user === null,
  })

  const current = user ?? me.data

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Settings"
        description="Session and application information. V1 exposes no mutating settings endpoints, so everything here is read-only."
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="Signed-in user" subtitle="From GET /api/users/me">
          {me.isLoading && !user ? (
            <LoadingRows rows={2} />
          ) : (
            <dl className="space-y-2 text-xs">
              <div className="flex justify-between gap-3">
                <dt className="text-ink-faint">Email</dt>
                <dd data-testid="settings-email" className="font-mono text-ink">
                  {current?.email ?? '—'}
                </dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-ink-faint">Role</dt>
                <dd className="font-mono uppercase text-accent">{current?.role ?? '—'}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-ink-faint">Active</dt>
                <dd data-mono className="text-ink">
                  {current?.is_active ? 'yes' : 'no'}
                </dd>
              </div>
            </dl>
          )}
        </Panel>

        <Panel title="Application" subtitle="Runtime facts about the console">
          <dl className="space-y-2 text-xs">
            <div className="flex justify-between gap-3">
              <dt className="text-ink-faint">Application</dt>
              <dd className="text-ink">SentinelAI · SOC Console (V1)</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-faint">Backend version</dt>
              <dd className="font-mono text-ink">0.1.0</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-faint">API base</dt>
              <dd className="font-mono text-ink">/api (proxied to :8000)</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-faint">Authentication</dt>
              <dd className="font-mono text-ink">JWT bearer</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-faint">Data policy</dt>
              <dd className="text-ink-dim">Read-only · no falsified telemetry</dd>
            </div>
          </dl>
        </Panel>
      </div>
    </div>
  )
}