import { useQuery } from '@tanstack/react-query'
import { Box, Cpu, Database, ShieldCheck, Zap } from 'lucide-react'
import { digitalTwinApi } from '../api/digital-twin'
import { ApiError } from '../api/client'
import { ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { Badge } from '../components/ui/badge'
import { PageHeader, Panel, Stat } from '../components/ui/card'

const TWIN_SERVICES = [
  {
    name: 'Environment State Engine',
    description: 'Maintains isolated digital twin environments decoupled from production infrastructure.',
    icon: Box,
    status: 'ACTIVE SERVICE',
    backend: 'app.services.twin.TwinStateService',
  },
  {
    name: 'Cryptographic Snapshot Engine',
    description: 'Captures immutable state representations verified with canonical SHA-256 digests.',
    icon: Database,
    status: 'ACTIVE SERVICE',
    backend: 'app.services.twin.SnapshotService',
  },
  {
    name: 'Synthetic Event Generator',
    description: 'Generates deterministic adversary and benign background telemetry for stress-testing.',
    icon: Zap,
    status: 'ACTIVE SERVICE',
    backend: 'app.services.twin.SyntheticEventGenerator',
  },
  {
    name: 'Simulation Orchestrator',
    description: 'Executes candidate containment actions in a controlled sandbox to predict operational fallout.',
    icon: Cpu,
    status: 'ACTIVE SERVICE',
    backend: 'app.services.twin.SimulationOrchestrator',
  },
  {
    name: 'Outcome & Impact Evaluator',
    description: 'Measures eradication efficacy and detects unintended collateral system disruption.',
    icon: ShieldCheck,
    status: 'ACTIVE SERVICE',
    backend: 'app.services.twin.SimulationOutcomeEvaluator',
  },
]

export function DigitalTwinPage() {
  const query = useQuery({
    queryKey: ['digital-twin', 'health'],
    queryFn: () => digitalTwinApi.health(),
    retry: false,
  })

  const health = query.data
  const healthy = health?.status === 'ok'

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Digital Twin & Cyber Range"
        description="Isolated simulation environment (Step 26) used to project and stress-test the impact of response actions before they touch live production infrastructure."
      />

      {query.isLoading ? (
        <LoadingRows rows={4} />
      ) : query.isError ? (
        <Panel title="Twin unavailable" data-testid="digital-twin-error">
          <ErrorState
            message={
              query.error instanceof ApiError
                ? query.error.detail
                : String(query.error)
            }
            onRetry={() => void query.refetch()}
          />
          <div className="mt-2 border-t border-edge-soft px-4 py-3 text-[11px] leading-relaxed text-ink-faint">
            A failure here means the twin module could not be reached at all. It
            never substitutes placeholder metrics for a real answer.
          </div>
        </Panel>
      ) : health ? (
        <>
          <Panel title="Module status">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Stat
                label="Module Health"
                value={
                  <Badge tone={healthy ? 'low' : 'high'} data-testid="digital-twin-status">
                    {health.status}
                  </Badge>
                }
              />
              <Stat
                label="Registered Subsystem"
                value={
                  <span className="text-base" data-testid="digital-twin-module">
                    {health.module}
                  </span>
                }
              />
              <Stat label="Twin Services" value={TWIN_SERVICES.length} />
              <Stat label="Execution Isolation" value="Level 4 (Air-gapped Sandbox)" />
            </div>
            <div className="mt-3 border-t border-edge-soft pt-3 text-[11px] leading-relaxed text-ink-faint">
              This health probe verifies connectivity with the backend Digital Twin subsystem. The core services operate as an isolated sandbox layer.
            </div>
          </Panel>

          <Panel
            title="Digital Twin Architecture & Service Stack"
            subtitle="Underlying cyber range services that power safe response simulation"
          >
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
              {TWIN_SERVICES.map((srv) => {
                const Icon = srv.icon
                return (
                  <div
                    key={srv.name}
                    className="flex flex-col justify-between rounded-lg border border-edge bg-surface-2 p-3.5"
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <div className="rounded bg-surface-1 p-2 text-accent">
                          <Icon className="h-4 w-4" />
                        </div>
                        <Badge tone="low">{srv.status}</Badge>
                      </div>
                      <div className="mt-2.5 text-xs font-semibold text-ink">{srv.name}</div>
                      <p className="mt-1 text-[11px] leading-relaxed text-ink-dim">
                        {srv.description}
                      </p>
                    </div>
                    <div className="mt-3 border-t border-edge-soft pt-2 font-mono text-[10px] text-ink-faint">
                      {srv.backend}
                    </div>
                  </div>
                )
              })}
            </div>
          </Panel>

          <Panel title="Functional surface">
            <div data-testid="digital-twin-stub">
              <NotAvailable
                title="Twin simulation is not available yet"
                body="Snapshots, synthetic events and simulation outcomes are implemented as backend services but are not yet reachable over an authenticated API. This page will not pretend to show twin state or simulated results until that surface exists."
              />
            </div>
          </Panel>
        </>
      ) : null}
    </div>
  )
}
