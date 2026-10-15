import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, FlaskConical, Play } from 'lucide-react'
import { ApiError } from '../api/client'
import { soarApi } from '../api/soar'
import { approvalsApi } from '../api/approvals'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { MonoId } from '../components/ui/mono-id'
import { Select } from '../components/ui/input'
import { Td, Th, TRow, Table } from '../components/ui/table'
import { formatTimestamp } from '../lib/formats'
import type {
  ApprovalRecord,
  SoarDryRunResult,
  SoarExecutionRecord,
  SoarExecutionRequest,
  SoarExecutionStatus,
  SoarPlaybookRecord,
  SoarStepExecutionRecord,
  SoarStepStatus,
} from '../types/api'

const PAGE_SIZE = 50

function executionLabel(status: SoarExecutionStatus): { label: string; tone: 'low' | 'muted' | 'critical' | 'accent' | 'medium' } {
  switch (status) {
    case 'succeeded':
      return { label: 'EXECUTED', tone: 'low' }
    case 'failed':
      return { label: 'FAILED', tone: 'critical' }
    case 'rejected':
      return { label: 'REJECTED', tone: 'critical' }
    case 'pending':
      return { label: 'PENDING APPROVAL', tone: 'accent' }
    case 'running':
      return { label: 'RUNNING', tone: 'accent' }
    case 'partial':
      return { label: 'PARTIAL', tone: 'medium' }
    case 'cancelled':
      return { label: 'CANCELLED', tone: 'muted' }
  }
}

function stepTone(status: SoarStepStatus): 'low' | 'muted' | 'critical' | 'accent' {
  switch (status) {
    case 'succeeded':
      return 'low'
    case 'failed':
    case 'timed_out':
      return 'critical'
    case 'pending':
    case 'running':
      return 'accent'
    case 'skipped':
    case 'cancelled':
      return 'muted'
  }
}

export function SoarPage() {
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [selectedPlaybook, setSelectedPlaybook] = useState<string | null>(null)
  const [selectedExecution, setSelectedExecution] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const playbooks = useQuery({
    queryKey: ['soar', 'playbooks', page, PAGE_SIZE],
    queryFn: () => soarApi.playbooks(page, PAGE_SIZE),
  })

  const executions = useQuery({
    queryKey: ['soar', 'executions', page, PAGE_SIZE],
    queryFn: () => soarApi.executions(page, PAGE_SIZE),
  })

  const approvals = useQuery({
    queryKey: ['approvals', 'list', 'approved', 200],
    queryFn: () => approvalsApi.list(1, 200, 'approved'),
  })

  const playbookDetail = useQuery({
    queryKey: ['soar', 'playbook', selectedPlaybook],
    queryFn: () => soarApi.playbook(selectedPlaybook as string),
    enabled: selectedPlaybook !== null,
  })

  const executionDetail = useQuery({
    queryKey: ['soar', 'execution', selectedExecution],
    queryFn: () => soarApi.execution(selectedExecution as string),
    enabled: selectedExecution !== null,
  })

  const mutation = useMutation({
    mutationFn: (fn: () => Promise<unknown>) => fn(),
    onSuccess: () => {
      setNotice('Sandbox SOAR action completed in the mock environment.')
      void queryClient.invalidateQueries({ queryKey: ['soar'] })
    },
    onError: (error: unknown) => {
      // Surface the sanitized server detail rather than a generic rejection:
      // SOAR mutations require the admin role, so a 403 here is a
      // permissions fact the reviewer needs to see, not a playbook fault.
      const detail =
        error instanceof ApiError ? error.detail : String(error)
      setNotice(`SOAR refused the run: ${detail}`)
    },
  })

  const runSoar = (fn: () => Promise<SoarExecutionRecord | SoarDryRunResult>): void =>
    mutation.mutate(fn)

  const playbookRows = useMemo(() => playbooks.data?.items ?? [], [playbooks.data])
  const executionRows = useMemo(() => executions.data?.items ?? [], [executions.data])
  const approvalRows = useMemo(() => approvals.data?.items ?? [], [approvals.data])

  const selected = playbookDetail.data
  const execSelected = executionDetail.data
  const selectedLabel = selected ? `${selected.name} · v${selected.version}` : 'Select a playbook to inspect its steps'

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="SOAR Orchestration"
        description="V2.18 governed automation over code-registered playbooks and sandbox/mock providers — an ALLOWED decision or a verifiable human approval grant is required before a single step runs."
      />

      {notice && <div className="rounded border border-low/40 bg-low/10 px-3 py-2 text-xs text-ink" data-testid="soar-notice">{notice}</div>}

      <div className="rounded border border-accent/30 bg-accent/5 px-3 py-2 text-[11px] leading-relaxed text-ink-dim" data-testid="soar-sandbox-disclaimer">
        <span className="font-medium text-ink">Sandbox / mock environment.</span> V2.18 providers are in-memory
        simulations. Automation never touches real infrastructure, and dry-runs execute nothing and persist nothing.
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Registered playbooks" value={playbooks.data?.total ?? 0} />
        <Stat label="Executions" value={executions.data?.total ?? 0} />
        <Stat
          label="Rejected / failed"
          value={executionRows.filter((r) => r.status === 'rejected' || r.status === 'failed').length}
          tone="text-critical"
        />
        <Stat
          label="Pending approval"
          value={executionRows.filter((r) => r.status === 'pending').length}
          tone="text-accent"
        />
      </div>

      <Panel
        title="Run under a real approval grant"
        subtitle="Executes with the verbatim policy decision persisted on an APPROVED approval request, plus that request's approval_id, so the backend gate verifies a durable grant rather than a client-asserted outcome."
        data-testid="soar-demo-panel"
      >
        <AuthorisedRun
          playbooks={playbookRows}
          approvals={approvalRows}
          busy={mutation.isPending}
          onDryRun={(body) => runSoar(() => soarApi.dryRun(body))}
          onExecute={(body) => runSoar(() => soarApi.execute(body))}
        />
      </Panel>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel
          title="Registered playbooks"
          subtitle={`${playbookRows.length} of ${playbooks.data?.total ?? 0} code-registered playbooks · deterministic seed order`}
          padded={false}
          className="xl:col-span-2"
        >
          {playbooks.isLoading ? (
            <LoadingRows rows={10} />
          ) : playbooks.isError ? (
            <ErrorState message={String(playbooks.error)} onRetry={() => void playbooks.refetch()} />
          ) : playbookRows.length === 0 ? (
            <EmptyState title="No playbooks registered" body="The fixed seed playbook set is synced on first access." />
          ) : (
            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Playbook</Th>
                  <Th>Primary action</Th>
                  <Th>Failure policy</Th>
                  <Th>Steps</Th>
                  <Th>Version</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {playbookRows.map((record) => (
                  <TRow
                    key={record.playbook_id}
                    onClick={() => setSelectedPlaybook(record.playbook_id)}
                    className="cursor-pointer"
                    data-testid="soar-playbook-row"
                  >
                    <Td className="max-w-[260px]">
                      <div className="truncate text-xs font-medium text-ink" title={record.name}>
                        {record.name}
                      </div>
                      <MonoId id={record.playbook_id} />
                    </Td>
                    <Td>
                      <Badge tone="accent">{record.primary_action}</Badge>
                    </Td>
                    <Td>
                      <Badge tone="muted">{record.failure_policy}</Badge>
                    </Td>
                    <Td className="font-mono text-[11px] text-ink">{record.step_count}</Td>
                    <Td className="font-mono text-[11px] text-ink-dim">v{record.version}</Td>
                  </TRow>
                ))}
              </tbody>
            </Table>
          )}
        </Panel>

        <Panel title="Playbook definition" subtitle={selectedLabel}>
          {playbookDetail.isLoading ? (
            <LoadingRows rows={8} />
          ) : playbookDetail.isError ? (
            <ErrorState message={String(playbookDetail.error)} />
          ) : selected ? (
            <PlaybookDetail detail={selected} />
          ) : (
            <NotAvailable
              title="No playbook selected"
              body="Select a playbook from the table to inspect its declarative steps, provider adapters and failure policy."
            />
          )}
        </Panel>
      </div>

      <Panel
        title="Execution history"
        subtitle="Persisted governed runs with the full step trace — explicit SIMULATED / EXECUTED / FAILED / REJECTED / PENDING APPROVAL labels"
        padded={false}
        data-testid="soar-executions-panel"
      >
        {executions.isLoading ? (
          <LoadingRows rows={8} />
        ) : executions.isError ? (
          <ErrorState message={String(executions.error)} onRetry={() => void executions.refetch()} />
        ) : executionRows.length === 0 ? (
          <EmptyState title="No executions yet" body="Run a sandbox demo above or through the governed decision engine to see executions." />
        ) : (
          <>
            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Status</Th>
                  <Th>Playbook</Th>
                  <Th>Target</Th>
                  <Th>Steps</Th>
                  <Th>Run by</Th>
                  <Th>Created</Th>
                  <Th />
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {executionRows.map((record) => {
                  const label = executionLabel(record.status)
                  const cancelable = record.status === 'pending' || record.status === 'running'
                  return (
                    <TRow
                      key={record.execution_id}
                      onClick={() => setSelectedExecution(record.execution_id)}
                      className="cursor-pointer"
                      data-testid="soar-execution-row"
                    >
                      <Td>
                        <Badge tone={label.tone}>{label.label}</Badge>
                      </Td>
                      <Td className="max-w-[180px]">
                        <MonoId id={record.playbook_id} />
                      </Td>
                      <Td className="max-w-[180px]">
                        <span className="block truncate font-mono text-[11px] text-ink" title={record.target}>
                          {record.target}
                        </span>
                      </Td>
                      <Td className="font-mono text-[11px] text-ink-dim">
                        {String(record.metadata?.step_count ?? record.steps.length)}
                      </Td>
                      <Td className="font-mono text-[11px] text-ink-dim">{record.created_by_role}</Td>
                      <Td className="font-mono text-[10px] text-ink-faint">{formatTimestamp(record.created_at)}</Td>
                      <Td className="text-right">
                        {cancelable && (
                          <Button
                            size="sm"
                            variant="danger"
                            disabled={mutation.isPending}
                            onClick={(event) => {
                              event.stopPropagation()
                              runSoar(() => soarApi.cancel(record.execution_id))
                            }}
                          >
                            <Ban className="h-3 w-3" aria-hidden="true" />
                            Cancel
                          </Button>
                        )}
                      </Td>
                    </TRow>
                  )
                })}
              </tbody>
            </Table>
            {executions.data && executions.data.total > PAGE_SIZE && (
              <div className="flex items-center justify-between border-t border-edge-soft px-4 py-2 text-[11px] text-ink-dim">
                <span>
                  Page {executions.data.page} of {Math.max(1, Math.ceil(executions.data.total / PAGE_SIZE))} ·{' '}
                  {executions.data.total} executions
                </span>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                    Prev
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page >= Math.ceil(executions.data.total / PAGE_SIZE)}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
            {execSelected && (
              <div className="border-t border-edge-soft p-4" data-testid="soar-execution-detail">
                {executionDetail.isLoading ? (
                  <LoadingRows rows={4} />
                ) : execSelected ? (
                  <ExecutionDetail detail={execSelected} />
                ) : null}
              </div>
            )}
          </>
        )}
      </Panel>
    </div>
  )
}

function AuthorisedRun({
  playbooks,
  approvals,
  busy,
  onDryRun,
  onExecute,
}: {
  playbooks: SoarPlaybookRecord[]
  approvals: ApprovalRecord[]
  busy: boolean
  onDryRun: (body: SoarExecutionRequest) => void
  onExecute: (body: SoarExecutionRequest) => void
}) {
  // Only a durable APPROVED grant satisfies the backend gate: it requires an
  // approval_id plus a matching policy_decision_id and action_type.
  const grants = approvals.filter(
    (approval) => approval.status === 'approved' && approval.decision,
  )

  const [approvalId, setApprovalId] = useState<string>('')
  const grant = grants.find((g) => g.approval_id === approvalId) ?? grants[0]

  const action = grant?.decision?.requested_action

  const matching: SoarPlaybookRecord[] = playbooks.filter(
    (p) => !action || p.primary_action === action,
  )
  const [playbookId, setPlaybookId] = useState('')
  const playbook =
    matching.find((p) => p.playbook_id === playbookId) ?? matching[0]

  const target = grant?.target ?? ''

  if (grants.length === 0) {
    return (
      <EmptyState
        title="No approved grant available"
        body="SOAR refuses to run without a verifiable human approval grant. Approve a pending request on the Approvals page, then return here."
      />
    )
  }

  if (!grant?.decision || !playbook) {
    return (
      <EmptyState
        title="No playbook matches this grant"
        body={`No registered playbook has primary_action=${action ?? 'unknown'} for the selected grant.`}
      />
    )
  }

  // Captured after the guards above so the closure keeps the narrowed,
  // non-optional decision type instead of re-reading the nullable field.
  const approvedDecision = grant.decision

  const body = (): SoarExecutionRequest => ({
    playbook_id: playbook.playbook_id,
    target,
    response_id: crypto.randomUUID(),
    approval_id: grant.approval_id,
    decision: approvedDecision,
  })

  return (
    <div className="flex flex-wrap items-end gap-3" data-testid="soar-demo-controls">
      <div className="space-y-1">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">
          Approval grant
        </div>
        <Select
          aria-label="Approval grant"
          className="h-8 text-[11px]"
          value={grant.approval_id}
          onChange={(event) => setApprovalId(event.target.value)}
        >
          {grants.map((g) => (
            <option key={g.approval_id} value={g.approval_id}>
              {g.action_type} · {g.target} · {g.policy_rule_id}
            </option>
          ))}
        </Select>
      </div>
      <div className="space-y-1">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">Playbook</div>
        <Select
          aria-label="Playbook"
          className="h-8 text-[11px]"
          value={playbook.playbook_id}
          onChange={(event) => setPlaybookId(event.target.value)}
        >
          {matching.map((o) => (
            <option key={o.playbook_id} value={o.playbook_id}>
              {o.playbook_id}
            </option>
          ))}
        </Select>
      </div>
      <div className="space-y-1">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">
          Target (from grant)
        </div>
        <div className="flex h-8 items-center px-2 font-mono text-[11px] text-ink-dim">
          {target}
        </div>
      </div>
      <div className="flex gap-2">
        <Button size="sm" variant="outline" disabled={busy} onClick={() => onDryRun(body())}>
          <FlaskConical className="h-3 w-3" aria-hidden="true" />
          Dry-run (simulated)
        </Button>
        <Button size="sm" disabled={busy} onClick={() => onExecute(body())}>
          <Play className="h-3 w-3" aria-hidden="true" />
          Execute (sandbox)
        </Button>
      </div>
      <p className="w-full text-[11px] leading-relaxed text-ink-dim">
        Runs only through the in-memory mock providers against target{' '}
        <span className="font-mono">{target}</span>. The decision is the verbatim
        snapshot persisted on approval{' '}
        <span className="font-mono">{grant.approval_id}</span> (
        <span className="font-mono">{grant.policy_rule_id}</span>), submitted
        with its <span className="font-mono">approval_id</span> so the backend
        gate verifies a real durable grant.
      </p>
    </div>
  )
}

function PlaybookDetail({ detail }: { detail: SoarPlaybookRecord }) {
  return (
    <div className="space-y-4" data-testid="soar-playbook-detail">
      <div className="grid grid-cols-2 gap-2 text-[11px]">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Primary action</div>
          <div className="mt-0.5">
            <Badge tone="accent">{detail.primary_action}</Badge>
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Failure policy</div>
          <div className="mt-0.5">
            <Badge tone="muted">{detail.failure_policy}</Badge>
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Schema / version</div>
          <div className="mt-0.5 font-mono text-[11px] text-ink-dim">
            {detail.schema_version} · v{detail.version}
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Enabled</div>
          <div className="mt-1">
            <Badge tone={detail.enabled ? 'low' : 'muted'}>{detail.enabled ? 'enabled' : 'disabled'}</Badge>
          </div>
        </div>
      </div>
      {detail.steps.length > 0 && (
        <div>
          <div className="mb-1.5 text-[10px] uppercase tracking-wider text-ink-faint">Declarative steps</div>
          <ol className="space-y-1">
            {detail.steps.map((step) => (
              <li key={step.step_number} className="flex items-start gap-2 text-[11px] text-ink-dim">
                <span className="mt-0.5 font-mono text-ink-faint">#{step.step_number}</span>
                <div className="min-w-0">
                  <div className="text-ink">
                    {step.label} <span className="font-mono text-[10px]">{step.operation}</span>
                  </div>
                  <div className="font-mono text-[10px] text-ink-faint">
                    {step.provider_id} → {step.target ?? 'decision target'} · retries {step.retries} ·{' '}
                    {step.timeout_seconds}s
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  )
}

function ExecutionDetail({ detail }: { detail: SoarExecutionRecord }) {
  const label = executionLabel(detail.status)
  return (
    <div className="space-y-3 text-[11px]">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={label.tone}>{label.label}</Badge>
        <span className="font-mono text-ink">playbook {detail.playbook_id}</span>
        <span className="font-mono text-ink-faint">v{detail.playbook_version}</span>
        <span className="text-ink-dim">
          {detail.simulated ? 'simulated · ' : ''}run by {detail.created_by_role}
        </span>
      </div>
      <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
        {detail.steps.map((step) => (
          <StepCard key={step.step_execution_id} step={step} />
        ))}
      </div>
      {detail.error_code && (
        <div className="rounded border border-critical/30 bg-critical/5 px-2 py-1 font-mono text-[10px] text-critical">
          {detail.error_code}
        </div>
      )}
    </div>
  )
}

function StepCard({ step }: { step: SoarStepExecutionRecord }) {
  return (
    <div className="rounded border border-edge-soft p-2">
      <div className="flex items-center justify-between">
        <span className="font-mono text-ink-dim">#{step.step_number}</span>
        <Badge tone={stepTone(step.status)}>{step.status}</Badge>
      </div>
      <div className="mt-1 truncate text-ink" title={step.label}>
        {step.label}
      </div>
      <div className="truncate font-mono text-[10px] text-ink-faint" title={`${step.provider_id} · ${step.target}`}>
        {step.provider_id} · {step.target}
      </div>
      {step.retries_attempted > 0 && <div className="text-[10px] text-ink-faint">retried {step.retries_attempted}×</div>}
      {step.error_code && <div className="text-[10px] text-critical">{step.error_code}</div>}
    </div>
  )
}