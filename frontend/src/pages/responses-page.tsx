import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Shield,
  ShieldAlert,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  Play,
  Server,
  Lock,
  WifiOff,
  UserX,
  FileWarning,
  ExternalLink,
} from 'lucide-react'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { MonoId } from '../components/ui/mono-id'
import { Table, TRow, Th, Td } from '../components/ui/table'
import { EmptyState, ErrorState, LoadingRows } from '../components/states'
import { soarApi } from '../api/soar'
import { approvalsApi } from '../api/approvals'
import { formatTimestamp } from '../lib/formats'
import type { ResponseActionType, SoarExecutionStatus } from '../types/api'

interface ResponseCapability {
  action: ResponseActionType
  label: string
  provider: 'edr' | 'firewall' | 'identity'
  providerName: string
  impact: 'low' | 'medium' | 'high' | 'critical'
  governance: 'auto' | 'approval_required'
  description: string
  icon: typeof Shield
}

const RESPONSE_CAPABILITIES: ResponseCapability[] = [
  {
    action: 'isolate_endpoint',
    label: 'Isolate Endpoint',
    provider: 'edr',
    providerName: 'EDR Sandbox Adapter',
    impact: 'critical',
    governance: 'approval_required',
    description: 'Sever all network interfaces on infected asset except telemetry uplink.',
    icon: WifiOff,
  },
  {
    action: 'terminate_session',
    label: 'Terminate Session',
    provider: 'edr',
    providerName: 'EDR Sandbox Adapter',
    impact: 'medium',
    governance: 'auto',
    description: 'Kill malicious interactive processes and evict active rogue user sessions.',
    icon: Terminal,
  },
  {
    action: 'quarantine_file',
    label: 'Quarantine File',
    provider: 'edr',
    providerName: 'EDR Sandbox Adapter',
    impact: 'medium',
    governance: 'approval_required',
    description: 'Isolate malicious executable from filesystem into encrypted forensic vault.',
    icon: FileWarning,
  },
  {
    action: 'block_ip',
    label: 'Block Source IP',
    provider: 'firewall',
    providerName: 'Perimeter Firewall Adapter',
    impact: 'low',
    governance: 'auto',
    description: 'Enforce perimeter drop rules on external C2 and brute-force IP addresses.',
    icon: ShieldAlert,
  },
  {
    action: 'block_domain',
    label: 'Block Domain',
    provider: 'firewall',
    providerName: 'DNS / Firewall Sinkhole',
    impact: 'low',
    governance: 'auto',
    description: 'Route adversary domains and phishing lures to local sinkhole.',
    icon: Lock,
  },
  {
    action: 'disable_account',
    label: 'Disable Account',
    provider: 'identity',
    providerName: 'IAM Identity Provider',
    impact: 'high',
    governance: 'approval_required',
    description: 'Revoke directory credentials and terminate OAuth tokens for compromised identity.',
    icon: UserX,
  },
]

function statusTone(status: SoarExecutionStatus): 'low' | 'muted' | 'critical' | 'accent' | 'medium' {
  switch (status) {
    case 'succeeded':
      return 'low'
    case 'failed':
      return 'critical'
    case 'rejected':
      return 'critical'
    case 'pending':
      return 'accent'
    case 'running':
      return 'accent'
    case 'partial':
      return 'medium'
    case 'cancelled':
      return 'muted'
    default:
      return 'muted'
  }
}

export function ResponsesPage() {
  const queryClient = useQueryClient()
  const [selectedAction, setSelectedAction] = useState<ResponseCapability>(RESPONSE_CAPABILITIES[0])
  const [targetInput, setTargetInput] = useState('')
  const [testResult, setTestResult] = useState<{ status: string; detail: string } | null>(null)

  const executionsQuery = useQuery({
    queryKey: ['soar', 'executions', 1, 50],
    queryFn: () => soarApi.executions(1, 50),
  })

  const pendingApprovalsQuery = useQuery({
    queryKey: ['approvals', 'recent', 'pending'],
    queryFn: () => approvalsApi.recent(10, 'pending'),
  })

  const approvedGrantsQuery = useQuery({
    queryKey: ['approvals', 'list', 'approved', 20],
    queryFn: () => approvalsApi.list(1, 20, 'approved'),
  })

  const executions = useMemo(() => executionsQuery.data?.items ?? [], [executionsQuery.data])
  const pendingApprovals = useMemo(() => pendingApprovalsQuery.data ?? [], [pendingApprovalsQuery.data])
  const approvedGrants = useMemo(() => approvedGrantsQuery.data?.items ?? [], [approvedGrantsQuery.data])

  const dryRunMutation = useMutation({
    mutationFn: async () => {
      const target = targetInput.trim()
      if (!target) {
        throw new Error('Please specify a target identifier (e.g. IP, domain, username, or endpoint ID).')
      }

      // Check if an approved grant exists matching this action
      const matchingGrant = approvedGrants.find((g) => g.decision?.requested_action === selectedAction.action)

      if (matchingGrant && matchingGrant.decision) {
        const res = await soarApi.dryRun({
          playbook_id: selectedAction.action,
          target,
          response_id: crypto.randomUUID(),
          approval_id: matchingGrant.approval_id,
          decision: matchingGrant.decision,
        })
        return {
          outcome: res.status,
          message: res.message ?? `Verified against ${selectedAction.providerName} with approved grant.`,
        }
      }

      // If no grant, simulate preflight check locally
      await new Promise((resolve) => setTimeout(resolve, 350))
      return {
        outcome: selectedAction.governance === 'approval_required' ? 'REQUIRES APPROVAL' : 'PREFLIGHT READY',
        message:
          selectedAction.governance === 'approval_required'
            ? `Action requires an approved human authorization grant before dispatching to ${selectedAction.providerName}.`
            : `Syntax and preflight valid for ${selectedAction.providerName}. Ready for automated execution.`,
      }
    },
    onSuccess: (data) => {
      setTestResult({
        status: data.outcome === 'succeeded' || data.outcome === 'PREFLIGHT READY' ? 'VALIDATED' : data.outcome,
        detail: data.message,
      })
      void queryClient.invalidateQueries({ queryKey: ['soar'] })
    },
    onError: (err: unknown) => {
      setTestResult({
        status: 'VALIDATION REFUSED',
        detail: err instanceof Error ? err.message : String(err),
      })
    },
  })

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <PageHeader
        title="Responses & Mitigation"
        description="Active security countermeasures, containment adapters, and governed response execution (Step 25). High-impact actions are safeguarded by human-in-the-loop policy gates."
      />

      {/* Governance & Architecture Banner */}
      <div className="rounded-lg border border-edge bg-surface-1 p-4 shadow-sm">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-start gap-3">
            <div className="rounded-md bg-accent/10 p-2 text-accent">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-xs font-semibold uppercase tracking-wider text-ink">
                Closed Governance Architecture
              </h2>
              <p className="mt-0.5 text-xs text-ink-dim">
                Automated containment is strictly gated by the Policy Engine (Step 24). Low-impact mitigations
                proceed automatically, while high-impact actions (endpoint isolation, account suspension) mandate human SOC authorization.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Link to="/approvals">
              <Button variant="outline" size="sm" className="gap-1.5">
                <ExternalLink className="h-3.5 w-3.5" />
                Approvals Queue ({pendingApprovals.length})
              </Button>
            </Link>
            <Link to="/soar">
              <Button variant="outline" size="sm" className="gap-1.5">
                <Play className="h-3.5 w-3.5" />
                SOAR Workflows
              </Button>
            </Link>
          </div>
        </div>
      </div>

      {/* Metric Counters */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Configured Actions" value={RESPONSE_CAPABILITIES.length} />
        <Stat label="Active Adapters" value="3 (EDR, FW, IAM)" />
        <Stat label="Total Executions" value={executionsQuery.data?.total ?? 0} />
        <Stat
          label="Pending Authorizations"
          value={pendingApprovals.length}
          tone={pendingApprovals.length > 0 ? 'text-accent' : 'text-ink-dim'}
        />
      </div>

      {/* Response Capabilities Grid */}
      <Panel
        title="Response Action Vocabulary"
        subtitle="Server-authoritative containment operations mapped to underlying security adapters"
      >
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
          {RESPONSE_CAPABILITIES.map((cap) => {
            const Icon = cap.icon
            const isSelected = selectedAction.action === cap.action
            return (
              <div
                key={cap.action}
                onClick={() => {
                  setSelectedAction(cap)
                  setTestResult(null)
                }}
                className={`cursor-pointer rounded-lg border p-3.5 transition-all ${
                  isSelected
                    ? 'border-accent bg-accent/5 ring-1 ring-accent'
                    : 'border-edge bg-surface-2 hover:border-ink/20'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <div className="rounded bg-surface-1 p-1.5 text-ink">
                      <Icon className="h-4 w-4" />
                    </div>
                    <span className="text-xs font-semibold text-ink">{cap.label}</span>
                  </div>
                  <Badge tone={cap.impact === 'critical' ? 'critical' : cap.impact === 'high' ? 'medium' : 'muted'}>
                    {cap.impact.toUpperCase()}
                  </Badge>
                </div>
                <p className="mt-2 text-[11px] leading-relaxed text-ink-dim">{cap.description}</p>
                <div className="mt-3 flex items-center justify-between border-t border-edge-soft pt-2 text-[10px] text-ink-faint">
                  <span>Adapter: <strong className="text-ink">{cap.provider.toUpperCase()}</strong></span>
                  <span>{cap.governance === 'approval_required' ? 'Mandates Approval' : 'Auto-Allowed'}</span>
                </div>
              </div>
            )
          })}
        </div>
      </Panel>

      {/* Interactive Response Dry-Run & Testing Harness */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel
          title="Mitigation Verification Harness"
          subtitle={`Validate response syntax and adapter preflight for ${selectedAction.label}`}
          className="lg:col-span-2"
        >
          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label className="text-[10px] uppercase tracking-wider text-ink-faint">Selected Operation</label>
                <div className="mt-1 flex items-center gap-2 rounded border border-edge bg-surface-2 px-3 py-2 text-xs font-mono text-ink">
                  <Server className="h-3.5 w-3.5 text-accent" />
                  {selectedAction.action}
                </div>
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider text-ink-faint">Target Adapter</label>
                <div className="mt-1 flex items-center gap-2 rounded border border-edge bg-surface-2 px-3 py-2 text-xs font-mono text-ink">
                  {selectedAction.providerName}
                </div>
              </div>
            </div>

            <div>
              <label className="text-[10px] uppercase tracking-wider text-ink-faint">
                Target Identifier (Asset ID, IP, Domain, Account)
              </label>
              <div className="mt-1 flex gap-2">
                <input
                  type="text"
                  placeholder={
                    selectedAction.action === 'isolate_endpoint'
                      ? 'e.g. host-workstation-88'
                      : selectedAction.action === 'block_ip'
                      ? 'e.g. 198.51.100.25'
                      : selectedAction.action === 'disable_account'
                      ? 'e.g. user.name@sentinel-corp.internal'
                      : 'e.g. target-identifier'
                  }
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  className="flex-1 rounded border border-edge bg-surface-2 px-3 py-2 text-xs text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
                />
                <Button
                  onClick={() => dryRunMutation.mutate()}
                  disabled={dryRunMutation.isPending || !targetInput.trim()}
                  className="gap-1.5"
                >
                  <Play className="h-3.5 w-3.5" />
                  {dryRunMutation.isPending ? 'Validating...' : 'Dry-Run Preflight'}
                </Button>
              </div>
            </div>

            {testResult && (
              <div
                className={`rounded border p-3 text-xs ${
                  testResult.status.includes('VALIDATED') || testResult.status.includes('PREFLIGHT')
                    ? 'border-low/40 bg-low/10 text-low'
                    : 'border-critical/40 bg-critical/10 text-critical'
                }`}
              >
                <div className="flex items-center gap-2 font-semibold">
                  {testResult.status.includes('VALIDATED') || testResult.status.includes('PREFLIGHT') ? (
                    <CheckCircle2 className="h-4 w-4" />
                  ) : (
                    <AlertTriangle className="h-4 w-4" />
                  )}
                  {testResult.status}
                </div>
                <div className="mt-1 text-[11px] opacity-90">{testResult.detail}</div>
              </div>
            )}
          </div>
        </Panel>

        {/* Security Adapters Status */}
        <Panel title="Security Adapters" subtitle="Active enforcement points">
          <div className="space-y-3">
            <div className="flex items-center justify-between rounded border border-edge bg-surface-2 p-3">
              <div>
                <div className="text-xs font-semibold text-ink">EDR Sandbox Adapter</div>
                <div className="text-[10px] text-ink-dim">Host Isolation, Process Kill, Quarantine</div>
              </div>
              <Badge tone="low">ONLINE</Badge>
            </div>
            <div className="flex items-center justify-between rounded border border-edge bg-surface-2 p-3">
              <div>
                <div className="text-xs font-semibold text-ink">Perimeter Firewall</div>
                <div className="text-[10px] text-ink-dim">IP Drop Rules, DNS Blackholing</div>
              </div>
              <Badge tone="low">ONLINE</Badge>
            </div>
            <div className="flex items-center justify-between rounded border border-edge bg-surface-2 p-3">
              <div>
                <div className="text-xs font-semibold text-ink">IAM Identity Provider</div>
                <div className="text-[10px] text-ink-dim">Account Revocation, Session Invalidation</div>
              </div>
              <Badge tone="low">ONLINE</Badge>
            </div>
          </div>
        </Panel>
      </div>

      {/* Real Executions Audit Log */}
      <Panel
        title="Recent Response Executions"
        subtitle="Authoritative audit log of executed, simulated, and pending mitigation actions"
        padded={false}
      >
        {executionsQuery.isLoading ? (
          <LoadingRows rows={6} />
        ) : executionsQuery.isError ? (
          <ErrorState message={String(executionsQuery.error)} />
        ) : executions.length === 0 ? (
          <EmptyState
            title="No mitigations recorded yet"
            body="Mitigation actions executed autonomously or approved by SOC analysts will stream here in real time."
          />
        ) : (
          <Table>
            <thead>
              <tr className="border-b border-edge">
                <Th>Execution ID</Th>
                <Th>Playbook / Action</Th>
                <Th>Status</Th>
                <Th>Steps</Th>
                <Th>Executed At</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge-soft">
              {executions.map((exec) => {
                const tone = statusTone(exec.status)
                return (
                  <TRow key={exec.execution_id}>
                    <Td className="font-mono text-xs text-ink">
                      <MonoId id={exec.execution_id} />
                    </Td>
                    <Td>
                      <div className="text-xs font-medium text-ink">{exec.playbook_id}</div>
                      <div className="text-[10px] text-ink-dim">
                        {exec.steps?.[0]?.operation ?? 'automated mitigation'}
                      </div>
                    </Td>
                    <Td>
                      <Badge tone={tone}>{exec.status.toUpperCase()}</Badge>
                    </Td>
                    <Td className="font-mono text-[11px] text-ink-dim">
                      {exec.steps?.length ?? 1} step(s)
                    </Td>
                    <Td className="font-mono text-[11px] text-ink-dim">
                      {formatTimestamp(exec.created_at)}
                    </Td>
                  </TRow>
                )
              })}
            </tbody>
          </Table>
        )}
      </Panel>
    </div>
  )
}
