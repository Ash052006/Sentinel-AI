import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { approvalsApi } from '../api/approvals'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows } from '../components/states'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { JsonViewer } from '../components/ui/json-viewer'
import { MonoId } from '../components/ui/mono-id'
import { ConfidenceBar, ScoreBar } from '../components/ui/progress'
import { Select } from '../components/ui/input'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'
import { ApprovalStatusBadge, PolicyDecisionBadge } from '../components/badges'
import { formatTimestamp } from '../lib/formats'
import type { ApprovalRecord, ApprovalStatus, PolicyDecision } from '../types/api'

const STATUSES: Array<ApprovalStatus | 'all'> = [
  'all',
  'pending',
  'approved',
  'rejected',
  'expired',
  'cancelled',
]

function PolicyDecisionPanel({ decision }: { decision: PolicyDecision }) {
  const evaluation = decision.metadata?.evaluation
  return (
    <div className="space-y-3" data-testid="policy-decision-panel">
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Policy</dt>
          <dd className="mt-1 font-mono text-[11px] text-ink">
            {decision.metadata?.policy ?? '—'}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Outcome</dt>
          <dd className="mt-1">
            <PolicyDecisionBadge status={decision.decision} />
          </dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Rule</dt>
          <dd className="mt-1 font-mono text-[11px] text-ink">{decision.policy_rule_id}</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Needs approval</dt>
          <dd className="mt-1 font-mono text-[11px] text-ink">
            {String(decision.requires_approval)}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Risk score</dt>
          <dd className="mt-1">
            <ScoreBar value={decision.risk_score} />
          </dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Confidence</dt>
          <dd className="mt-1">
            <ConfidenceBar value={decision.confidence} />
          </dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Decision id</dt>
          <dd className="mt-1">
            <MonoId id={decision.policy_decision_id} />
          </dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Decided at</dt>
          <dd className="mt-1 font-mono text-[11px] text-ink-dim">
            {formatTimestamp(decision.timestamp)}
          </dd>
        </div>
      </dl>

      <div>
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">Reason</div>
        <div className="mt-1 text-[11px] text-ink-dim">{decision.reason}</div>
      </div>

      {evaluation?.gate_results?.length ? (
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">
            Policy gates ({evaluation.decision_path})
          </div>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {evaluation.gate_results.map((gate) => (
              <li key={gate.gate}>
                <Badge tone={gate.passed ? 'low' : 'critical'}>
                  {gate.gate}
                  {gate.required ? ' *' : ''} {gate.passed ? 'pass' : 'fail'}
                </Badge>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <div className="min-w-0">
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">
            Policy evidence
          </div>
          <div className="mt-1">
            <JsonViewer value={decision.evidence as unknown as Record<string, unknown>} />
          </div>
        </div>
        <div className="min-w-0">
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">
            Decision metadata
          </div>
          <div className="mt-1">
            <JsonViewer value={decision.metadata as Record<string, unknown>} />
          </div>
        </div>
      </div>
    </div>
  )
}

function ApprovalDetail({ approval }: { approval: ApprovalRecord }) {
  const queryClient = useQueryClient()
  const [comment, setComment] = useState('')

  const resolve = useMutation({
    mutationFn: (action: 'approve' | 'reject' | 'cancel') => {
      const payload = { comment: comment.trim() || `resolved from /approvals` }
      if (action === 'approve') return approvalsApi.approve(approval.approval_id, payload)
      if (action === 'reject') return approvalsApi.reject(approval.approval_id, payload)
      return approvalsApi.cancel(approval.approval_id, payload)
    },
    onSuccess: () => {
      setComment('')
      void queryClient.invalidateQueries({ queryKey: ['approvals'] })
    },
  })

  const pending = approval.status === 'pending'

  return (
    <div className="space-y-4" data-testid="approval-detail">
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Approval id</dt>
          <dd className="mt-1">
            <MonoId id={approval.approval_id} />
          </dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Correlation</dt>
          <dd className="mt-1">
            <MonoId id={approval.correlation_id} />
          </dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Requested by</dt>
          <dd className="mt-1 font-mono text-[11px] text-ink">
            {approval.requested_by_role}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Expires</dt>
          <dd className="mt-1 font-mono text-[11px] text-ink-dim">
            {formatTimestamp(approval.expires_at)}
          </dd>
        </div>
      </dl>

      {approval.decision ? (
        <PolicyDecisionPanel decision={approval.decision} />
      ) : (
        <EmptyState
          title="No policy decision snapshot"
          body="This approval row predates decision-snapshot retention, so only the flattened reason and policy_rule_id columns are available."
        />
      )}

      <Panel title="Human resolution" padded>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div>
            <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Status</dt>
            <dd className="mt-1">
              <ApprovalStatusBadge status={approval.status} />
            </dd>
          </div>
          <div>
            <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Resolved at</dt>
            <dd className="mt-1 font-mono text-[11px] text-ink-dim">
              {approval.resolved_at ? formatTimestamp(approval.resolved_at) : '—'}
            </dd>
          </div>
          <div>
            <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Response</dt>
            <dd className="mt-1 font-mono text-[11px] text-ink">
              {approval.response_status ?? '—'}
              {approval.response_provider ? ` (${approval.response_provider})` : ''}
            </dd>
          </div>
          <div>
            <dt className="text-[10px] uppercase tracking-wider text-ink-faint">Resolution note</dt>
            <dd className="mt-1 text-[11px] text-ink-dim">
              {approval.resolution_reason ?? '—'}
            </dd>
          </div>
        </div>

        {pending ? (
          <div className="mt-4 space-y-2">
            <label
              htmlFor="approval-comment"
              className="block text-[10px] uppercase tracking-wider text-ink-faint"
            >
              Resolution comment
            </label>
            <input
              id="approval-comment"
              data-testid="approval-comment"
              value={comment}
              onChange={(event) => setComment(event.target.value)}
              placeholder="Why you are granting or refusing this action"
              className="h-9 w-full max-w-lg rounded-md border border-edge bg-surface-0 px-3 text-xs text-ink outline-none focus:border-accent"
            />
            <div className="flex gap-2">
              <Button
                size="sm"
                data-testid="approval-approve"
                disabled={resolve.isPending}
                onClick={() => resolve.mutate('approve')}
              >
                Approve
              </Button>
              <Button
                size="sm"
                variant="danger"
                data-testid="approval-reject"
                disabled={resolve.isPending}
                onClick={() => resolve.mutate('reject')}
              >
                Reject
              </Button>
              <Button
                size="sm"
                variant="outline"
                data-testid="approval-cancel"
                disabled={resolve.isPending}
                onClick={() => resolve.mutate('cancel')}
              >
                Cancel
              </Button>
            </div>
            {resolve.isError ? (
              <ErrorState
                message={String(resolve.error)}
                onRetry={() => resolve.reset()}
              />
            ) : null}
          </div>
        ) : (
          <div className="mt-3 text-[11px] text-ink-faint">
            This approval is {approval.status} and can no longer be resolved. The
            backend enforces a single terminal transition per decision.
          </div>
        )}
      </Panel>
    </div>
  )
}

export function ApprovalsPage() {
  const [status, setStatus] = useState<ApprovalStatus | 'all'>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const approvals = useQuery({
    queryKey: ['approvals', 'list', status],
    queryFn: () => approvalsApi.list(1, 100, status === 'all' ? undefined : status),
  })

  const selected = useQuery({
    queryKey: ['approvals', 'get', selectedId],
    queryFn: () => approvalsApi.get(selectedId as string),
    enabled: selectedId !== null,
    retry: false,
  })

  const rows = approvals.data?.items ?? []
  const pendingCount = rows.filter((r) => r.status === 'pending').length
  const approvedCount = rows.filter((r) => r.status === 'approved').length
  const rejectedCount = rows.filter((r) => r.status === 'rejected').length

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Approvals"
        description="Human-in-the-loop authorisation. Every row is one REQUIRES_APPROVAL Step 24 policy decision routed to an authorised reviewer, served by GET /api/approvals."
      >
        <Select
          aria-label="Filter by approval status"
          value={status}
          onChange={(event) => {
            setStatus(event.target.value as ApprovalStatus | 'all')
            setSelectedId(null)
          }}
        >
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {value === 'all' ? 'All statuses' : value}
            </option>
          ))}
        </Select>
      </PageHeader>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Panel>
          <Stat label="Requests" value={rows.length} />
        </Panel>
        <Panel>
          <Stat label="Pending" value={pendingCount} tone="text-medium" />
        </Panel>
        <Panel>
          <Stat label="Approved" value={approvedCount} tone="text-low" />
        </Panel>
        <Panel>
          <Stat label="Rejected" value={rejectedCount} tone="text-critical" />
        </Panel>
      </div>

      {selectedId ? (
        <Panel
          title="Approval detail"
          subtitle="Served by GET /api/approvals/{approval_id}"
          action={
            <button
              type="button"
              onClick={() => setSelectedId(null)}
              className="text-[11px] text-accent hover:underline"
            >
              close
            </button>
          }
        >
          {selected.isLoading ? (
            <LoadingRows rows={4} />
          ) : selected.isError ? (
            <ErrorState
              message={String(selected.error)}
              onRetry={() => selected.refetch()}
            />
          ) : selected.data ? (
            <ApprovalDetail approval={selected.data} />
          ) : (
            <EmptyState title="Approval not found" />
          )}
        </Panel>
      ) : null}

      <Panel padded={false}>
        {approvals.isLoading ? (
          <LoadingRows rows={8} />
        ) : approvals.isError ? (
          <ErrorState
            message={String(approvals.error)}
            onRetry={() => approvals.refetch()}
          />
        ) : rows.length === 0 ? (
          <EmptyState
            title="No approval requests"
            body="No persisted approval request matched this filter. Approvals are created when the policy engine returns REQUIRES_APPROVAL."
          />
        ) : (
          <Table>
            <thead>
              <tr className="border-b border-edge">
                <Th>Status</Th>
                <Th>Action</Th>
                <Th>Target</Th>
                <Th>Policy decision</Th>
                <Th>Rule</Th>
                <Th>Risk</Th>
                <Th>Requested</Th>
                <Th>Approval id</Th>
                <Th />
              </tr>
            </thead>
            <tbody className="divide-y divide-edge-soft">
              {rows.map((item) => (
                <TRow key={item.id}>
                  <Td>
                    <ApprovalStatusBadge status={item.status} />
                  </Td>
                  <Td>
                    <span className="font-mono text-[11px] text-ink">{item.action_type}</span>
                  </Td>
                  <Td>
                    <span className="font-mono text-[11px] text-ink-dim">{item.target}</span>
                  </Td>
                  <Td>
                    {item.decision ? (
                      <PolicyDecisionBadge status={item.decision.decision} />
                    ) : (
                      <span className="text-[11px] text-ink-faint">—</span>
                    )}
                  </Td>
                  <Td>
                    <span className="font-mono text-[11px] text-ink-dim">
                      {item.policy_rule_id}
                    </span>
                  </Td>
                  <Td>
                    <ScoreBar value={item.risk_score} />
                  </Td>
                  <Td className="text-xs text-ink-dim">
                    {formatTimestamp(item.requested_at)}
                  </Td>
                  <MonoCell>
                    <MonoId id={item.approval_id} />
                  </MonoCell>
                  <Td>
                    <button
                      type="button"
                      onClick={() => setSelectedId(item.approval_id)}
                      className="cursor-pointer select-none text-[11px] text-accent hover:underline"
                    >
                      open
                    </button>
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