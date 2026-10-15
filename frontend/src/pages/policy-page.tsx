import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { approvalsApi } from '../api/approvals'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows } from '../components/states'
import { Badge } from '../components/ui/badge'
import { PolicyDecisionBadge } from '../components/badges'
import { MonoId } from '../components/ui/mono-id'
import { ConfidenceBar, ScoreBar } from '../components/ui/progress'
import { JsonViewer } from '../components/ui/json-viewer'
import { Select } from '../components/ui/input'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'
import { formatTimestamp } from '../lib/formats'
import type {
  ApprovalRecord,
  PolicyDecision,
  PolicyDecisionStatus,
} from '../types/api'

const OUTCOMES: Array<PolicyDecisionStatus | 'all'> = [
  'all',
  'allowed',
  'denied',
  'requires_approval',
]

/**
 * Step 24 defines no policy table and no policy API: the engine evaluates in
 * memory only.  It does, however, persist the *verbatim decision* on every
 * approval row it routes, because REQUIRES_APPROVAL is the only outcome that
 * reaches a human.  This view therefore reads real decisions from
 * GET /api/approvals rather than re-running the engine or inventing rows.
 */
export function PolicyPage() {
  const [outcome, setOutcome] = useState<PolicyDecisionStatus | 'all'>('all')
  const [expanded, setExpanded] = useState<string | null>(null)

  const approvals = useQuery({
    queryKey: ['approvals', 'list', 'policy-page'],
    queryFn: () => approvalsApi.list(1, 200),
  })

  const decisions = useMemo(() => {
    const items: Array<{ approval: ApprovalRecord; decision: PolicyDecision }> = []
    for (const approval of approvals.data?.items ?? []) {
      if (approval.decision) items.push({ approval, decision: approval.decision })
    }
    return outcome === 'all'
      ? items
      : items.filter((row) => row.decision.decision === outcome)
  }, [approvals.data, outcome])

  const stats = useMemo(() => {
    const counts: Record<PolicyDecisionStatus, number> = {
      allowed: 0,
      denied: 0,
      requires_approval: 0,
    }
    for (const { decision } of decisions) counts[decision.decision] += 1
    return counts
  }, [decisions])

  const policyNames = useMemo(
    () =>
      Array.from(
        new Set(
          decisions
            .map((row) => row.decision.metadata?.policy)
            .filter((value): value is string => typeof value === 'string'),
        ),
      ),
    [decisions],
  )

  const selected = decisions.find((row) => row.decision.policy_decision_id === expanded)

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Policy"
        description="Real Step 24 policy decisions, read from the verbatim decision snapshot persisted on every routed approval. Served by GET /api/approvals."
      >
        <Select
          aria-label="Filter by policy outcome"
          value={outcome}
          onChange={(event) => {
            setOutcome(event.target.value as PolicyDecisionStatus | 'all')
            setExpanded(null)
          }}
        >
          {OUTCOMES.map((value) => (
            <option key={value} value={value}>
              {value === 'all' ? 'All outcomes' : value.replace(/_/g, ' ')}
            </option>
          ))}
        </Select>
      </PageHeader>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Panel>
          <Stat label="Decisions" value={decisions.length} />
        </Panel>
        <Panel>
          <Stat label="Allowed" value={stats.allowed} tone="text-low" />
        </Panel>
        <Panel>
          <Stat label="Denied" value={stats.denied} tone="text-critical" />
        </Panel>
        <Panel>
          <Stat
            label="Requires approval"
            value={stats.requires_approval}
            tone="text-medium"
          />
        </Panel>
      </div>

      <Panel title="Evaluation context" subtitle="What the engine actually read">
        <div className="space-y-2 text-[11px] text-ink-dim">
          <p>
            The policy engine is deterministic and in-memory: it is not persisted
            and has no API of its own. What is persisted is the exact decision it
            reached, on the approval row, so an auditor can reconstruct the gate
            evaluation behind any human authorisation.
          </p>
          <div className="flex flex-wrap gap-1.5 pt-1">
            <span className="text-ink-faint">Policy:</span>
            {policyNames.length ? (
              policyNames.map((name) => (
                <Badge key={name} tone="accent">
                  {name}
                </Badge>
              ))
            ) : (
              <span className="text-ink-faint">—</span>
            )}
          </div>
        </div>
      </Panel>

      {selected ? (
        <Panel
          title="Decision detail"
          subtitle={selected.decision.policy_decision_id}
          action={
            <button
              type="button"
              onClick={() => setExpanded(null)}
              className="text-[11px] text-accent hover:underline"
            >
              close
            </button>
          }
        >
          <div className="space-y-3">
            <div className="flex flex-wrap gap-1.5">
              <PolicyDecisionBadge status={selected.decision.decision} />
              <Badge tone="muted">{selected.decision.policy_rule_id}</Badge>
              <Badge tone="muted">{selected.decision.requested_action}</Badge>
            </div>
            <div className="text-[11px] text-ink-dim">{selected.decision.reason}</div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div>
                <span className="text-[10px] uppercase tracking-wider text-ink-faint">
                  Risk score
                </span>
                <div className="mt-1">
                  <ScoreBar value={selected.decision.risk_score} />
                </div>
              </div>
              <div>
                <span className="text-[10px] uppercase tracking-wider text-ink-faint">
                  Confidence
                </span>
                <div className="mt-1">
                  <ConfidenceBar value={selected.decision.confidence} />
                </div>
              </div>
              <div>
                <span className="text-[10px] uppercase tracking-wider text-ink-faint">
                  Decided at
                </span>
                <div className="mt-1 font-mono text-[11px] text-ink-dim">
                  {formatTimestamp(selected.decision.timestamp)}
                </div>
              </div>
              <div>
                <span className="text-[10px] uppercase tracking-wider text-ink-faint">
                  Approval
                </span>
                <div className="mt-1">
                  <MonoId id={selected.approval.approval_id} />
                </div>
              </div>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {(selected.decision.metadata?.evaluation?.gate_results ?? []).map(
                (gate) => (
                  <Badge key={gate.gate} tone={gate.passed ? 'low' : 'critical'}>
                    {gate.gate}
                    {gate.required ? ' *' : ''} {gate.passed ? 'pass' : 'fail'}
                  </Badge>
                ),
              )}
            </div>
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              <div className="min-w-0">
                <div className="text-[10px] uppercase tracking-wider text-ink-faint">
                  Policy evidence
                </div>
                <div className="mt-1">
                  <JsonViewer
                    value={
                      selected.decision.evidence as unknown as Record<string, unknown>
                    }
                  />
                </div>
              </div>
              <div className="min-w-0">
                <div className="text-[10px] uppercase tracking-wider text-ink-faint">
                  Decision metadata
                </div>
                <div className="mt-1">
                  <JsonViewer value={selected.decision.metadata as Record<string, unknown>} />
                </div>
              </div>
            </div>
          </div>
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
        ) : decisions.length === 0 ? (
          <EmptyState
            title="No policy decisions"
            body="No approval row carries a decision snapshot. A decision appears here once the policy engine returns REQUIRES_APPROVAL and the request is routed for human authorisation."
          />
        ) : (
          <Table>
            <thead>
              <tr className="border-b border-edge">
                <Th>Outcome</Th>
                <Th>Rule</Th>
                <Th>Action</Th>
                <Th>Risk</Th>
                <Th>Confidence</Th>
                <Th>Reason</Th>
                <Th>Decided at</Th>
                <Th>Decision id</Th>
                <Th />
              </tr>
            </thead>
            <tbody className="divide-y divide-edge-soft">
              {decisions.map(({ decision }) => (
                <TRow key={decision.policy_decision_id}>
                  <Td>
                    <PolicyDecisionBadge status={decision.decision} />
                  </Td>
                  <Td>
                    <span className="font-mono text-[11px] text-ink">
                      {decision.policy_rule_id}
                    </span>
                  </Td>
                  <Td>
                    <span className="font-mono text-[11px] text-ink-dim">
                      {decision.requested_action}
                    </span>
                  </Td>
                  <Td>
                    <ScoreBar value={decision.risk_score} />
                  </Td>
                  <Td>
                    <ConfidenceBar value={decision.confidence} />
                  </Td>
                  <Td className="max-w-md text-[11px] text-ink-dim">{decision.reason}</Td>
                  <Td className="text-xs text-ink-dim">
                    {formatTimestamp(decision.timestamp)}
                  </Td>
                  <MonoCell>
                    <MonoId id={decision.policy_decision_id} />
                  </MonoCell>
                  <Td>
                    <button
                      type="button"
                      onClick={() => setExpanded(decision.policy_decision_id)}
                      className="cursor-pointer select-none text-[11px] text-accent hover:underline"
                    >
                      detail
                    </button>
                  </Td>
                </TRow>
              ))}
            </tbody>
          </Table>
        )}
      </Panel>

      <Panel title="Authorise" subtitle="The human half of the same decision">
        <p className="text-[11px] text-ink-dim">
          Resolving a decision is a separate, explicit step.{' '}
          <Link to="/approvals" className="text-accent hover:underline">
            Open Approvals
          </Link>{' '}
          to approve, reject or cancel a pending request.
        </p>
      </Panel>
    </div>
  )
}