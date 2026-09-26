import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { RotateCcw, ThumbsDown, ThumbsUp } from 'lucide-react'
import { detectionAsCodeApi } from '../api/detectionAsCode'
import { RuleTypeBadge, SeverityBadge } from '../components/badges'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { MonoId } from '../components/ui/mono-id'
import { Input, Select } from '../components/ui/input'
import { Td, Th, TRow, Table } from '../components/ui/table'
import { formatTimestamp } from '../lib/formats'
import type {
  DetectionAsCodeRuleDetail,
  DetectionRuleVersionRecord,
  DeploymentState,
  ReleaseState,
  ValidationOutcome,
} from '../types/api'
import type {
  LifecycleOutput,
} from '../api/detectionAsCode'

const PAGE_SIZE = 50

interface Filters {
  query: string
  ruleType: 'all' | 'sigma' | 'yara'
  state: 'all' | 'validated' | 'released' | 'deployed' | 'disabled'
}

function stateLabel(record: DetectionRuleVersionRecord): string {
  if (!record.enabled) return 'disabled'
  if (record.deployment_state === 'deployed') return 'deployed'
  if (record.release_state === 'released') return 'released'
  if (record.validation_status === 'validated') return 'validated'
  return 'draft'
}

function validationTone(status: ValidationOutcome): 'low' | 'muted' | 'critical' | 'medium' {
  if (status === 'validated') return 'low'
  if (status === 'failed') return 'critical'
  if (status === 'validating') return 'medium'
  return 'muted'
}

function releaseTone(state: ReleaseState): 'low' | 'muted' | 'accent' | 'critical' {
  if (state === 'released') return 'low'
  if (state === 'failed') return 'critical'
  if (state === 'validated' || state === 'validating') return 'accent'
  return 'muted'
}

function deployTone(state: DeploymentState): 'low' | 'muted' {
  return state === 'deployed' ? 'low' : 'muted'
}

function matchFilters(record: DetectionRuleVersionRecord, filters: Filters): boolean {
  if (filters.ruleType !== 'all' && record.rule_type !== filters.ruleType) return false
  const state = stateLabel(record)
  if (filters.state !== 'all' && state !== filters.state) return false
  if (filters.query.trim()) {
    const needle = filters.query.trim().toLowerCase()
    const haystack = `${record.title} ${record.rule_id} ${record.source_path}`.toLowerCase()
    if (!haystack.includes(needle)) return false
  }
  return true
}

export function DetectionAsCodePage() {
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState<Filters>({ query: '', ruleType: 'all', state: 'all' })
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const list = useQuery({
    queryKey: ['detection-as-code', 'list', page, PAGE_SIZE],
    queryFn: () => detectionAsCodeApi.list(page, PAGE_SIZE),
  })

  const detail = useQuery({
    queryKey: ['detection-as-code', 'detail', selectedId],
    queryFn: () => detectionAsCodeApi.get(selectedId as string),
    enabled: selectedId !== null,
  })

  const actions = useMutation({
    mutationFn: (fn: () => Promise<LifecycleOutput>) => fn(),
    onSuccess: (result) => {
      setNotice(`Rule ${result.rule_id ?? ''} governed at ${result.version ?? ''}`)
      void queryClient.invalidateQueries({ queryKey: ['detection-as-code'] })
    },
    onError: () => setNotice(null),
  })

  const items = useMemo(() => list.data?.items ?? [], [list.data])
  const rows = useMemo(
    () => items.filter((record) => matchFilters(record, filters)),
    [items, filters],
  )

  const sigmaTotal = items.filter((r) => r.rule_type === 'sigma').length
  const yaraTotal = items.filter((r) => r.rule_type === 'yara').length
  const validatedTotal = items.filter((r) => r.validation_status === 'validated').length
  const releasedTotal = items.filter((r) => r.release_state === 'released').length
  const deployedTotal = items.filter((r) => r.deployment_state === 'deployed').length

  const gov = (fn: () => Promise<LifecycleOutput>) => () => {
    actions.mutate(fn)
  }

  const enabled = actions.isPending
  const selected = detail.data

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Detection-as-Code Governance"
        description="V2.17 governed lifecycle over the controlled rule repository — server-side validation through the real Sigma/YARA engines, strict semver, then release → deploy → rollback. Accounts for 28 Sigma + 25 YARA governed rules."
      />

      {notice && <div className="rounded border border-low/40 bg-low/10 px-3 py-2 text-xs text-ink">{notice}</div>}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
        <Stat label="Governed" value={items.length} />
        <Stat label="Sigma" value={sigmaTotal} />
        <Stat label="YARA" value={yaraTotal} />
        <Stat label="Validated" value={validatedTotal} tone="text-low" />
        <Stat label="Released" value={releasedTotal} tone="text-accent" />
        <Stat label="Deployed" value={deployedTotal} tone="text-ink" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel
          title="Governed rules"
          subtitle={`${rows.length} of ${items.length} latest versions · deterministic manifest order`}
          padded={false}
          className="xl:col-span-2"
          action={
            <div className="flex flex-wrap items-center gap-2">
              <Input
                aria-label="Search governed rules"
                placeholder="Search title, id, source…"
                className="h-7 w-44 text-[11px]"
                value={filters.query}
                onChange={(event) =>
                  setFilters((current) => ({ ...current, query: event.target.value }))
                }
              />
              <Select
                aria-label="Filter by rule type"
                className="h-7 text-[11px]"
                value={filters.ruleType}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    ruleType: event.target.value as Filters['ruleType'],
                  }))
                }
              >
                <option value="all">All types</option>
                <option value="sigma">Sigma</option>
                <option value="yara">YARA</option>
              </Select>
              <Select
                aria-label="Filter by governance state"
                className="h-7 text-[11px]"
                value={filters.state}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    state: event.target.value as Filters['state'],
                  }))
                }
              >
                <option value="all">All states</option>
                <option value="validated">Validated</option>
                <option value="released">Released</option>
                <option value="deployed">Deployed</option>
                <option value="disabled">Disabled</option>
              </Select>
            </div>
          }
        >
          {list.isLoading ? (
            <LoadingRows rows={10} />
          ) : list.isError ? (
            <ErrorState message={String(list.error)} onRetry={() => list.refetch()} />
          ) : rows.length === 0 ? (
            <EmptyState
              title="No governed rules"
              body="No governed rules match the active filters. Rules appear here once validated."
            />
          ) : (
            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Rule</Th>
                  <Th>Version</Th>
                  <Th>Type</Th>
                  <Th>Severity</Th>
                  <Th>Validation</Th>
                  <Th>Release</Th>
                  <Th>Deploy</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {rows.map((record) => (
                  <TRow
                    key={record.version_id}
                    onClick={() => setSelectedId(record.rule_id)}
                    className="cursor-pointer"
                    data-testid="dac-rule-row"
                  >
                    <Td className="max-w-[240px]">
                      <div className="truncate text-xs font-medium text-ink" title={record.title}>
                        {record.title}
                      </div>
                      <MonoId id={record.rule_id} />
                    </Td>
                    <Td className="font-mono text-[11px] text-ink">v{record.version}</Td>
                    <Td>
                      <RuleTypeBadge ruleType={record.rule_type} />
                    </Td>
                    <Td>
                      <SeverityBadge severity={record.severity} />
                    </Td>
                    <Td>
                      <Badge tone={validationTone(record.validation_status)}>
                        {record.validation_status}
                      </Badge>
                    </Td>
                    <Td>
                      <Badge tone={releaseTone(record.release_state)}>{record.release_state}</Badge>
                    </Td>
                    <Td>
                      <Badge tone={deployTone(record.deployment_state)}>{record.deployment_state}</Badge>
                    </Td>
                  </TRow>
                ))}
              </tbody>
            </Table>
          )}
          {list.data && list.data.total > PAGE_SIZE && (
            <div className="flex items-center justify-between border-t border-edge-soft px-4 py-2 text-[11px] text-ink-dim">
              <span>
                Page {list.data.page} of {Math.max(1, Math.ceil(list.data.total / PAGE_SIZE))} · {list.data.total} rules
              </span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                  Prev
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= Math.ceil(list.data.total / PAGE_SIZE)}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </Panel>

        <Panel
          title="Rule lifecycle"
          subtitle={selected ? `${selected.current.title} · v${selected.current.version}` : 'Select a row to inspect its governed lifecycle'}
        >
          {detail.isLoading ? (
            <LoadingRows rows={8} />
          ) : detail.isError ? (
            <ErrorState message={String(detail.error)} />
          ) : selected ? (
            <GovernanceDetail
              detail={selected}
              busy={enabled}
              onValidate={gov(() => detectionAsCodeApi.validate({ rule_id: selected.current.rule_id }))}
              onRelease={gov(() =>
                detectionAsCodeApi.release(selected.current.rule_id, selected.current.version),
              )}
              onDeploy={gov(() =>
                detectionAsCodeApi.deploy(selected.current.rule_id, selected.current.version),
              )}
              onRollback={gov(() =>
                detectionAsCodeApi.rollback(selected.current.rule_id, selected.current.version),
              )}
              onToggle={gov(() =>
                detectionAsCodeApi.setEnabled({
                  rule_id: selected.current.rule_id,
                  version: selected.current.version,
                  enabled: !selected.current.enabled,
                }),
              )}
            />
          ) : (
            <NotAvailable
              title="No rule selected"
              body="Select a governed rule from the table to inspect its validation gates, release history, and versioning ledger."
            />
          )}
        </Panel>
      </div>
    </div>
  )
}

function Gate({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="flex items-center justify-between">
      <span className="font-mono text-[11px] text-ink-dim">{label}</span>
      <Badge tone={ok ? 'low' : 'critical'}>{ok ? 'ok' : 'fail'}</Badge>
    </div>
  )
}

function GovernanceDetail({
  detail,
  busy,
  onValidate,
  onRelease,
  onDeploy,
  onRollback,
  onToggle,
}: {
  detail: DetectionAsCodeRuleDetail
  busy: boolean
  onValidate: () => void
  onRelease: () => void
  onDeploy: () => void
  onRollback: () => void
  onToggle: () => void
}) {
  const current = detail.current
  const validation = detail.validation
  const activeRelease = detail.releases.find((r) => r.version === current.version)

  return (
    <div className="space-y-4" data-testid="dac-preview">
      <div className="grid grid-cols-2 gap-2 text-[11px]">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Version / type</div>
          <div className="mt-0.5 flex items-center gap-1.5">
            <span className="font-mono text-ink">v{current.version}</span>
            <RuleTypeBadge ruleType={current.rule_type} />
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Severity</div>
          <div className="mt-1">
            <SeverityBadge severity={current.severity} />
          </div>
        </div>
        <div className="col-span-2">
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Source</div>
          <div className="mt-0.5 font-mono text-[11px] text-ink-dim">{current.source_path}</div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Author</div>
          <div className="mt-0.5 text-ink">{current.author ?? '—'}</div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Status</div>
          <div className="mt-0.5 text-ink">{current.status ?? '—'}</div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Enabled</div>
          <div className="mt-1">
            <Badge tone={current.enabled ? 'low' : 'muted'}>
              {current.enabled ? 'enabled' : 'disabled'}
            </Badge>
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Updated</div>
          <div className="mt-0.5 font-mono text-[10px] text-ink-dim">
            {formatTimestamp(current.updated_at)}
          </div>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" disabled={busy} onClick={onValidate}>
          Validate
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={busy || current.validation_status !== 'validated'}
          onClick={onRelease}
        >
          Release
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={busy || current.release_state !== 'released'}
          onClick={onDeploy}
        >
          Deploy
        </Button>
        <Button size="sm" variant="outline" disabled={busy || !activeRelease} onClick={onRollback}>
          <RotateCcw className="h-3 w-3" aria-hidden="true" />
          Rollback
        </Button>
        <Button
          size="sm"
          variant={current.enabled ? 'danger' : 'default'}
          disabled={busy}
          onClick={onToggle}
        >
          {current.enabled ? (
            <>
              <ThumbsDown className="h-3 w-3" aria-hidden="true" /> Disable
            </>
          ) : (
            <>
              <ThumbsUp className="h-3 w-3" aria-hidden="true" /> Enable
            </>
          )}
        </Button>
      </div>

      <div>
        <div className="mb-1.5 text-[10px] uppercase tracking-wider text-ink-faint">
          Validation gates · {validation.outcome}
        </div>
        <div className="grid grid-cols-2 gap-x-3 gap-y-1">
          <Gate label="manifest_valid" ok={validation.manifest_valid} />
          <Gate label="source_exists" ok={validation.source_exists} />
          <Gate label="source_hash_match" ok={validation.source_hash_match} />
          <Gate label="path_safe" ok={validation.path_safe} />
          <Gate label="secret_safe" ok={validation.secret_safe} />
          <Gate label="rule_type_matches" ok={validation.rule_type_matches} />
          <Gate label="severity_valid" ok={validation.severity_valid} />
          <Gate label="metadata_complete" ok={validation.metadata_complete} />
          <Gate label="compiles" ok={validation.compiles} />
          <Gate label="positive_passed" ok={validation.positive_passed} />
          <Gate label="negative_passed" ok={validation.negative_passed} />
        </div>
        {validation.errors.length > 0 && (
          <div className="mt-2 rounded border border-critical/30 bg-critical/5 p-2 font-mono text-[10px] leading-relaxed text-critical">
            {validation.errors.map((error) => (
              <div key={error}>{error}</div>
            ))}
          </div>
        )}
      </div>

      {detail.changes.length > 0 && (
        <div>
          <div className="mb-1.5 text-[10px] uppercase tracking-wider text-ink-faint">
            Versioning ledger
          </div>
          <ol className="space-y-1">
            {detail.changes.map((change) => (
              <li key={change.change_id} className="flex items-center gap-2 text-[11px] text-ink-dim">
                <Badge tone="muted">{change.change_kind}</Badge>
                <span className="font-mono">
                  {change.from_version ?? '—'} → {change.to_version}
                </span>
                {change.bump_class && <Badge tone="neutral">{change.bump_class}</Badge>}
                {change.change_reason && (
                  <span className="truncate" title={change.change_reason}>
                    {change.change_reason}
                  </span>
                )}
                <span className="ml-auto font-mono text-[10px] text-ink-faint">
                  {formatTimestamp(change.created_at)}
                </span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  )
}