import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, Play, Plus } from 'lucide-react'
import { threatHuntingApi } from '../api/threat-hunting'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { MonoId } from '../components/ui/mono-id'
import { Input, Select, Textarea } from '../components/ui/input'
import { Td, Th, TRow, Table } from '../components/ui/table'
import { formatTimestamp } from '../lib/formats'
import type {
  HuntType,
  Page,
  ThreatHuntEvidenceRecord,
  ThreatHuntFindingRecord,
  ThreatHuntRecord,
  ThreatHuntStatus,
  ThreatHuntTimelineItemRecord,
} from '../types/api'

const PAGE_SIZE = 50

const HUNT_TYPES: Array<{ value: HuntType; label: string }> = [
  { value: 'detection_review', label: 'Detection Review' },
  { value: 'indicator_hunt', label: 'Indicator Hunt' },
  { value: 'authentication_anomaly', label: 'Auth Anomaly' },
  { value: 'privilege_activity', label: 'Privilege Activity' },
  { value: 'multi_stage_activity', label: 'Multi-Stage Activity' },
]

type DetailTab = 'findings' | 'evidence' | 'timeline'

function statusLabel(status: ThreatHuntStatus): { label: string; tone: 'low' | 'muted' | 'critical' | 'accent' | 'neutral' } {
  switch (status) {
    case 'completed':
      return { label: 'COMPLETED', tone: 'low' }
    case 'failed':
      return { label: 'FAILED', tone: 'critical' }
    case 'running':
      return { label: 'RUNNING', tone: 'accent' }
    case 'cancelled':
      return { label: 'CANCELLED', tone: 'muted' }
    case 'draft':
      return { label: 'DRAFT', tone: 'neutral' }
  }
}

function huntTypeLabel(huntType: HuntType): string {
  return HUNT_TYPES.find((h) => h.value === huntType)?.label ?? huntType
}

function toLocalInput(value: Date): string {
  const pad = (n: number): string => String(n).padStart(2, '0')
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}T${pad(value.getHours())}:${pad(value.getMinutes())}`
}

function toIso(local: string): string {
  return new Date(local).toISOString()
}

export function ThreatHuntingPage() {
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [selectedHunt, setSelectedHunt] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<ThreatHuntStatus | ''>('')
  const [notice, setNotice] = useState<string | null>(null)
  const [detailTab, setDetailTab] = useState<DetailTab>('findings')

  const hunts = useQuery({
    queryKey: ['threat-hunting', 'hunts', page, PAGE_SIZE, statusFilter],
    queryFn: () =>
      threatHuntingApi.hunts(
        page,
        PAGE_SIZE,
        statusFilter === '' ? undefined : statusFilter,
      ),
  })

  const huntDetail = useQuery({
    queryKey: ['threat-hunting', 'hunt', selectedHunt],
    queryFn: () => threatHuntingApi.hunt(selectedHunt as string),
    enabled: selectedHunt !== null,
  })

  const findings = useQuery({
    queryKey: ['threat-hunting', 'findings', selectedHunt],
    queryFn: () => threatHuntingApi.findings(selectedHunt as string),
    enabled: selectedHunt !== null && huntDetail.data?.status === 'completed',
  })

  const evidence = useQuery({
    queryKey: ['threat-hunting', 'evidence', selectedHunt],
    queryFn: () => threatHuntingApi.evidence(selectedHunt as string),
    enabled: selectedHunt !== null && huntDetail.data?.status === 'completed',
  })

  const timeline = useQuery({
    queryKey: ['threat-hunting', 'timeline', selectedHunt],
    queryFn: () => threatHuntingApi.timeline(selectedHunt as string),
    enabled: selectedHunt !== null && huntDetail.data?.status === 'completed',
  })

  const mutation = useMutation({
    mutationFn: (fn: () => Promise<unknown>) => fn(),
    onSuccess: () => {
      setNotice('Threat hunt updated — the read-only engine reported the transition.')
      void queryClient.invalidateQueries({ queryKey: ['threat-hunting'] })
    },
    onError: () => {
      setNotice('The threat hunt service rejected the request (bounded or terminal state).')
    },
  })

  const runHunt = (huntId: string): void => mutation.mutate(() => threatHuntingApi.run(huntId))
  const cancelHunt = (huntId: string): void => mutation.mutate(() => threatHuntingApi.cancel(huntId))
  const createHunt = (body: Parameters<typeof threatHuntingApi.create>[0]): void =>
    mutation.mutate(() => threatHuntingApi.create(body))

  const huntRows = useMemo(() => hunts.data?.items ?? [], [hunts.data])
  const selected = huntDetail.data

  const completed = useMemo(
    () => huntRows.filter((h) => h.status === 'completed').length,
    [huntRows],
  )
  const failed = useMemo(
    () => huntRows.filter((h) => h.status === 'failed').length,
    [huntRows],
  )
  const actionable = useMemo(
    () => huntRows.filter((h) => h.status === 'draft').length,
    [huntRows],
  )

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Threat Hunting"
        description="V2.19 governed investigation over persisted Signal history — hunts compile a bounded, allowlisted filter grammar, read analytical records only, and never execute, block, quarantine, or reach SOAR."
      />

      {notice && (
        <div className="rounded border border-low/40 bg-low/10 px-3 py-2 text-xs text-ink" data-testid="hunt-notice">
          {notice}
        </div>
      )}

      <div className="rounded border border-accent/30 bg-accent/5 px-3 py-2 text-[11px] leading-relaxed text-ink-dim" data-testid="hunt-disclaimer">
        <span className="font-medium text-ink">Investigation only.</span> A hunt reads persisted
        detection / correlation / risk / intelligence / memory history and returns deterministic
        evidence, findings and a timeline. It never fabricates provenance, never mutates security
        state, and has no provider or action surface.
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Hunts" value={hunts.data?.total ?? 0} />
        <Stat label="Completed" value={completed} tone="text-low" />
        <Stat label="Failed" value={failed} tone="text-critical" />
        <Stat label="Actionable (draft)" value={actionable} tone="text-accent" />
      </div>

      <Panel
        title="New hunt"
        subtitle="Create a validated draft over a bounded window — it runs synchronously and exactly once when you trigger it."
        data-testid="hunt-create-panel"
      >
        <NewHuntForm busy={mutation.isPending} onCreate={createHunt} />
      </Panel>

      <Panel
        title="Hunts"
        subtitle="Persisted hunts, newest first — drafts can be run or cancelled; executes that exceed a bound fail with a structured error."
        padded={false}
        data-testid="hunts-panel"
      >
        <div className="flex items-center justify-between gap-3 border-b border-edge-soft px-4 py-2">
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Filter by status</div>
          <Select
            aria-label="Status filter"
            className="h-7 text-[11px]"
            value={statusFilter}
            onChange={(event) => {
              setStatusFilter(event.target.value as ThreatHuntStatus | '')
              setPage(1)
            }}
          >
            <option value="">All statuses</option>
            <option value="draft">Draft</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </Select>
        </div>
        {hunts.isLoading ? (
          <LoadingRows rows={8} />
        ) : hunts.isError ? (
          <ErrorState message={String(hunts.error)} onRetry={() => void hunts.refetch()} />
        ) : huntRows.length === 0 ? (
          <EmptyState
            title="No hunts yet"
            body="Create a draft above or through the governed API to see hunts here."
          />
        ) : (
          <>
            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Status</Th>
                  <Th>Hunt</Th>
                  <Th>Type</Th>
                  <Th>Results</Th>
                  <Th>Findings</Th>
                  <Th>Created</Th>
                  <Th />
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {huntRows.map((record) => {
                  const label = statusLabel(record.status)
                  return (
                    <TRow
                      key={record.hunt_id}
                      onClick={() => {
                        setSelectedHunt(record.hunt_id)
                        setDetailTab('findings')
                      }}
                      className="cursor-pointer"
                      data-testid="threat-hunt-row"
                    >
                      <Td>
                        <Badge tone={label.tone}>{label.label}</Badge>
                      </Td>
                      <Td className="max-w-[220px]">
                        <div className="truncate text-xs font-medium text-ink" title={record.name}>
                          {record.name}
                        </div>
                        <MonoId id={record.hunt_id} />
                      </Td>
                      <Td className="whitespace-nowrap text-[11px] text-ink-dim">
                        {huntTypeLabel(record.hunt_type)}
                      </Td>
                      <Td className="font-mono text-[11px] text-ink">{record.result_count}</Td>
                      <Td className="font-mono text-[11px] text-ink">{record.finding_count}</Td>
                      <Td className="font-mono text-[10px] text-ink-faint">
                        {formatTimestamp(record.created_at)}
                      </Td>
                      <Td className="text-right">
                        {record.status === 'draft' && (
                          <div className="flex justify-end gap-1">
                            <Button
                              size="sm"
                              disabled={mutation.isPending}
                              onClick={(event) => {
                                event.stopPropagation()
                                runHunt(record.hunt_id)
                              }}
                              data-testid={`run-${record.hunt_id}`}
                            >
                              <Play className="h-3 w-3" aria-hidden="true" />
                              Run
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={mutation.isPending}
                              onClick={(event) => {
                                event.stopPropagation()
                                cancelHunt(record.hunt_id)
                              }}
                              data-testid={`cancel-${record.hunt_id}`}
                            >
                              <Ban className="h-3 w-3" aria-hidden="true" />
                              Cancel
                            </Button>
                          </div>
                        )}
                      </Td>
                    </TRow>
                  )
                })}
              </tbody>
            </Table>
            {hunts.data && hunts.data.total > PAGE_SIZE && (
              <div className="flex items-center justify-between border-t border-edge-soft px-4 py-2 text-[11px] text-ink-dim">
                <span>
                  Page {hunts.data.page} of {Math.max(1, Math.ceil(hunts.data.total / PAGE_SIZE))} ·{' '}
                  {hunts.data.total} hunts
                </span>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                    Prev
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page >= Math.ceil(hunts.data.total / PAGE_SIZE)}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </Panel>

      <Panel
        title="Hunt detail"
        subtitle={selected ? `${selected.name} · ${selected.hunt_id}` : 'Select a hunt row to inspect its filters, findings, evidence and timeline.'}
        padded={false}
      >
        {huntDetail.isLoading ? (
          <LoadingRows rows={6} />
        ) : huntDetail.isError ? (
          <ErrorState message={String(huntDetail.error)} />
        ) : selected ? (
          <HuntDetail
            detail={selected}
            tab={detailTab}
            onTab={setDetailTab}
            findings={findings.data}
            evidence={evidence.data}
            timeline={timeline.data}
            loading={findings.isLoading || evidence.isLoading || timeline.isLoading}
          />
        ) : (
          <div className="p-4">
            <NotAvailable
              title="No hunt selected"
              body="Select a hunt from the table to inspect its structured filters and persisted run artifacts."
            />
          </div>
        )}
      </Panel>
    </div>
  )
}

function NewHuntForm({
  busy,
  onCreate,
}: {
  busy: boolean
  onCreate: (body: Parameters<typeof threatHuntingApi.create>[0]) => void
}) {
  const now = new Date()
  const [name, setName] = useState('Reconnaissance sweep')
  const [huntType, setHuntType] = useState<HuntType>('detection_review')
  const [description, setDescription] = useState('Revisit persisted detection history for the bounded window.')
  const [start, setStart] = useState(toLocalInput(new Date(now.getTime() - 24 * 60 * 60 * 1000)))
  const [end, setEnd] = useState(toLocalInput(now))

  const startValid = start !== '' && end !== '' && new Date(start).getTime() < new Date(end).getTime()

  const submit = (event: React.FormEvent): void => {
    event.preventDefault()
    if (!startValid || name.trim() === '') return
    onCreate({
      name: name.trim(),
      hunt_type: huntType,
      description: description.trim(),
      start_time: toIso(start),
      end_time: toIso(end),
      filters: [],
    })
  }

  return (
    <form
      className="flex flex-wrap items-end gap-3"
      data-testid="hunt-create-form"
      onSubmit={submit}
    >
      <div className="space-y-1">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">Name</div>
        <Input
          aria-label="Hunt name"
          className="h-8 w-56 text-[11px]"
          value={name}
          onChange={(event) => setName(event.target.value)}
        />
      </div>
      <div className="space-y-1">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">Template</div>
        <Select
          aria-label="Hunt template"
          className="h-8 text-[11px]"
          value={huntType}
          onChange={(event) => setHuntType(event.target.value as HuntType)}
        >
          {HUNT_TYPES.map((h) => (
            <option key={h.value} value={h.value}>
              {h.label}
            </option>
          ))}
        </Select>
      </div>
      <div className="space-y-1">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">Start</div>
        <Input
          aria-label="Window start"
          type="datetime-local"
          className="h-8 w-44 text-[11px] font-mono"
          value={start}
          onChange={(event) => setStart(event.target.value)}
        />
      </div>
      <div className="space-y-1">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">End</div>
        <Input
          aria-label="Window end"
          type="datetime-local"
          className="h-8 w-44 text-[11px] font-mono"
          value={end}
          onChange={(event) => setEnd(event.target.value)}
        />
      </div>
      <div className="flex gap-2">
        <Button size="sm" disabled={busy || !startValid} type="submit">
          <Plus className="h-3 w-3" aria-hidden="true" />
          Create draft
        </Button>
      </div>
      <div className="w-full">
        <Textarea
          aria-label="Hunt description"
          className="h-16 text-[11px]"
          value={description}
          onChange={(event) => setDescription(event.target.value)}
        />
      </div>
      <p className="w-full text-[11px] leading-relaxed text-ink-dim">
        Drafts are validated against the V2.19 grammar (closed fields/operators, max 8 filters,
        bounded window ≤ 720 h) before they can run. No filters selects the whole surface of the
        template within the window.
      </p>
    </form>
  )
}

function HuntDetail({
  detail,
  tab,
  onTab,
  findings,
  evidence,
  timeline,
  loading,
}: {
  detail: ThreatHuntRecord
  tab: DetailTab
  onTab: (tab: DetailTab) => void
  findings: Page<ThreatHuntFindingRecord> | undefined
  evidence: Page<ThreatHuntEvidenceRecord> | undefined
  timeline: Page<ThreatHuntTimelineItemRecord> | undefined
  loading: boolean
}) {
  const label = statusLabel(detail.status)
  return (
    <div className="space-y-0" data-testid="hunt-detail-panel">
      <div className="space-y-3 border-b border-edge-soft p-4">
        <div className="flex flex-wrap items-center gap-2 text-[11px]">
          <Badge tone={label.tone}>{label.label}</Badge>
          <span className="font-mono text-ink-dim">{huntTypeLabel(detail.hunt_type)}</span>
          <span className="text-ink-dim">window</span>
          <span className="font-mono text-ink-faint">
            {formatTimestamp(detail.start_time)} → {formatTimestamp(detail.end_time)}
          </span>
          <span className="text-ink-dim">· run by {detail.created_by_role}</span>
        </div>
        <div className="grid grid-cols-3 gap-2 text-[11px]">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-ink-faint">Evidence</div>
            <div className="mt-0.5 font-mono text-ink">{detail.result_count}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-ink-faint">Findings</div>
            <div className="mt-0.5 font-mono text-ink">{detail.finding_count}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-wider text-ink-faint">Timeline</div>
            <div className="mt-0.5 font-mono text-ink">{detail.timeline_count}</div>
          </div>
        </div>
        {detail.description && <p className="text-[11px] text-ink-dim">{detail.description}</p>}
        {detail.filters.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {detail.filters.map((filter, index) => (
              <span key={`${filter.field}-${index}`} className="rounded border border-edge-soft bg-surface-2 px-2 py-0.5 font-mono text-[10px] text-ink-dim">
                {filter.field} {filter.operator}{' '}
                <span className="text-ink">{filter.values?.join(', ') ?? filter.value ?? '—'}</span>
              </span>
            ))}
          </div>
        )}
        {detail.error_code && (
          <div className="rounded border border-critical/30 bg-critical/5 px-2 py-1 font-mono text-[10px] text-critical" data-testid="hunt-error">
            {detail.error_code}: {detail.error_message}
          </div>
        )}
      </div>

      {detail.status === 'completed' && (
        <div className="flex gap-1 border-b border-edge-soft px-4 py-2" data-testid="hunt-tabs">
          {(['findings', 'evidence', 'timeline'] as DetailTab[]).map((name) => (
            <Button
              key={name}
              size="sm"
              variant={tab === name ? 'default' : 'outline'}
              onClick={() => onTab(name)}
            >
              {name}
            </Button>
          ))}
        </div>
      )}

      <div className="p-4">
        {detail.status !== 'completed' ? (
          <NotAvailable
            title="No run artifacts"
            body="Evidence, findings and timeline appear once the hunt has completed within bounds."
          />
        ) : loading ? (
          <LoadingRows rows={5} />
        ) : tab === 'findings' ? (
          <FindingsTable records={findings?.items ?? []} total={findings?.total ?? 0} />
        ) : tab === 'evidence' ? (
          <EvidenceTable records={evidence?.items ?? []} total={evidence?.total ?? 0} />
        ) : (
          <TimelineTable records={timeline?.items ?? []} total={timeline?.total ?? 0} />
        )}
      </div>
    </div>
  )
}

function FindingsTable({ records, total }: { records: ThreatHuntFindingRecord[]; total: number }) {
  return (
    <div data-testid="hunt-findings">
      {records.length === 0 ? (
        <EmptyState title="No findings" body="The run produced no finding groups — only the summary shows when evidence is collected." />
      ) : (
        <Table>
          <thead>
            <tr className="border-b border-edge">
              <Th>Finding</Th>
              <Th>Severity</Th>
              <Th>Provenance</Th>
              <Th>Evidence refs</Th>
              <Th>Observed</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-edge-soft">
            {records.map((record) => (
              <TRow key={record.finding_id} data-testid="hunt-finding-row">
                <Td className="max-w-[240px]">
                  <span className="block truncate text-xs font-medium text-ink" title={record.title}>
                    {record.title}
                  </span>
                  <span className="block truncate text-[10px] text-ink-faint" title={record.description}>
                    {record.description}
                  </span>
                </Td>
                <Td>
                  {record.severity ? <Badge tone="medium">{record.severity}</Badge> : <span className="text-[10px] text-ink-faint">—</span>}
                </Td>
                <Td className="font-mono text-[10px] text-ink-dim">{record.provenance}</Td>
                <Td className="font-mono text-[10px] text-ink-dim">{record.evidence_ids.length}</Td>
                <Td className="font-mono text-[10px] text-ink-faint">
                  {record.observed_at ? formatTimestamp(record.observed_at) : '—'}
                </Td>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
      <div className="mt-2 text-[10px] uppercase tracking-wider text-ink-faint">{total} total findings</div>
    </div>
  )
}

function EvidenceTable({ records, total }: { records: ThreatHuntEvidenceRecord[]; total: number }) {
  return (
    <div data-testid="hunt-evidence">
      {records.length === 0 ? (
        <EmptyState title="No evidence" body="The run matched no persisted records within the window." />
      ) : (
        <Table>
          <thead>
            <tr className="border-b border-edge">
              <Th>Type</Th>
              <Th>Provenance</Th>
              <Th>Severity</Th>
              <Th>Summary</Th>
              <Th>Observed</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-edge-soft">
            {records.map((record) => (
              <TRow key={record.evidence_id} data-testid="hunt-evidence-row">
                <Td>
                  <Badge tone="accent">{record.evidence_type}</Badge>
                </Td>
                <Td className="font-mono text-[10px] text-ink-dim">{record.provenance}</Td>
                <Td>
                  {record.severity ? <Badge tone="medium">{record.severity}</Badge> : <span className="text-[10px] text-ink-faint">—</span>}
                </Td>
                <Td className="max-w-[260px]">
                  <span className="block truncate text-[11px] text-ink-dim" title={record.summary}>
                    {record.summary}
                  </span>
                </Td>
                <Td className="font-mono text-[10px] text-ink-faint">
                  {record.observed_at ? formatTimestamp(record.observed_at) : '—'}
                </Td>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
      <div className="mt-2 text-[10px] uppercase tracking-wider text-ink-faint">{total} total evidence items</div>
    </div>
  )
}

function TimelineTable({ records, total }: { records: ThreatHuntTimelineItemRecord[]; total: number }) {
  return (
    <div data-testid="hunt-timeline">
      {records.length === 0 ? (
        <EmptyState title="No timeline" body="The run collected no chronology to display." />
      ) : (
        <Table>
          <thead>
            <tr className="border-b border-edge">
              <Th>Observed</Th>
              <Th>Kind</Th>
              <Th>Summary</Th>
              <Th>Provenance</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-edge-soft">
            {records.map((record) => (
              <TRow key={record.timeline_item_id} data-testid="hunt-timeline-row">
                <Td className="whitespace-nowrap font-mono text-[10px] text-ink-faint">
                  {record.observed_at ? formatTimestamp(record.observed_at) : '—'}
                </Td>
                <Td>
                  <Badge tone="accent">{record.evidence_type}</Badge>
                </Td>
                <Td className="max-w-[300px]">
                  <span className="block truncate text-[11px] text-ink-dim" title={record.evidence_summary}>
                    {record.evidence_summary}
                  </span>
                </Td>
                <Td className="font-mono text-[10px] text-ink-dim">{record.provenance}</Td>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
      <div className="mt-2 text-[10px] uppercase tracking-wider text-ink-faint">{total} total timeline items</div>
    </div>
  )
}