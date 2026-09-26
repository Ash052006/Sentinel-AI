import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { detectionRulesApi, type AnalyticsWindow } from '../api/detectionRules'
import { detectionsApi } from '../api/detections'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { RuleTypeBadge, SeverityBadge } from '../components/badges'
import { Badge } from '../components/ui/badge'
import { MonoId } from '../components/ui/mono-id'
import { Input, Select } from '../components/ui/input'
import { formatTimestamp, shorten } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'
import type {
  DetectionRule,
  DetectionSeverity,
  RuleType,
} from '../types/api'

interface FilterState {
  query: string
  ruleType: 'all' | RuleType
  severity: 'all' | DetectionSeverity
  status: 'all' | 'enabled' | 'disabled'
}

const WINDOWS: Array<{ value: AnalyticsWindow; label: string }> = [
  { value: '1h', label: 'Last 1h' },
  { value: '6h', label: 'Last 6h' },
  { value: '24h', label: 'Last 24h' },
  { value: '7d', label: 'Last 7d' },
  { value: '30d', label: 'Last 30d' },
]

const SEVERITY_ORDER: Record<DetectionSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

function matchFilters(rule: DetectionRule, filters: FilterState): boolean {
  if (filters.ruleType !== 'all' && rule.rule_type !== filters.ruleType) return false
  if (filters.severity !== 'all' && rule.severity !== filters.severity) return false
  if (filters.status !== 'all') {
    const enabled = rule.enabled
    if (filters.status === 'enabled' && !enabled) return false
    if (filters.status === 'disabled' && enabled) return false
  }
  if (filters.query.trim()) {
    const needle = filters.query.trim().toLowerCase()
    const haystack = `${rule.name} ${rule.rule_id} ${rule.category ?? ''} ${rule.source_file ?? ''}`.toLowerCase()
    if (!haystack.includes(needle)) return false
  }
  return true
}

function bucketLabel(iso: string, window: AnalyticsWindow): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  if (window === '1h' || window === '6h' || window === '24h') {
    return date.toISOString().slice(11, 16)
  }
  return date.toISOString().slice(5, 10)
}

export function DetectionRulesPage() {
  const [filters, setFilters] = useState<FilterState>({
    query: '',
    ruleType: 'all',
    severity: 'all',
    status: 'all',
  })
  const [window, setWindow] = useState<AnalyticsWindow>('30d')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const rules = useQuery({
    queryKey: ['detection-rules'],
    queryFn: () => detectionRulesApi.list(),
  })

  const analytics = useQuery({
    queryKey: ['detection-rules', 'analytics', window],
    queryFn: () => detectionRulesApi.analytics(window),
  })

  const selected = useQuery({
    queryKey: ['detection-rules', 'detail', selectedId],
    queryFn: () => detectionRulesApi.get(selectedId as string),
    enabled: selectedId !== null,
  })

  const recent = useQuery({
    queryKey: ['detections', 'recent', 10],
    queryFn: () => detectionsApi.recent(10),
  })

  const rulesData = useMemo(() => rules.data ?? [], [rules.data])
  const rows = useMemo(
    () => rulesData.filter((rule) => matchFilters(rule, filters)),
    [rulesData, filters],
  )
  rows.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.source_file?.localeCompare(b.source_file ?? '') ||
      a.rule_id.localeCompare(b.rule_id),
  )

  const sigmaTotal = rulesData.filter((r) => r.rule_type === 'sigma').length
  const yaraTotal = rulesData.filter((r) => r.rule_type === 'yara').length
  const enabledTotal = rulesData.filter((r) => r.enabled).length
  const disabledTotal = rulesData.filter((r) => !r.enabled).length
  const matchTotal = rulesData.reduce((sum, r) => sum + r.match_count, 0)
  const matchedRules = rulesData.filter((r) => r.match_count > 0).length

  const activity = (analytics.data?.buckets ?? []).map((bucket) => ({
    label: bucketLabel(bucket.bucket_start, window),
    detections: bucket.detections,
  }))
  const severityData = (analytics.data?.by_severity ?? []).slice().sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  )

  const detail = selected.data

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Detection Rules"
        description="Repository Sigma + YARA rule set loaded by the Step 26 engine. Match stats are real persisted detections — rules that never matched report 0."
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Total rules" value={rulesData.length} />
        <Stat label="Sigma" value={sigmaTotal} />
        <Stat label="YARA" value={yaraTotal} />
        <Stat label="Enabled" value={enabledTotal} />
        <Stat label="Disabled" value={disabledTotal} />
        <Stat label="Matches" value={matchTotal} tone="text-accent" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel
          title="Rule table"
          subtitle={`${rows.length} of ${rulesData.length} loaded rules · rules with persisted matches: ${matchedRules}`}
          padded={false}
          className="xl:col-span-2"
          action={
            <div className="flex flex-wrap items-center gap-2">
              <Input
                aria-label="Search rules"
                placeholder="Search name, id, category…"
                className="h-7 w-48 text-[11px]"
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
                    ruleType: event.target.value as FilterState['ruleType'],
                  }))
                }
              >
                <option value="all">All types</option>
                <option value="sigma">Sigma</option>
                <option value="yara">YARA</option>
              </Select>
              <Select
                aria-label="Filter by severity"
                className="h-7 text-[11px]"
                value={filters.severity}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    severity: event.target.value as FilterState['severity'],
                  }))
                }
              >
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </Select>
              <Select
                aria-label="Filter by status"
                className="h-7 text-[11px]"
                value={filters.status}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    status: event.target.value as FilterState['status'],
                  }))
                }
              >
                <option value="all">All statuses</option>
                <option value="enabled">Enabled</option>
                <option value="disabled">Disabled</option>
              </Select>
            </div>
          }
        >
          {rules.isLoading ? (
            <LoadingRows rows={10} />
          ) : rules.isError ? (
            <ErrorState message={String(rules.error)} onRetry={() => rules.refetch()} />
          ) : rows.length === 0 ? (
            <EmptyState
              title="No matching rules"
              body="No loaded rules matched the active filters. Clear a filter to widen the view."
            />
          ) : (
            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Rule</Th>
                  <Th>ID</Th>
                  <Th>Type</Th>
                  <Th>Severity</Th>
                  <Th>Category</Th>
                  <Th>Status</Th>
                  <Th className="text-right">Matches</Th>
                  <Th>Last match</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {rows.map((rule) => (
                  <TRow
                    key={rule.rule_id}
                    onClick={() => setSelectedId(rule.rule_id)}
                    className="cursor-pointer"
                    data-testid="rule-row"
                  >
                    <Td className="max-w-[240px]">
                      <div className="truncate text-xs font-medium text-ink" title={rule.name}>
                        {rule.name}
                      </div>
                      <div className="truncate text-[10px] text-ink-faint" title={rule.description}>
                        {shorten(rule.description, 60)}
                      </div>
                    </Td>
                    <MonoCell>
                      <MonoId id={rule.rule_id} />
                    </MonoCell>
                    <Td>
                      <RuleTypeBadge ruleType={rule.rule_type} />
                    </Td>
                    <Td>
                      <SeverityBadge severity={rule.severity} />
                    </Td>
                    <Td className="font-mono text-[11px] text-ink-dim">{rule.category ?? '—'}</Td>
                    <Td>
                      {rule.enabled ? (
                        <Badge tone="low">enabled</Badge>
                      ) : (
                        <Badge tone="muted">disabled</Badge>
                      )}
                    </Td>
                    <Td className="text-right font-mono text-[11px] text-ink">{rule.match_count}</Td>
                    <Td className="text-[10px] text-ink-dim">
                      {rule.last_matched_at ? formatTimestamp(rule.last_matched_at) : 'never'}
                    </Td>
                  </TRow>
                ))}
              </tbody>
            </Table>
          )}
        </Panel>

        <Panel
          title="Rule preview"
          subtitle={detail ? detail.name : 'Select a row to inspect its definition'}
        >
          {selected.isLoading ? (
            <LoadingRows rows={8} />
          ) : selected.isError ? (
            <ErrorState message={String(selected.error)} />
          ) : detail ? (
            <div className="space-y-3" data-testid="rule-preview">
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-ink-faint">Type / status</div>
                  <div className="mt-0.5 flex items-center gap-1.5">
                    <RuleTypeBadge ruleType={detail.rule_type} />
                    <Badge tone={detail.enabled ? 'low' : 'muted'}>
                      {detail.enabled ? 'enabled' : 'disabled'}
                    </Badge>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-ink-faint">Severity</div>
                  <div className="mt-1">
                    <SeverityBadge severity={detail.severity} />
                  </div>
                </div>
                <div className="col-span-2">
                  <div className="text-[10px] uppercase tracking-wider text-ink-faint">Category</div>
                  <div className="mt-0.5 font-mono text-ink">{detail.category ?? '—'}</div>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-ink-faint">Version</div>
                  <div className="mt-0.5 font-mono text-ink">{detail.version}</div>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-ink-faint">Author</div>
                  <div className="mt-0.5 text-ink">{detail.author ?? '—'}</div>
                </div>
                <div className="col-span-2">
                  <div className="text-[10px] uppercase tracking-wider text-ink-faint">Source file</div>
                  <div className="mt-0.5 font-mono text-[11px] text-ink-dim">
                    {detail.source_file ?? '—'}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-ink-faint">Matches</div>
                  <div className="mt-0.5 font-mono text-ink">{detail.match_count}</div>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-ink-faint">Last match</div>
                  <div className="mt-0.5 font-mono text-[10px] text-ink-dim">
                    {detail.last_matched_at ? formatTimestamp(detail.last_matched_at) : 'never'}
                  </div>
                </div>
                {detail.tags.length > 0 && (
                  <div className="col-span-2">
                    <div className="text-[10px] uppercase tracking-wider text-ink-faint">Tags</div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {detail.tags.map((tag) => (
                        <Badge key={tag} tone="muted">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <div>
                <div className="mb-1 text-[10px] uppercase tracking-wider text-ink-faint">
                  Definition
                </div>
                <pre className="max-h-72 overflow-auto rounded-md border border-edge bg-surface-0 p-3 font-mono text-[10px] leading-relaxed text-ink-dim">
                  {detail.content}
                </pre>
              </div>
            </div>
          ) : (
            <NotAvailable
              title="No rule selected"
              body="Click any row in the rule table to inspect its definition, provenance, and real match statistics here."
            />
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel
          title="Detection activity"
          subtitle={`Persisted detections in the ${window} window`}
          padded={false}
          action={
            <Select
              aria-label="Analytics window"
              className="h-7 text-[11px]"
              value={window}
              onChange={(event) => setWindow(event.target.value as AnalyticsWindow)}
            >
              {WINDOWS.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </Select>
          }
        >
          {analytics.isLoading ? (
            <LoadingRows rows={6} />
          ) : analytics.isError ? (
            <ErrorState message={String(analytics.error)} onRetry={() => analytics.refetch()} />
          ) : activity.length === 0 ? (
            <EmptyState
              title="Historical match data unavailable"
              body={`No persisted detection rows fall inside the ${window} window. Counts are never fabricated.`}
            />
          ) : (
            <div className="h-56" data-testid="activity-chart">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={activity} margin={{ top: 12, right: 12, left: 0, bottom: 0 }}>
                  <CartesianGrid stroke="#1a222c" vertical={false} />
                  <XAxis
                    dataKey="label"
                    tick={{ fill: '#5a6575', fontSize: 10 }}
                    tickLine={false}
                    axisLine={{ stroke: '#232d3a' }}
                  />
                  <YAxis
                    allowDecimals={false}
                    width={32}
                    tick={{ fill: '#5a6575', fontSize: 10 }}
                    tickLine={false}
                    axisLine={{ stroke: '#232d3a' }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#10151c',
                      border: '1px solid #232d3a',
                      fontSize: 11,
                      borderRadius: 6,
                    }}
                  />
                  <Bar dataKey="detections" name="detections" fill="#4cc2ff" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>

        <Panel
          title="Matches by severity"
          subtitle={`Persisted matches in the ${window} window`}
          padded={false}
        >
          {analytics.isLoading ? (
            <LoadingRows rows={6} />
          ) : analytics.isError ? (
            <ErrorState message={String(analytics.error)} onRetry={() => analytics.refetch()} />
          ) : severityData.every((item) => item.count === 0) ? (
            <EmptyState
              title="No match data"
              body="No persisted matching rows in the selected window. Loaded repository rules have not matched yet, so counts are honestly zero."
            />
          ) : (
            <div className="h-56" data-testid="severity-chart">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} margin={{ top: 12, right: 12, left: 0, bottom: 0 }}>
                  <CartesianGrid stroke="#1a222c" vertical={false} />
                  <XAxis
                    dataKey="severity"
                    tick={{ fill: '#5a6575', fontSize: 10 }}
                    tickLine={false}
                    axisLine={{ stroke: '#232d3a' }}
                  />
                  <YAxis
                    allowDecimals={false}
                    width={32}
                    tick={{ fill: '#5a6575', fontSize: 10 }}
                    tickLine={false}
                    axisLine={{ stroke: '#232d3a' }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#10151c',
                      border: '1px solid #232d3a',
                      fontSize: 11,
                      borderRadius: 6,
                    }}
                  />
                  <Bar dataKey="count" name="matches" fill="#ff9f43" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>
      </div>

      <Panel
        title="Recent persisted detections"
        subtitle="Newest rows from the detection query layer"
        padded={false}
      >
        {recent.isLoading ? (
          <LoadingRows rows={6} />
        ) : recent.isError ? (
          <ErrorState message={String(recent.error)} onRetry={() => recent.refetch()} />
        ) : (recent.data ?? []).length === 0 ? (
          <EmptyState title="No detections" body="The recent feed is empty." />
        ) : (
          <Table>
            <thead>
              <tr className="border-b border-edge">
                <Th>Detection</Th>
                <Th>Rule</Th>
                <Th>Severity</Th>
                <Th>Detected at</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge-soft">
              {(recent.data ?? []).map((det) => (
                <TRow key={det.id}>
                  <MonoCell>
                    <MonoId id={det.detection_id} />
                  </MonoCell>
                  <MonoCell>
                    <MonoId id={det.rule_id} />
                  </MonoCell>
                  <Td>
                    <SeverityBadge severity={det.severity} />
                  </Td>
                  <Td className="text-xs text-ink-dim">{formatTimestamp(det.detected_at)}</Td>
                </TRow>
              ))}
            </tbody>
          </Table>
        )}
      </Panel>
    </div>
  )
}