import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { BookKey, ShieldAlert } from 'lucide-react'
import { Panel, Separator } from '../../components/ui/card'
import { Badge } from '../../components/ui/badge'
import { Button } from '../../components/ui/button'
import {
  CorrelationStatusBadge,
  RiskLevelBadge,
  RuleTypeBadge,
  SeverityBadge,
} from '../../components/badges'
import { MonoId } from '../../components/ui/mono-id'
import { ConfidenceBar, ScoreBar } from '../../components/ui/progress'
import { EmptyState, ErrorState, LoadingRows } from '../../components/states'
import { TBody, Td, Th, TRow, Table, MonoCell } from '../../components/ui/table'
import { formatDateTime } from '../../lib/formats'
import { approvalsApi } from '../../api/approvals'
import { useAuthStore } from '../../store/auth'
import {
  BUCKET_MS,
  buildActivitySeries,
  buildDailyFallbackSeries,
  hasSufficientSeries,
  nonEmptyBuckets,
  seriesTotals,
  TIME_WINDOWS,
  WINDOW_LABEL,
  type TimeWindow,
} from '../../lib/aggregation'
import { cn } from '../../lib/utils'
import type {
  ApprovalRecord,
  CorrelationResult,
  DetectionResult,
  RiskAssessment,
  RiskLevel,
} from '../../types/api'
import type { LevelCounts, RulesSummary } from './dashboard-data'
import {
  ACTIVITY_ROWS,
  APPROVAL_SOC_ROLES,
  APPROVALS_LIMIT,
  APPROVALS_PENDING_KEY,
  EVENT_ROWS,
  INCIDENT_ROWS,
} from './dashboard-data'

function humanizeSpan(ms: number): string {
  const minutes = Math.round(ms / 60_000)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.round(ms / 3_600_000)
  if (hours < 24) return `${hours}h`
  return `${Math.round(hours / 24)}d`
}

// ---------------------------------------------------------------------------
// KPI strip — compact, honest, never reports a feed page size as a total.
// ---------------------------------------------------------------------------

const levelText: Record<RiskLevel, string> = {
  critical: 'text-critical',
  high: 'text-high',
  medium: 'text-medium',
  low: 'text-low',
}

const levelBg: Record<RiskLevel, string> = {
  critical: 'bg-critical',
  high: 'bg-high',
  medium: 'bg-medium',
  low: 'bg-low',
}

const LEVEL_ORDER: RiskLevel[] = ['critical', 'high', 'medium', 'low']

interface KpiCellDef {
  label: string
  value: number | string
  sub: string
  tone?: string
  testId?: string
}

export function KpiStrip({
  className,
  loading,
  activeIncidents,
  byLevel,
  detections30d,
  correlationCount,
  riskCount,
  memoryIndicators,
}: {
  className?: string
  loading: boolean
  activeIncidents: number
  byLevel: LevelCounts
  detections30d: number | null
  correlationCount: number
  riskCount: number
  memoryIndicators: number
}) {
  const cells: KpiCellDef[] = [
    { label: 'Active incidents', value: activeIncidents, sub: 'risk + correlation join' },
    { label: 'Critical', value: byLevel.critical, sub: 'bounded risk feed', tone: levelText.critical },
    { label: 'High', value: byLevel.high, sub: 'bounded risk feed', tone: levelText.high },
    { label: 'Low', value: byLevel.low, sub: 'bounded risk feed', tone: levelText.low },
    {
      label: 'Detections · 30d',
      value: loading ? '…' : (detections30d ?? '—'),
      sub: 'persisted aggregate',
    },
    {
      label: 'Correlations',
      value: loading ? '…' : correlationCount,
      sub: loading ? 'loading feed…' : `recent feed — ${correlationCount} loaded`,
      testId: 'kpi-correlations',
    },
    {
      label: 'Risk assessments',
      value: loading ? '…' : riskCount,
      sub: loading ? 'loading feed…' : `recent feed — ${riskCount} loaded`,
      testId: 'kpi-risk',
    },
    {
      label: 'Threat indicators',
      value: loading ? '…' : memoryIndicators,
      sub: 'from incident memories',
    },
    { label: 'Response actions', value: loading ? '…' : 0, sub: 'none · simulated only' },
  ]

  return (
    <section
      className={cn('grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5 xl:grid-cols-9', className)}
      data-testid="kpi-strip"
    >
      {cells.map((cell) => (
        <div
          key={cell.label}
          data-testid={cell.testId ?? 'kpi-cell'}
          className="min-w-0 rounded-md border border-edge bg-surface-1 px-3 py-2"
        >
          <div className="truncate text-[10px] font-semibold uppercase tracking-wider text-ink-dim">
            {cell.label}
          </div>
          <div
            className={cn('mt-1 font-mono text-lg leading-none', cell.tone ?? 'text-ink')}
            data-testid="kpi-value"
          >
            {cell.value}
          </div>
          <div className="mt-1 truncate text-[10px] text-ink-faint">{cell.sub}</div>
        </div>
      ))}
    </section>
  )
}

// ---------------------------------------------------------------------------
// Security activity — real chronological bucketing with an honest
// "insufficient historical data" fallback.
// ---------------------------------------------------------------------------

const SERIES = [
  { key: 'detections' as const, label: 'Detections', color: '#4cc2ff' },
  { key: 'correlations' as const, label: 'Correlations', color: '#ff9f43' },
  { key: 'risk' as const, label: 'Risk assessments', color: '#ffd166' },
]

function tooltipStyle() {
  return {
    backgroundColor: '#10151c',
    border: '1px solid #232d3a',
    fontSize: 11,
    borderRadius: 6,
  }
}

function ActivityBars({
  data,
}: {
  data: Array<{ label: string; detections: number; correlations: number; risk: number }>
}) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={data} margin={{ top: 10, right: 12, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1a222c" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fill: '#5a6575', fontSize: 10 }}
          tickLine={false}
          axisLine={{ stroke: '#232d3a' }}
          interval="preserveStartEnd"
          minTickGap={28}
        />
        <YAxis
          allowDecimals={false}
          width={34}
          tick={{ fill: '#5a6575', fontSize: 10 }}
          tickLine={false}
          axisLine={{ stroke: '#232d3a' }}
        />
        <Tooltip
          contentStyle={tooltipStyle()}
          labelStyle={{ color: '#8994a4' }}
          cursor={{ fill: 'rgba(76,194,255,0.06)' }}
        />
        {SERIES.map((item) => (
          <Bar
            key={item.key}
            dataKey={item.key}
            name={item.label}
            fill={item.color}
            radius={[2, 2, 0, 0]}
            maxBarSize={14}
          />
        ))}
      </BarChart>
    </ResponsiveContainer>
  )
}

export function SecurityActivityPanel({
  detectionFeed,
  correlationFeed,
  riskFeed,
  loading,
  hasError,
  onRetry,
  className,
}: {
  detectionFeed: DetectionResult[]
  correlationFeed: CorrelationResult[]
  riskFeed: RiskAssessment[]
  loading: boolean
  hasError: boolean
  onRetry: () => void
  className?: string
}) {
  const [window, setWindow] = useState<TimeWindow>('30d')

  const input = useMemo(
    () => ({
      detections: detectionFeed.map((item) => item.detected_at),
      correlations: correlationFeed.map((item) => item.timestamp),
      risk: riskFeed.map((item) => item.timestamp),
    }),
    [detectionFeed, correlationFeed, riskFeed],
  )

  const series = useMemo(() => buildActivitySeries(input, window), [input, window])
  const sufficient = hasSufficientSeries(series)
  const nonEmpty = nonEmptyBuckets(series)
  const daily = useMemo(() => buildDailyFallbackSeries(input), [input])
  const dailyTotals = useMemo(() => seriesTotals(daily), [daily])

  return (
    <Panel
      title="Security activity"
      subtitle="Detection, correlation and risk activity over time · bucketed from bounded recent feeds (limit 200 each)"
      className={cn('xl:col-span-8', className)}
      padded={false}
      action={
        <div className="flex items-center gap-1" data-testid="activity-window">
          {TIME_WINDOWS.map((option) => (
            <button
              key={option}
              type="button"
              onClick={() => setWindow(option)}
              aria-pressed={window === option}
              data-testid={`window-${option}`}
              className={cn(
                'h-6 rounded border px-2 font-mono text-[10px] uppercase transition-colors',
                window === option
                  ? 'border-accent/40 bg-accent/10 text-accent'
                  : 'border-edge bg-surface-0 text-ink-faint hover:text-ink',
              )}
            >
              {WINDOW_LABEL[option]}
            </button>
          ))}
        </div>
      }
    >
      <div className="flex items-center justify-between gap-3 border-b border-edge-soft px-4 py-2">
        <span className="text-[11px] text-ink-faint">
          Trailing {WINDOW_LABEL[window]} window ·{' '}
          {humanizeSpan(BUCKET_MS[window])} buckets
        </span>
        <span className="flex items-center gap-3">
          {SERIES.map((item) => (
            <span key={item.key} className="inline-flex items-center gap-1 text-[10px] text-ink-dim">
              <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: item.color }} />
              {item.label}
            </span>
          ))}
        </span>
      </div>

      {loading ? (
        <div className="p-4">
          <LoadingRows rows={6} />
        </div>
      ) : hasError ? (
        <ErrorState
          message="Security activity feeds are unavailable."
          onRetry={onRetry}
        />
      ) : sufficient && series.length > 0 ? (
        <>
          <div className="h-64 p-2">
            <ActivityBars data={series} />
          </div>
          <div className="border-t border-edge-soft px-4 py-1.5 text-right text-[10px] text-ink-faint">
            {nonEmpty} distinct time buckets in the {WINDOW_LABEL[window]} window
          </div>
        </>
      ) : (
        <div data-testid="insufficient-data" className="flex flex-col gap-2 p-4 text-center">
          <div className="text-xs font-medium text-ink-dim">Insufficient historical data</div>
          <div className="mx-auto max-w-lg text-[11px] leading-relaxed text-ink-faint">
            The {WINDOW_LABEL[window]} window contains only{' '}
            {nonEmpty} distinct time bucket{nonEmpty === 1 ? '' : 's'} from the bounded feeds — not
            enough to draw a meaningful series. Below is the full observed sample bucketed by day
            instead, sorted chronologically.
          </div>
          {daily.length > 1 ? (
            <>
              <div className="h-56">
                <ActivityBars data={daily} />
              </div>
              <div className="text-[10px] text-ink-faint">
                Full observed sample · detections {dailyTotals.detections} · correlations{' '}
                {dailyTotals.correlations} · risk {dailyTotals.risk}
              </div>
            </>
          ) : (
            <div className="text-[10px] text-ink-faint">
              The bounded feeds contain too few distinct timestamps to draw any chronological
              series.
            </div>
          )}
        </div>
      )}
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// Risk overview — real level distribution from the bounded risk feed.
// ---------------------------------------------------------------------------

export function RiskOverviewPanel({
  riskFeed,
  loading,
  hasError,
  onRetry,
  className,
}: {
  riskFeed: RiskAssessment[]
  loading: boolean
  hasError: boolean
  onRetry: () => void
  className?: string
}) {
  const counts = useMemo(() => {
    const out: Record<RiskLevel, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const risk of riskFeed) out[risk.level] += 1
    return out
  }, [riskFeed])
  const total = riskFeed.length

  return (
    <Panel
      title="Risk overview"
      subtitle={`Level distribution within the bounded risk feed (${loading ? '…' : `${total} sampled`})`}
      className={className}
      padded={false}
    >
      {loading ? (
        <LoadingRows rows={5} />
      ) : hasError ? (
        <ErrorState message="Risk data is unavailable." onRetry={onRetry} />
      ) : total === 0 ? (
        <EmptyState title="No risk assessments" body="The bounded risk feed is empty." />
      ) : (
        <dl className="space-y-2.5 p-4">
          {LEVEL_ORDER.map((level) => {
            const count = counts[level]
            const pct = total > 0 ? ((count / total) * 100).toFixed(0) : '0'
            return (
              <div key={level} data-testid="risk-level">
                <div className="flex items-center justify-between gap-2">
                  <dt className={cn('text-[11px] font-semibold uppercase tracking-wider', levelText[level])}>
                    {level}
                  </dt>
                  <dd className="font-mono text-[11px] text-ink-dim">
                    {count} · {pct}%
                  </dd>
                </div>
                <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-surface-3">
                  <div
                    className={cn('h-full rounded-full', levelBg[level])}
                    style={{ width: `${total > 0 ? (count / total) * 100 : 0}%` }}
                  />
                </div>
              </div>
            )
          })}
          <div className="border-t border-edge-soft pt-2 text-[10px] text-ink-faint">
            Percentages are shares of the bounded feed ({total} assessed records), not full history.
          </div>
        </dl>
      )}
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// Detection rules — compact repository summary from the live rules API.
// ---------------------------------------------------------------------------

export function RulesSummaryPanel({
  summary,
  loading,
  hasError,
  className,
}: {
  summary: RulesSummary
  loading: boolean
  hasError: boolean
  className?: string
}) {
  return (
    <Panel title="Detection rules" subtitle="Registered repository (live rule API)" className={className} padded={false}>
      <div className="grid grid-cols-2 gap-2 p-4">
        {[
          { label: 'Total', value: summary.total },
          { label: 'Sigma', value: summary.sigma },
          { label: 'YARA', value: summary.yara },
          { label: 'Enabled', value: summary.enabled },
        ].map((item) => (
          <div key={item.label} className="rounded-md border border-edge-soft bg-surface-0 px-3 py-2">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-dim">
              {item.label}
            </div>
            <div className="mt-0.5 font-mono text-base leading-none text-ink">
              {loading ? '…' : hasError ? '—' : item.value}
            </div>
            {item.label === 'Enabled' && (
              <div className="mt-1 text-[10px] text-ink-faint">{summary.disabled} disabled</div>
            )}
          </div>
        ))}
      </div>
      <div className="border-t border-edge-soft px-4 py-2 text-right">
        <Link to="/detection-rules" className="text-[11px] font-medium text-accent hover:underline">
          VIEW RULES →
        </Link>
      </div>
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// Incidents — the largest table on the dashboard (correlation + risk join).
// ---------------------------------------------------------------------------

export function IncidentsPanel({
  incidentRows,
  activeIncidents,
  byLevel,
  newestDataAt,
  loading,
  hasError,
  onRetry,
  className,
}: {
  incidentRows: Array<{ risk: RiskAssessment; correlation: CorrelationResult | null }>
  activeIncidents: number
  byLevel: LevelCounts
  newestDataAt: number
  loading: boolean
  hasError: boolean
  onRetry: () => void
  className?: string
}) {
  const navigate = useNavigate()
  const highest = incidentRows.length > 0 ? incidentRows[0]! : null
  const newestIncidentAt =
    incidentRows.length > 0
      ? incidentRows.reduce((max, row) => (row.risk.timestamp > max ? row.risk.timestamp : max), '')
      : null

  const overview = [
    { label: 'Active incidents', value: String(activeIncidents) },
    {
      label: 'Critical incidents',
      value: String(byLevel.critical),
    },
    {
      label: 'Newest incident',
      value: newestIncidentAt ? formatDateTime(newestIncidentAt) : '—',
    },
    {
      label: 'Highest risk',
      value: highest ? `${highest.risk.level.toUpperCase()} ${highest.risk.score.toFixed(2)}` : '—',
    },
    {
      label: 'Last activity',
      value: newestDataAt > 0 ? formatDateTime(new Date(newestDataAt).toISOString()) : 'Unavailable',
    },
  ]

  return (
    <Panel
      title="Active incidents"
      subtitle="Correlation + risk assessments from bounded feeds (limit 200 each) · click a row to inspect"
      className={cn('xl:col-span-8', className)}
      padded={false}
      action={
        <Link to="/incidents" className="text-[11px] font-medium uppercase tracking-wide text-accent hover:underline">
          View all →
        </Link>
      }
    >
      <div className="grid grid-cols-2 gap-x-3 gap-y-2 border-b border-edge-soft px-4 py-2 lg:grid-cols-5">
        {overview.map((item) => (
          <div key={item.label}>
            <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-dim">
              {item.label}
            </div>
            <div className="mt-0.5 truncate font-mono text-xs text-ink" title={item.value}>
              {item.value}
            </div>
          </div>
        ))}
      </div>

      {loading ? (
        <LoadingRows rows={8} />
      ) : hasError ? (
        <ErrorState message="Incident data is unavailable." onRetry={onRetry} />
      ) : incidentRows.length === 0 ? (
        <EmptyState
          title="No incidents"
          body="No risk assessments exist in the bounded recent feed."
        />
      ) : (
        <Table>
          <thead className="bg-surface-2">
            <tr>
              <Th>Incident / Correlation</Th>
              <Th>Risk</Th>
              <Th>Score</Th>
              <Th>Confidence</Th>
              <Th>Detections</Th>
              <Th>Events</Th>
              <Th>Last seen</Th>
              <Th>Status</Th>
            </tr>
          </thead>
          <TBody>
            {incidentRows.slice(0, INCIDENT_ROWS).map((row) => {
              const members = row.correlation?.members ?? []
              const events = new Set(members.map((member) => member.event_id)).size
              return (
                <TRow
                  key={row.risk.id}
                  data-testid="incident-row"
                  onClick={() => navigate(`/incidents/${row.risk.correlation_id}`)}
                >
                  <MonoCell>
                    <Link
                      to={`/incidents/${row.risk.correlation_id}`}
                      onClick={(event) => event.stopPropagation()}
                      className="text-accent hover:underline"
                    >
                      inspect
                    </Link>
                    <span className="mx-1 text-ink-faint">·</span>
                    <MonoId id={row.risk.correlation_id} />
                  </MonoCell>
                  <Td>
                    <RiskLevelBadge level={row.risk.level} />
                  </Td>
                  <Td>
                    <ScoreBar value={row.risk.score} />
                  </Td>
                  <Td>
                    <ConfidenceBar value={row.risk.confidence} />
                  </Td>
                  <Td>{row.correlation ? members.length : '—'}</Td>
                  <Td>{row.correlation ? events : '—'}</Td>
                  <Td className="text-xs text-ink-dim">
                    {formatDateTime(row.correlation?.timestamp ?? row.risk.timestamp)}
                  </Td>
                  <Td>
                    {row.correlation ? (
                      <CorrelationStatusBadge status={row.correlation.status} />
                    ) : (
                      <span className="text-[11px] text-ink-faint">—</span>
                    )}
                  </Td>
                </TRow>
              )
            })}
          </TBody>
        </Table>
      )}
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// Recent detections — compact overview, never the full feed.
// ---------------------------------------------------------------------------

export function RecentDetectionsPanel({
  detectionFeed,
  loading,
  hasError,
  onRetry,
  className,
}: {
  detectionFeed: DetectionResult[]
  loading: boolean
  hasError: boolean
  onRetry: () => void
  className?: string
}) {
  return (
    <Panel
      title="Recent detections"
      subtitle={`Newest ${loading ? '…' : detectionFeed.length} persisted matches (bounded feed)`}
      className={cn('xl:col-span-6', className)}
      padded={false}
      action={
        <Link to="/detections" className="text-[11px] font-medium uppercase tracking-wide text-accent hover:underline">
          View all →
        </Link>
      }
    >
      {loading ? (
        <LoadingRows rows={7} />
      ) : hasError ? (
        <ErrorState message="Detection data is unavailable." onRetry={onRetry} />
      ) : detectionFeed.length === 0 ? (
        <EmptyState title="No detections" body="The bounded recent detection feed is empty." />
      ) : (
        <Table>
          <thead className="bg-surface-2">
            <tr>
              <Th>Time</Th>
              <Th>Rule</Th>
              <Th>Severity</Th>
              <Th>Confidence</Th>
              <Th>Source</Th>
            </tr>
          </thead>
          <TBody>
            {detectionFeed.slice(0, ACTIVITY_ROWS).map((item) => (
              <TRow key={item.id} data-testid="detection-row">
                <Td className="whitespace-nowrap text-xs text-ink-dim" title={formatDateTime(item.detected_at)}>
                  {formatDateTime(item.detected_at)}
                </Td>
                <Td>
                  <span data-mono className="text-[11px] text-ink" title={item.rule_id}>
                    {item.rule_id}
                  </span>
                </Td>
                <Td>
                  <SeverityBadge severity={item.severity} />
                </Td>
                <Td>
                  <ConfidenceBar value={item.confidence} />
                </Td>
                <Td>
                  <RuleTypeBadge ruleType={item.rule_type} />
                </Td>
              </TRow>
            ))}
          </TBody>
        </Table>
      )}
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// Recent correlations — newest established correlations.
// ---------------------------------------------------------------------------

export function RecentCorrelationsPanel({
  correlationFeed,
  loading,
  hasError,
  onRetry,
  className,
}: {
  correlationFeed: CorrelationResult[]
  loading: boolean
  hasError: boolean
  onRetry: () => void
  className?: string
}) {
  return (
    <Panel
      title="Recent correlations"
      subtitle={`Newest ${loading ? '…' : correlationFeed.length} persisted correlations (bounded feed)`}
      className={cn('xl:col-span-6', className)}
      padded={false}
      action={
        <Link to="/correlations" className="text-[11px] font-medium uppercase tracking-wide text-accent hover:underline">
          View all →
        </Link>
      }
    >
      {loading ? (
        <LoadingRows rows={7} />
      ) : hasError ? (
        <ErrorState message="Correlation data is unavailable." onRetry={onRetry} />
      ) : correlationFeed.length === 0 ? (
        <EmptyState title="No correlations" body="The bounded recent correlation feed is empty." />
      ) : (
        <Table>
          <thead className="bg-surface-2">
            <tr>
              <Th>Status</Th>
              <Th>Confidence</Th>
              <Th>Members</Th>
              <Th>Timestamp</Th>
              <Th>Correlation</Th>
            </tr>
          </thead>
          <TBody>
            {correlationFeed.slice(0, ACTIVITY_ROWS).map((item) => (
              <TRow key={item.id} data-testid="correlation-row">
                <Td>
                  <CorrelationStatusBadge status={item.status} />
                </Td>
                <Td>
                  <ConfidenceBar value={item.confidence} />
                </Td>
                <Td>{item.members.length}</Td>
                <Td className="whitespace-nowrap text-xs text-ink-dim" title={formatDateTime(item.timestamp)}>
                  {formatDateTime(item.timestamp)}
                </Td>
                <MonoCell>
                  <Link
                    to={`/correlations/${item.correlation_id}`}
                    className="text-accent hover:underline"
                  >
                    view
                  </Link>
                  <span className="mx-1 text-ink-faint">·</span>
                  <MonoId id={item.correlation_id} />
                </MonoCell>
              </TRow>
            ))}
          </TBody>
        </Table>
      )}
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// Threat intelligence — honest empty state; V1 has no TI read API.
// ---------------------------------------------------------------------------

export function ThreatIntelPanel({
  memoryFeed,
  memoryIndicators,
  loading,
  hasError,
  className,
}: {
  memoryFeed: Array<{ indicators: Array<unknown> }>
  memoryIndicators: number
  loading: boolean
  hasError: boolean
  className?: string
}) {
  return (
    <Panel
      title="Threat intelligence"
      subtitle="Provider layer exists · no V1 read API"
      className={cn('xl:col-span-4', className)}
      padded={false}
    >
      {loading ? (
        <LoadingRows rows={5} />
      ) : hasError ? (
        <ErrorState message="Incident memory data is unavailable." />
      ) : (
        <div data-testid="ti-empty" className="flex flex-col items-center gap-2 px-4 py-10 text-center">
          <BookKey className="h-6 w-6 text-ink-faint" aria-hidden="true" />
          <div className="text-sm font-medium text-ink-dim">No threat-intelligence indicators</div>
          <div className="max-w-md text-[11px] leading-relaxed text-ink-faint">
            V1 exposes no threat-intelligence indicator API. {memoryFeed.length}{' '}
            {memoryFeed.length === 1 ? 'incident memory' : 'incident memories'} loaded by the
            bounded feed record {memoryIndicators} indicator
            {memoryIndicators === 1 ? '' : 's'}. Nothing is fabricated here.
          </div>
          <div className="text-[10px] text-ink-faint">
            Step 8 threat-intelligence contracts exist but persist and serve no indicators.
          </div>
        </div>
      )}
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// Merged recent security events — real, timestamp-sorted, honest.
// ---------------------------------------------------------------------------

type EventKind = 'detection' | 'correlation' | 'risk'

export function RecentSecurityEventsPanel({
  detectionFeed,
  correlationFeed,
  riskFeed,
  loading,
  hasError,
  onRetry,
  className,
}: {
  detectionFeed: DetectionResult[]
  correlationFeed: CorrelationResult[]
  riskFeed: RiskAssessment[]
  loading: boolean
  hasError: boolean
  onRetry: () => void
  className?: string
}) {
  const events = useMemo(() => {
    type EventRow = {
      key: string
      ts: string
      kind: EventKind
      ref: string
      to: string
      tone: 'accent' | 'neutral' | 'medium'
      severity?: DetectionResult['severity']
      level?: RiskLevel
    }
    const rows: EventRow[] = [
      ...detectionFeed.map((item) => ({
        key: `det-${item.id}`,
        ts: item.detected_at,
        kind: 'detection' as const,
        ref: item.detection_id,
        to: '/detections',
        tone: 'accent' as const,
        severity: item.severity,
      })),
      ...correlationFeed.map((item) => ({
        key: `corr-${item.id}`,
        ts: item.timestamp,
        kind: 'correlation' as const,
        ref: item.correlation_id,
        to: `/correlations/${item.correlation_id}`,
        tone: 'neutral' as const,
      })),
      ...riskFeed.map((item) => ({
        key: `risk-${item.id}`,
        ts: item.timestamp,
        kind: 'risk' as const,
        ref: item.risk_assessment_id,
        to: `/incidents/${item.correlation_id}`,
        tone: 'medium' as const,
        level: item.level,
      })),
    ]
    return rows.sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, EVENT_ROWS)
  }, [detectionFeed, correlationFeed, riskFeed])

  return (
    <Panel
      title="Recent security events"
      subtitle="Detection, correlation and risk events merged & timestamp-sorted (bounded feeds, limit 200 each)"
      className={cn('xl:col-span-8', className)}
      padded={false}
    >
      {loading ? (
        <LoadingRows rows={8} />
      ) : hasError ? (
        <ErrorState message="Security event feeds are unavailable." onRetry={onRetry} />
      ) : events.length === 0 ? (
        <EmptyState title="No security events" body="All bounded feeds are empty." />
      ) : (
        <Table>
          <thead className="bg-surface-2">
            <tr>
              <Th>Time</Th>
              <Th>Type</Th>
              <Th>Severity / Level</Th>
              <Th>Reference</Th>
              <Th />
            </tr>
          </thead>
          <TBody>
            {events.map((event) => (
              <TRow key={event.key} data-testid="security-event-row">
                <Td className="whitespace-nowrap text-xs text-ink-dim" title={formatDateTime(event.ts)}>
                  {formatDateTime(event.ts)}
                </Td>
                <Td>
                  <Badge tone={event.tone}>{event.kind}</Badge>
                </Td>
                <Td>
                  {event.severity ? (
                    <SeverityBadge severity={event.severity} />
                  ) : event.level ? (
                    <RiskLevelBadge level={event.level} />
                  ) : (
                    <span className="text-[11px] text-ink-faint">—</span>
                  )}
                </Td>
                <MonoCell>
                  <MonoId id={event.ref} />
                </MonoCell>
                <Td>
                  <Link to={event.to} className="text-[11px] text-accent hover:underline">
                    open
                  </Link>
                </Td>
              </TRow>
            ))}
          </TBody>
        </Table>
      )}
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// Response + policy — honest simulation-only panel. No fabricated outcomes.
// ---------------------------------------------------------------------------

function OperationMiniStat({ label }: { label: string }) {
  return (
    <div className="rounded-md border border-edge-soft bg-surface-0 px-2 py-1.5 text-center">
      <div className="truncate text-[10px] font-semibold uppercase tracking-wider text-ink-dim">
        {label}
      </div>
      <div className="mt-0.5 font-mono text-sm text-ink">0</div>
    </div>
  )
}

export function PolicyResponsePanel({ className }: { className?: string }) {
  return (
    <Panel
      title="Response & policy activity"
      subtitle="Step 24 policy · Step 25 response harness"
      className={className}
      padded={false}
    >
      <div className="flex items-center justify-between border-b border-edge-soft px-4 py-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-ink-dim">
          Operational layer
        </span>
        <Badge tone="accent" data-testid="simulated-operations">SIMULATED</Badge>
      </div>

      <div className="space-y-3 p-4">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-wider text-ink">
            Policy activity
          </div>
          <div className="mt-2 grid grid-cols-3 gap-2">
            <OperationMiniStat label="Allowed" />
            <OperationMiniStat label="Denied" />
            <OperationMiniStat label="Req. approval" />
          </div>
          <p className="mt-2 text-[10px] leading-relaxed text-ink-faint">
            Step 24 evaluates declarative policy and emits ALLOWED / DENIED / REQUIRES_APPROVAL
            decisions, but it defines no persistence and no policy API — no decision is stored or
            served, so the honest count is 0.
          </p>
        </div>

        <Separator />

        <div>
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-ink">
              Response activity
            </span>
            <span className="text-[10px] font-mono uppercase text-accent/80">
              MockResponseProvider
            </span>
          </div>
          <div className="mt-2 grid grid-cols-4 gap-2">
            <OperationMiniStat label="Executed" />
            <OperationMiniStat label="Failed" />
            <OperationMiniStat label="Rejected" />
            <OperationMiniStat label="Skipped" />
          </div>
          <p className="mt-2 text-[10px] leading-relaxed text-ink-faint">
            Step 25 executes against the simulated provider in memory and discards every outcome.
            No response ever touched real infrastructure, and nothing is persisted or served.
          </p>
        </div>
      </div>
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// Pending approvals — live human-in-the-loop authorizations (bounded feed).
// ---------------------------------------------------------------------------

interface ApproveMutation {
  id: string
  action: 'approve' | 'reject'
  comment: string
}

export function PendingApprovalsPanel({
  approvals,
  loading,
  hasError,
  onRetry,
  className,
}: {
  approvals: ApprovalRecord[]
  loading: boolean
  hasError: boolean
  onRetry: () => void
  className?: string
}) {
  const role = useAuthStore((state) => state.user?.role ?? null)
  const accessible = APPROVAL_SOC_ROLES.includes(role ?? '')
  const queryClient = useQueryClient()

  const [confirming, setConfirming] = useState<ApproveMutation | null>(null)

  const mutation = useMutation({
    mutationFn: (vars: ApproveMutation) =>
      vars.action === 'approve'
        ? approvalsApi.approve(vars.id, { comment: vars.comment })
        : approvalsApi.reject(vars.id, { comment: vars.comment }),
    onSuccess: () => {
      setConfirming(null)
      void queryClient.invalidateQueries({ queryKey: APPROVALS_PENDING_KEY })
    },
  })

  const move = mutation.isPending
  const failure =
    mutation.isError && mutation.variables
      ? { id: mutation.variables.id, message: mutation.error.message }
      : null

  return (
    <Panel
      title="Pending approvals"
      subtitle={`Human-in-the-loop authorizations · bounded pending feed (max ${APPROVALS_LIMIT})`}
      data-testid="pending-approvals"
      className={className}
      padded={false}
    >
      {!accessible ? (
        <div className="flex flex-col gap-1 px-4 py-6 text-center">
          <div className="text-xs font-medium text-ink-dim">Approval access restricted</div>
          <div className="mx-auto max-w-md text-[11px] leading-relaxed text-ink-faint">
            The current role{role ? ` (${role})` : ''} cannot view or act on approval requests.
            Only admin, analyst and ciso roles are authorized.
          </div>
        </div>
      ) : loading ? (
        <LoadingRows rows={5} />
      ) : hasError ? (
        <ErrorState message="Approval data is unavailable." onRetry={onRetry} />
      ) : approvals.length === 0 ? (
        <EmptyState
          title="No pending approvals"
          body="No REQUIRES_APPROVAL policy decisions are awaiting a human decision."
        />
      ) : (
        <Table>
          <thead className="bg-surface-2">
            <tr>
              <Th>Risk</Th>
              <Th>Action</Th>
              <Th>Target</Th>
              <Th>Rule</Th>
              <Th>Requested by</Th>
              <Th>Requested at</Th>
              <Th>Decision</Th>
            </tr>
          </thead>
          <TBody>
            {approvals.slice(0, APPROVALS_LIMIT).map((item) => {
              const isConfirming = confirming?.id === item.approval_id
              const isBusy = isConfirming && move
              const failed = isConfirming && failure?.id === item.approval_id
              return (
                <TRow key={item.approval_id} data-testid="approval-row">
                  <Td>
                    <RiskLevelBadge level={item.risk_level} />
                  </Td>
                  <Td>
                    <Badge tone="neutral">{item.action_type}</Badge>
                  </Td>
                  <MonoCell>
                    <span className="text-[11px] text-ink" title={item.target}>
                      {item.target}
                    </span>
                  </MonoCell>
                  <Td>
                    <span data-mono className="text-[11px] text-ink" title={item.policy_rule_id}>
                      {item.policy_rule_id}
                    </span>
                  </Td>
                  <Td>
                    <span className="text-[11px] text-ink-dim">{item.requested_by_role}</span>
                  </Td>
                  <Td
                    className="whitespace-nowrap text-xs text-ink-dim"
                    title={formatDateTime(item.requested_at)}
                  >
                    {formatDateTime(item.requested_at)}
                  </Td>
                  <Td>
                    {isConfirming ? (
                      <div className="flex flex-col items-end gap-1.5">
                        <input
                          type="text"
                          data-testid="approval-comment"
                          value={confirming?.comment ?? ''}
                          onChange={(event) =>
                            setConfirming({
                              id: item.approval_id,
                              action: confirming?.action ?? 'approve',
                              comment: event.target.value,
                            })
                          }
                          placeholder="Required accountability comment"
                          disabled={isBusy}
                          className="h-7 w-56 rounded-md border border-edge bg-surface-0 px-2 font-mono text-[11px] text-ink focus:border-accent focus:outline-none"
                        />
                        {failed && (
                          <span className="text-[10px] text-critical">{failure?.message}</span>
                        )}
                        <div className="flex items-center gap-1.5">
                          <Button
                            size="sm"
                            variant={confirming?.action === 'approve' ? 'default' : 'danger'}
                            disabled={!confirming?.comment.trim() || isBusy}
                            onClick={() => confirming && mutation.mutate(confirming)}
                            data-testid="approval-confirm"
                          >
                            {isBusy ? 'Working…' : `Confirm ${confirming?.action}`}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={isBusy}
                            onClick={() => setConfirming(null)}
                          >
                            Cancel
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={move}
                          onClick={() =>
                            setConfirming({ id: item.approval_id, action: 'approve', comment: '' })
                          }
                          data-testid="approval-approve"
                        >
                          Approve
                        </Button>
                        <Button
                          size="sm"
                          variant="danger"
                          disabled={move}
                          onClick={() =>
                            setConfirming({ id: item.approval_id, action: 'reject', comment: '' })
                          }
                          data-testid="approval-reject"
                        >
                          Reject
                        </Button>
                      </div>
                    )}
                  </Td>
                </TRow>
              )
            })}
          </TBody>
        </Table>
      )}

      <div className="border-t border-edge-soft px-4 py-2 text-[10px] leading-relaxed text-ink-faint">
        Approval authorizes only — it never executes. An APPROVED grant is re-checked at the Step 25
        Response gate, which records its own response_status (executed / failed / skipped / rejected).
      </div>
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// System health — real probes; unknown states are reported as unknown.
// ---------------------------------------------------------------------------

function statusDot(status: string): string {
  const ok = ['connected', 'healthy', 'HEALTHY']
  const bad = ['unhealthy', 'DEGRADED', 'unavailable']
  if (ok.includes(status)) return 'bg-low text-low'
  if (bad.includes(status)) return 'bg-critical text-critical'
  return 'bg-ink-faint text-ink-faint'
}

export function SystemHealthPanel({
  db,
  kafka,
  className,
}: {
  db: {
    data: { status?: string } | undefined
    isLoading: boolean
    isError: boolean
  }
  kafka: {
    data: { status?: string } | undefined
    isLoading: boolean
    isError: boolean
  }
  className?: string
}) {
  const dbStatus = db.isLoading ? '…' : db.data?.status ?? (db.isError ? 'unavailable' : 'UNKNOWN')
  const kafkaStatus = kafka.isLoading ? '…' : kafka.data?.status ?? (kafka.isError ? 'unavailable' : 'UNKNOWN')
  const apiStatus = db.isLoading || kafka.isLoading ? '…' : db.isError || kafka.isError ? 'DEGRADED' : 'HEALTHY'
  const aiStatus = 'UNKNOWN'

  const rows = [
    { label: 'Database', status: dbStatus, testid: 'db-health' },
    { label: 'Kafka', status: kafkaStatus, testid: 'kafka-health' },
    { label: 'API', status: apiStatus, testid: 'api-health' },
    { label: 'AI provider', status: aiStatus, testid: 'ai-health' },
  ]

  return (
    <Panel title="System health" subtitle="Live dependency probes" className={className} padded={false}>
      <div className="space-y-1.5 p-4">
        {rows.map((row) => (
          <div key={row.label} className="flex items-center justify-between gap-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-ink-dim">
              {row.label}
            </span>
            <span
              data-testid={row.testid}
              className={cn('inline-flex items-center gap-1.5 font-mono text-[11px]', statusDot(row.status))}
            >
              <span className={cn('h-1.5 w-1.5 rounded-full', statusDot(row.status).split(' ')[0])} />
              {row.status}
            </span>
          </div>
        ))}
        <div className="border-t border-edge-soft pt-2 text-[10px] leading-relaxed text-ink-faint">
          DB/Kafka come from the health probes. API state is inferred from probe success — the
          backend exposes no /health/api — and the AI provider is not exposed, so it is UNKNOWN.
        </div>
      </div>
    </Panel>
  )
}

export function DashboardErrorBanner({
  hasError,
  onRetry,
}: {
  hasError: boolean
  onRetry: () => void
}) {
  if (!hasError) return null
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-high/40 bg-high/10 px-3 py-2 text-xs text-ink" data-testid="dashboard-error">
      <span className="inline-flex items-center gap-2">
        <ShieldAlert className="h-4 w-4 text-high" aria-hidden="true" />
        One or more bounded feeds failed to load. Panels below show their own states.
      </span>
      <button type="button" onClick={onRetry} className="font-medium text-accent hover:underline">
        Retry all
      </button>
    </div>
  )
}