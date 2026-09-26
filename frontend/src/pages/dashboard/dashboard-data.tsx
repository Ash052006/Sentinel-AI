import { useQuery } from '@tanstack/react-query'
import { detectionsApi } from '../../api/detections'
import { correlationsApi } from '../../api/correlations'
import { risksApi } from '../../api/risks'
import { memoriesApi } from '../../api/memories'
import { detectionRulesApi } from '../../api/detectionRules'
import { approvalsApi } from '../../api/approvals'
import { healthApi } from '../../api/health'
import { useAuthStore } from '../../store/auth'
import { toTimestamp } from '../../lib/aggregation'
import type { CorrelationResult, RiskAssessment, RiskLevel } from '../../types/api'

/** Browser feeds carry a query limit; the dashboard never reports it as a total. */
export const FEED = 200
export const INCIDENT_ROWS = 8
export const ACTIVITY_ROWS = 7
export const EVENT_ROWS = 10

/** Bounded pending-approvals feed shown on the dashboard. */
export const APPROVALS_LIMIT = 10
export const APPROVALS_PENDING_KEY = ['approvals', 'pending'] as const

/** Roles the backend authorizes to view/act on approval requests. */
export const APPROVAL_SOC_ROLES = ['admin', 'analyst', 'ciso']

export interface IncidentRow {
  risk: RiskAssessment
  correlation: CorrelationResult | null
}

export interface RulesSummary {
  total: number
  sigma: number
  yara: number
  enabled: number
  disabled: number
}

export interface LevelCounts extends Record<RiskLevel, number> {
  critical: number
  high: number
  medium: number
  low: number
}

const levelRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }

export function joinIncidents(
  risks: RiskAssessment[],
  correlations: CorrelationResult[],
): IncidentRow[] {
  const byId = new Map(correlations.map((item) => [item.correlation_id, item]))
  return risks
    .map((risk) => ({ risk, correlation: byId.get(risk.correlation_id) ?? null }))
    .sort((a, b) => {
      const rankDiff = levelRank[b.risk.level] - levelRank[a.risk.level]
      if (rankDiff !== 0) return rankDiff
      return b.risk.timestamp.localeCompare(a.risk.timestamp)
    })
}

export function useDashboardData() {
  const role = useAuthStore((state) => state.user?.role ?? null)
  const approvalsAccessible = APPROVAL_SOC_ROLES.includes(role ?? '')

  const detections = useQuery({
    queryKey: ['detections', 'recent', FEED],
    queryFn: () => detectionsApi.recent(FEED),
  })
  const correlations = useQuery({
    queryKey: ['correlations', 'recent', FEED],
    queryFn: () => correlationsApi.recent(FEED),
  })
  const risks = useQuery({
    queryKey: ['risks', 'recent', FEED],
    queryFn: () => risksApi.recent(FEED),
  })
  const memories = useQuery({
    queryKey: ['memories', 'recent', FEED],
    queryFn: () => memoriesApi.recent(FEED),
  })
  const rules = useQuery({
    queryKey: ['detection-rules', 'list'],
    queryFn: () => detectionRulesApi.list(),
  })
  const analytics = useQuery({
    queryKey: ['detection-rules', 'analytics', '30d'],
    queryFn: () => detectionRulesApi.analytics('30d'),
  })
  const db = useQuery({
    queryKey: ['health', 'database'],
    queryFn: healthApi.database,
  })
  const kafka = useQuery({
    queryKey: ['health', 'kafka'],
    queryFn: healthApi.kafka,
  })
  const approvals = useQuery({
    queryKey: APPROVALS_PENDING_KEY,
    queryFn: () => approvalsApi.recent(APPROVALS_LIMIT, 'pending'),
    enabled: approvalsAccessible,
  })

  const detectionFeed = detections.data ?? []
  const correlationFeed = correlations.data ?? []
  const riskFeed = risks.data ?? []
  const memoryFeed = memories.data ?? []
  const approvalFeed = approvals.data ?? []

  const incidentRows = joinIncidents(riskFeed, correlationFeed)

  const activeIncidents = (() => {
    const seen = new Set<string>()
    for (const row of incidentRows) {
      if (row.correlation?.status === 'active') seen.add(row.risk.correlation_id)
    }
    return seen.size
  })()

  const byLevel = (() => {
    const counts: LevelCounts = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const risk of riskFeed) counts[risk.level] += 1
    return counts
  })()

  const rulesSummary = (() => {
    const list = rules.data ?? []
    const sigma = list.filter((rule) => rule.rule_type === 'sigma').length
    const yara = list.filter((rule) => rule.rule_type === 'yara').length
    const enabled = list.filter((rule) => rule.enabled).length
    return { total: list.length, sigma, yara, enabled, disabled: list.length - enabled }
  })()

  const memoryIndicators = (() =>
    memoryFeed.reduce(
      (sum, memory) => sum + (Array.isArray(memory.indicators) ? memory.indicators.length : 0),
      0,
    ))()

  const newestDataAt = (() => {
    let max = 0
    const candidates = [
      ...detectionFeed.map((item) => toTimestamp(item.detected_at)),
      ...correlationFeed.map((item) => toTimestamp(item.timestamp)),
      ...riskFeed.map((item) => toTimestamp(item.timestamp)),
    ]
    for (const ts of candidates) {
      if (ts !== null && ts > max) max = ts
    }
    return max
  })()

  const isLoading =
    detections.isLoading ||
    correlations.isLoading ||
    risks.isLoading ||
    memories.isLoading ||
    db.isLoading ||
    kafka.isLoading
  const isError =
    detections.isError || correlations.isError || risks.isError || memories.isError

  return {
    detections,
    correlations,
    risks,
    memories,
    approvals,
    rules,
    analytics,
    db,
    kafka,
    detectionFeed,
    correlationFeed,
    riskFeed,
    memoryFeed,
    approvalFeed,
    approvalsAccessible,
    incidentRows,
    activeIncidents,
    byLevel,
    rulesSummary,
    memoryIndicators,
    newestDataAt,
    isLoading,
    isError,
  }
}

export type DashboardData = ReturnType<typeof useDashboardData>