import {
  DashboardErrorBanner,
  IncidentsPanel,
  KpiStrip,
  PendingApprovalsPanel,
  PolicyResponsePanel,
  RecentCorrelationsPanel,
  RecentDetectionsPanel,
  RecentSecurityEventsPanel,
  RiskOverviewPanel,
  RulesSummaryPanel,
  SecurityActivityPanel,
  SystemHealthPanel,
  ThreatIntelPanel,
} from './dashboard/panels'
import { useDashboardData } from './dashboard/dashboard-data'

/**
 * SOC command-center dashboard.
 *
 * Layout (12-column grid on xl+):
 *   12  → compact KPI strip
 *   8/4 → Security activity | Risk overview + Detection rules
 *   8/4 → Active incidents   | Threat intelligence
 *   6/6 → Recent detections  | Recent correlations
 *   8/4 → Recent security events | Pending approvals + Response & policy + System health
 *
 * Every number is derived from real backend APIs; bounded feeds are labelled
 * as bounded and their page size is never presented as a total.
 */
export function DashboardPage() {
  const data = useDashboardData()

  return (
    <div data-testid="soc-dashboard" className="grid grid-cols-1 gap-3 xl:grid-cols-12">
      <DashboardErrorBanner hasError={data.isError} onRetry={() => {
        void data.detections.refetch()
        void data.correlations.refetch()
        void data.risks.refetch()
        void data.memories.refetch()
      }} />

      <KpiStrip
        className="xl:col-span-12"
        loading={data.isLoading}
        activeIncidents={data.activeIncidents}
        byLevel={data.byLevel}
        detections30d={data.analytics.data?.total_detections ?? null}
        correlationCount={data.correlationFeed.length}
        riskCount={data.riskFeed.length}
        memoryIndicators={data.memoryIndicators}
      />

      <SecurityActivityPanel
        detectionFeed={data.detectionFeed}
        correlationFeed={data.correlationFeed}
        riskFeed={data.riskFeed}
        loading={data.isLoading}
        hasError={data.isError}
        onRetry={() => void data.detections.refetch()}
      />

      <div className="grid grid-cols-1 gap-3 xl:col-span-4">
        <RiskOverviewPanel
          riskFeed={data.riskFeed}
          loading={data.risks.isLoading}
          hasError={data.risks.isError}
          onRetry={() => void data.risks.refetch()}
        />
        <RulesSummaryPanel
          summary={data.rulesSummary}
          loading={data.rules.isLoading}
          hasError={data.rules.isError}
        />
      </div>

      <IncidentsPanel
        incidentRows={data.incidentRows}
        activeIncidents={data.activeIncidents}
        byLevel={data.byLevel}
        newestDataAt={data.newestDataAt}
        loading={data.risks.isLoading || data.correlations.isLoading}
        hasError={data.risks.isError || data.correlations.isError}
        onRetry={() => {
          void data.risks.refetch()
          void data.correlations.refetch()
        }}
      />

      <ThreatIntelPanel
        memoryFeed={data.memoryFeed}
        memoryIndicators={data.memoryIndicators}
        loading={data.memories.isLoading}
        hasError={data.memories.isError}
      />

      <RecentDetectionsPanel
        detectionFeed={data.detectionFeed}
        loading={data.detections.isLoading}
        hasError={data.detections.isError}
        onRetry={() => void data.detections.refetch()}
      />

      <RecentCorrelationsPanel
        correlationFeed={data.correlationFeed}
        loading={data.correlations.isLoading}
        hasError={data.correlations.isError}
        onRetry={() => void data.correlations.refetch()}
      />

      <RecentSecurityEventsPanel
        detectionFeed={data.detectionFeed}
        correlationFeed={data.correlationFeed}
        riskFeed={data.riskFeed}
        loading={data.isLoading}
        hasError={data.isError}
        onRetry={() => {
          void data.detections.refetch()
          void data.correlations.refetch()
          void data.risks.refetch()
        }}
      />

      <div className="grid grid-cols-1 gap-3 xl:col-span-4">
        <PendingApprovalsPanel
          approvals={data.approvalFeed}
          loading={data.approvals.isLoading}
          hasError={data.approvals.isError}
          onRetry={() => void data.approvals.refetch()}
        />
        <PolicyResponsePanel />
        <SystemHealthPanel
          db={{
            data: data.db.data,
            isLoading: data.db.isLoading,
            isError: data.db.isError,
          }}
          kafka={{
            data: data.kafka.data,
            isLoading: data.kafka.isLoading,
            isError: data.kafka.isError,
          }}
        />
      </div>
    </div>
  )
}