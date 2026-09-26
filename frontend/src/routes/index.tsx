import { createBrowserRouter, Navigate } from 'react-router-dom'
import { AppShell } from '../layouts/app-shell'
import { AttackPathPage } from '../pages/attack-path-page'
import { AuditPage } from '../pages/audit-page'
import { CorrelationDetailPage } from '../pages/correlation-detail-page'
import { CorrelationsPage } from '../pages/correlations-page'
import { DashboardPage } from '../pages/dashboard-page'
import { DetectionAsCodePage } from '../pages/detection-as-code-page'
import { DetectionsPage } from '../pages/detections-page'
import { DetectionRulesPage } from '../pages/detection-rules-page'
import { IncidentDetailPage } from '../pages/incident-detail-page'
import { IncidentReportsPage } from '../pages/incident-reports-page'
import { IncidentsPage } from '../pages/incidents-page'
import { InvestigationsPage } from '../pages/investigations-page'
import { LoginPage } from '../pages/login-page'
import { NotFoundPage } from '../pages/not-found-page'
import { PolicyPage } from '../pages/policy-page'
import { ResponsesPage } from '../pages/responses-page'
import { RiskPage } from '../pages/risk-page'
import { SearchResultsPage } from '../pages/search-results-page'
import { SettingsPage } from '../pages/settings-page'
import { SoarPage } from '../pages/soar-page'
import { SystemPage } from '../pages/system-page'
import { ThreatHuntingPage } from '../pages/threat-hunting-page'
import { ThreatIntelPage } from '../pages/threat-intel-page'

export const router = createBrowserRouter([
  { path: '/login', element: <LoginPage /> },
  {
    element: <AppShell />,
    children: [
      { path: '/', element: <Navigate to="/dashboard" replace /> },
      { path: '/dashboard', element: <DashboardPage /> },
      { path: '/incidents', element: <IncidentsPage /> },
      { path: '/incidents/:correlationId', element: <IncidentDetailPage /> },
      { path: '/detections', element: <DetectionsPage /> },
      { path: '/detection-rules', element: <DetectionRulesPage /> },
      { path: '/detection-as-code', element: <DetectionAsCodePage /> },
      { path: '/correlations', element: <CorrelationsPage /> },
      { path: '/correlations/:correlationId', element: <CorrelationDetailPage /> },
      { path: '/risk', element: <RiskPage /> },
      { path: '/threat-intelligence', element: <ThreatIntelPage /> },
      { path: '/investigations', element: <InvestigationsPage /> },
      { path: '/policy', element: <PolicyPage /> },
      { path: '/responses', element: <ResponsesPage /> },
      { path: '/soar', element: <SoarPage /> },
      { path: '/threat-hunting', element: <ThreatHuntingPage /> },
      { path: '/incident-reports', element: <IncidentReportsPage /> },
      { path: '/attack-paths', element: <AttackPathPage /> },
      { path: '/attack-paths/:correlationId', element: <AttackPathPage /> },
      { path: '/system', element: <SystemPage /> },
      { path: '/audit', element: <AuditPage /> },
      { path: '/settings', element: <SettingsPage /> },
      { path: '/search', element: <SearchResultsPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
])