import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within, act, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DashboardPage } from './dashboard-page'
import { renderWithProviders } from '../test/utils'
import { detectionsApi } from '../api/detections'
import { correlationsApi } from '../api/correlations'
import { risksApi } from '../api/risks'
import { memoriesApi } from '../api/memories'
import { detectionRulesApi } from '../api/detectionRules'
import { approvalsApi } from '../api/approvals'
import { healthApi } from '../api/health'
import { useAuthStore } from '../store/auth'
import type {
  ApprovalRecord,
  CorrelationMember,
  CorrelationResult,
  DetectionResult,
  DetectionRule,
  DetectionRuleAnalytics,
  IncidentMemory,
  RiskAssessment,
} from '../types/api'

vi.mock('../api/detections', () => ({
  detectionsApi: { recent: vi.fn() },
}))
vi.mock('../api/correlations', () => ({
  correlationsApi: { recent: vi.fn() },
}))
vi.mock('../api/risks', () => ({
  risksApi: { recent: vi.fn() },
}))
vi.mock('../api/memories', () => ({
  memoriesApi: { recent: vi.fn() },
}))
vi.mock('../api/detectionRules', () => ({
  detectionRulesApi: { list: vi.fn(), analytics: vi.fn() },
}))
vi.mock('../api/approvals', () => ({
  approvalsApi: {
    list: vi.fn(),
    recent: vi.fn(),
    get: vi.fn(),
    approve: vi.fn(),
    reject: vi.fn(),
    cancel: vi.fn(),
  },
}))
vi.mock('../api/health', () => ({
  healthApi: { database: vi.fn(), kafka: vi.fn() },
}))

const DETECTION_API = vi.mocked(detectionsApi)
const CORRELATIONS_API = vi.mocked(correlationsApi)
const RISKS_API = vi.mocked(risksApi)
const MEMORIES_API = vi.mocked(memoriesApi)
const RULES_API = vi.mocked(detectionRulesApi)
const APPROVALS_API = vi.mocked(approvalsApi)
const HEALTH_API = vi.mocked(healthApi)

const DAY = 86_400_000
const now = Date.now()
const at = (offsetMs: number) => new Date(now - offsetMs).toISOString()

function detection(overrides: Partial<DetectionResult> = {}): DetectionResult {
  const detectedAt = overrides.detected_at ?? at(10 * DAY)
  return {
    id: 'det-1',
    event_id: 'evt-1',
    detection_id: 'DETECTION-1',
    rule_id: 'rule-web-01',
    rule_type: 'sigma',
    rule_version: '1',
    severity: 'high',
    matched: true,
    confidence: 0.9,
    evidence: {},
    result_metadata: {},
    detected_at: detectedAt,
    provenance: 'observed',
    created_at: detectedAt,
    updated_at: detectedAt,
    ...overrides,
  }
}

function member(order: number): CorrelationMember {
  return {
    id: `m-${order}`,
    correlation_id: 'CORR-1',
    detection_id: 'DETECTION-1',
    event_id: `evt-${order}`,
    timestamp: at(8 * DAY),
    member_order: order,
    created_at: at(8 * DAY),
    updated_at: at(8 * DAY),
  }
}

function correlation(overrides: Partial<CorrelationResult> = {}): CorrelationResult {
  const timestamp = overrides.timestamp ?? at(8 * DAY)
  return {
    id: 'corr-1',
    correlation_id: 'CORR-1',
    status: 'active',
    confidence: 0.8,
    evidence: {},
    result_metadata: {},
    timestamp,
    provenance: 'observed',
    members: [member(1), member(2)],
    created_at: timestamp,
    updated_at: timestamp,
    ...overrides,
  }
}

function risk(overrides: Partial<RiskAssessment> = {}): RiskAssessment {
  const timestamp = overrides.timestamp ?? at(6 * DAY)
  return {
    id: 'risk-1',
    risk_assessment_id: 'RISK-1',
    correlation_id: 'CORR-1',
    score: 78,
    level: 'high',
    confidence: 0.85,
    factors: [],
    evidence: [],
    assessment_metadata: {},
    timestamp,
    provenance: 'observed',
    created_at: timestamp,
    updated_at: timestamp,
    ...overrides,
  }
}

function memory(): IncidentMemory {
  return {
    id: 'mem-1',
    memory_id: 'MEM-1',
    memory_type: 'incident_summary',
    title: 'Web shell intrusion',
    summary: 'compromise summary',
    correlation_id: 'CORR-1',
    sources: [],
    indicators: [{ ip: '10.0.0.8' }],
    entities: [],
    techniques: [],
    findings: [],
    actions: [],
    outcomes: {},
    memory_metadata: {},
    confidence: 0.7,
    provenance: 'observed',
    created_at: at(5 * DAY),
    updated_at: at(5 * DAY),
  }
}

function approval(overrides: Partial<ApprovalRecord> = {}): ApprovalRecord {
  const requestedAt = overrides.requested_at ?? at(2 * DAY)
  return {
    id: 'app-1',
    approval_id: 'APPROVAL-1',
    policy_decision_id: 'DECISION-1',
    correlation_id: 'CORR-1',
    action_type: 'block_ip',
    target: '10.0.0.8',
    status: 'pending',
    reason: 'elevated-risk escalation',
    policy_rule_id: 'rule-elevated-01',
    risk_level: 'high',
    risk_score: 0.78,
    confidence: 0.85,
    evidence: [],
    request_note: null,
    requested_by: 'u-1',
    requested_by_role: 'analyst',
    requested_at: requestedAt,
    expires_at: at(-1 * DAY),
    resolved_at: null,
    resolved_by: null,
    resolution_reason: null,
    response_status: null,
    response_provider: null,
    response_error_code: null,
    provenance: 'approval_reviewed',
    metadata: {},
    created_at: requestedAt,
    updated_at: requestedAt,
    ...overrides,
  }
}

function rule(ruleId: string, ruleType: 'sigma' | 'yara', enabled = true): DetectionRule {
  return {
    rule_id: ruleId,
    name: ruleId,
    description: '',
    rule_type: ruleType,
    severity: 'high',
    enabled,
    version: '1',
    category: null,
    tags: [],
    author: null,
    date: null,
    status: null,
    source_file: null,
    match_count: 0,
    last_matched_at: null,
  }
}

const analytics30d: DetectionRuleAnalytics = {
  window: '30d',
  total_detections: 5548,
  buckets: [],
  by_severity: [],
  rules_with_matches: 0,
}

interface MockOptions {
  detections?: DetectionResult[]
  correlations?: CorrelationResult[]
  risks?: RiskAssessment[]
  memories?: IncidentMemory[]
  rules?: DetectionRule[]
  analytics?: DetectionRuleAnalytics
  approvals?: ApprovalRecord[]
  reject?: string[]
}

function installMocks(options: MockOptions = {}) {
  const detections = options.detections ?? [
    detection({ detected_at: at(5 * DAY) }),
    detection({ id: 'det-2', detection_id: 'DETECTION-2', rule_id: 'rule-web-02', detected_at: at(10 * DAY) }),
  ]
  const correlations = options.correlations ?? [
    correlation(),
    correlation({ id: 'corr-2', correlation_id: 'CORR-2', members: [member(1)], timestamp: at(11 * DAY) }),
  ]
  const risks = options.risks ?? [
    risk(),
    risk({
      id: 'risk-2',
      risk_assessment_id: 'RISK-2',
      correlation_id: 'CORR-2',
      score: 41,
      level: 'low',
      timestamp: at(9 * DAY),
    }),
  ]

  const reject = new Set(options.reject ?? [])
  if (reject.has('detectionsApi')) {
    DETECTION_API.recent.mockRejectedValue(new Error('boom'))
  } else {
    DETECTION_API.recent.mockResolvedValue(detections)
  }
  if (reject.has('correlationsApi')) {
    CORRELATIONS_API.recent.mockRejectedValue(new Error('boom'))
  } else {
    CORRELATIONS_API.recent.mockResolvedValue(correlations)
  }
  if (reject.has('risksApi')) {
    RISKS_API.recent.mockRejectedValue(new Error('boom'))
  } else {
    RISKS_API.recent.mockResolvedValue(risks)
  }
  MEMORIES_API.recent.mockResolvedValue(options.memories ?? [memory()])
  APPROVALS_API.recent.mockResolvedValue(options.approvals ?? [])
  RULES_API.list.mockResolvedValue(
    options.rules ?? [
      ...Array.from({ length: 8 }, (_, i) => rule(`sigma-rule-${i + 1}`, 'sigma')),
      ...Array.from({ length: 5 }, (_, i) => rule(`yara-rule-${i + 1}`, 'yara')),
    ],
  )
  RULES_API.analytics.mockResolvedValue(options.analytics ?? analytics30d)
  HEALTH_API.database.mockResolvedValue({ status: 'connected' })
  HEALTH_API.kafka.mockResolvedValue({ status: 'healthy' })
}

beforeEach(() => {
  vi.resetAllMocks()
  useAuthStore.getState().setUser(null)
})

afterEach(() => {
  vi.clearAllMocks()
})

function renderDash() {
  return renderWithProviders(<DashboardPage />, { route: '/dashboard' })
}

describe('DashboardPage — SOC command center', () => {
  it('renders the full 12-column command-center layout with real KPI values', async () => {
    installMocks()
    renderDash()

    expect(await screen.findByTestId('soc-dashboard')).toBeInTheDocument()
    expect(screen.getByTestId('kpi-strip')).toBeInTheDocument()

    await screen.findByText('5548')
    expect(within(screen.getByTestId('kpi-correlations')).getByTestId('kpi-value')).toHaveTextContent('2')
    expect(within(screen.getByTestId('kpi-risk')).getByTestId('kpi-value')).toHaveTextContent('2')

    const activeCell = screen.getAllByTestId('kpi-cell')[0]!
    expect(activeCell).toHaveTextContent('Active incidents')
    expect(within(activeCell).getByTestId('kpi-value')).toHaveTextContent('2')

    expect(screen.getByText('Detections · 30d')).toBeInTheDocument()
    expect(screen.getByText('persisted aggregate')).toBeInTheDocument()
  })

  it('never reports a bounded feed page size as a total', async () => {
    const big: DetectionResult[] = Array.from({ length: 200 }, (_, i) =>
      detection({ id: `det-${i}`, detection_id: `DETECTION-${i}`, rule_id: `rule-${i}`, detected_at: at(10 * DAY) }),
    )
    const bigC: CorrelationResult[] = Array.from({ length: 200 }, (_, i) =>
      correlation({ id: `corr-${i}`, correlation_id: `CORR-${i}`, members: [member(1)], timestamp: at(11 * DAY) }),
    )
    const bigR: RiskAssessment[] = Array.from({ length: 200 }, (_, i) =>
      risk({
        id: `risk-${i}`,
        risk_assessment_id: `RISK-${i}`,
        correlation_id: `CORR-${i}`,
        level: i % 2 === 0 ? 'high' : 'low',
        timestamp: at(7 * DAY),
      }),
    )

    installMocks({ detections: big, correlations: bigC, risks: bigR })
    renderDash()

    expect((await screen.findAllByText('recent feed — 200 loaded')).length).toBeGreaterThanOrEqual(2)
    expect(screen.queryByText(/200 total/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/of 200/i)).not.toBeInTheDocument()
    // the "Detections · 30d" KPI uses the persisted aggregate, never the 200-row feed page size.
    expect(await screen.findByText('5548')).toBeInTheDocument()
    expect(screen.queryByText('detections · 30d')).toBeNull()
  })

  it('renders full, never-truncated UTC timestamps in table rows', async () => {
    installMocks({
      detections: [
        detection({ detected_at: '2027-10-23T04:00:52Z' }),
        detection({ id: 'det-2', detection_id: 'DETECTION-2', rule_id: 'rule-web-02', detected_at: at(5 * DAY) }),
      ],
      correlations: [correlation({ timestamp: '2027-10-23T04:00:00Z' })],
      risks: [risk({ timestamp: '2027-10-23T04:00:52Z' })],
    })
    renderDash()

    const detectionRows = await screen.findAllByTestId('detection-row')
    await waitFor(() => {
      expect(within(detectionRows[0]!).getByText('23 Oct 2027 04:00:52 UTC')).toBeInTheDocument()
      expect(within(detectionRows[0]!).queryByText(/^23 Oct 2027$/)).toBeNull()
    })

    const correlationRows = await screen.findAllByTestId('correlation-row')
    await waitFor(() => {
      expect(within(correlationRows[0]!).getByText('23 Oct 2027 04:00:00 UTC')).toBeInTheDocument()
    })

    const incidents = await screen.findAllByTestId('incident-row')
    await waitFor(() => {
      expect(within(incidents[0]!).getByText('23 Oct 2027 04:00:00 UTC')).toBeInTheDocument()
      expect(within(incidents[0]!).queryByText('23 Oct 2027')).toBeNull()
    })
  })

  it('renders the bounded risk distribution with honest percentage shares', async () => {
    installMocks({
      risks: [
        risk({ id: 'r1', level: 'high', score: 90 }),
        risk({ id: 'r2', level: 'high', score: 70 }),
        risk({ id: 'r3', level: 'low', score: 30 }),
        risk({ id: 'r4', level: 'low', score: 20 }),
      ],
    })
    renderDash()

    const levels = await screen.findAllByTestId('risk-level')
    await waitFor(() => {
      expect(levels[0]).toHaveTextContent('critical')
      expect(levels[0]).toHaveTextContent('0 · 0%')
      expect(levels[1]).toHaveTextContent('high')
      expect(levels[1]).toHaveTextContent('2 · 50%')
      expect(levels[3]).toHaveTextContent('low')
      expect(levels[3]).toHaveTextContent('2 · 50%')
      expect(screen.getByText(/shares of the bounded feed/i)).toBeInTheDocument()
    })

    expect(screen.getAllByTestId('kpi-value')[1]!).toHaveTextContent('0')
  })

  it('renders the incident table with correlation joins and navigation links', async () => {
    installMocks()
    renderDash()

    const rows = await screen.findAllByTestId('incident-row')
    await waitFor(() => {
      expect(within(rows[0]!).getByText(/CORR1/)).toBeInTheDocument()
      expect(within(rows[0]!).getByRole('link', { name: 'inspect' })).toHaveAttribute(
        'href',
        '/incidents/CORR-1',
      )
      expect(within(rows[0]!).getByText('high')).toBeInTheDocument()
      expect(within(rows[0]!).getByText('active')).toBeInTheDocument()
      const viewAll = screen.getAllByRole('link', { name: /view all/i })
      expect(viewAll.map((link) => link.getAttribute('href')).filter(Boolean)).toContain('/incidents')
    })
  })

  it('shows real rules summary from the live rules API', async () => {
    installMocks()
    renderDash()

    await screen.findByText('Detection rules')
    expect(screen.getByText('Total')).toBeInTheDocument()
    expect(screen.getByText('Sigma')).toBeInTheDocument()
    expect(screen.getByText('YARA')).toBeInTheDocument()
    expect(screen.getByText('0 disabled')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getAllByText('13').length).toBeGreaterThanOrEqual(1)
      expect(screen.getByText('8')).toBeInTheDocument()
      expect(screen.getByText('5')).toBeInTheDocument()
    })
    expect(screen.getByRole('link', { name: /VIEW RULES/i })).toHaveAttribute('href', '/detection-rules')
  })

  it('reports system health honestly from probes and marks unknowns as UNKNOWN', async () => {
    installMocks()
    renderDash()

    await waitFor(() => {
      expect(screen.getByTestId('db-health')).toHaveTextContent('connected')
      expect(screen.getByTestId('kafka-health')).toHaveTextContent('healthy')
      expect(screen.getByTestId('api-health')).toHaveTextContent('HEALTHY')
      expect(screen.getByTestId('ai-health')).toHaveTextContent('UNKNOWN')
    })
  })

  it('keeps threat intelligence and response/policy panels honest when no API serves them', async () => {
    installMocks()
    renderDash()

    const ti = await screen.findByTestId('ti-empty')
    expect(ti).toHaveTextContent('No threat-intelligence indicators')
    expect(ti).toHaveTextContent('Nothing is fabricated here')

    const simulated = screen.getByTestId('simulated-operations')
    expect(simulated).toHaveTextContent('SIMULATED')
    const policyPanel = screen
      .getByText('Response & policy activity')
      .closest('.overflow-hidden') as HTMLElement
    expect(within(policyPanel).getAllByText('0')).toHaveLength(7)
  })

  it('exposes the activity window selector with 30d default and renders a chronological chart', async () => {
    installMocks()
    renderDash()

    await screen.findByText('Security activity')
    const windowBar = screen.getByTestId('activity-window')
    expect(within(windowBar).getByTestId('window-30d')).toHaveAttribute('aria-pressed', 'true')
    expect(await screen.findByText(/distinct time bucket/i)).toHaveTextContent('distinct time buckets in the 30D window')

    await userEvent.click(screen.getByTestId('window-24h'))
    expect(screen.getByTestId('window-24h')).toHaveAttribute('aria-pressed', 'true')
  })

  it('shows an honest insufficient-data state when the feed has too few distinct buckets', async () => {
    installMocks({
      detections: [detection({ detected_at: at(5 * DAY) })],
      correlations: [],
      risks: [],
    })
    renderDash()

    const note = await screen.findByTestId('insufficient-data')
    expect(note).toHaveTextContent('Insufficient historical data')
    expect(note).toHaveTextContent('not enough to draw a meaningful series')
    expect(note).toHaveTextContent('too few distinct timestamps to draw any chronological series')
  })

  it('shows empty states when all bounded feeds are empty', async () => {
    installMocks({ detections: [], correlations: [], risks: [], memories: [] })
    renderDash()

    expect(await screen.findByText('No incidents')).toBeInTheDocument()
    expect(screen.getByText('No detections')).toBeInTheDocument()
    expect(screen.getByText('No correlations')).toBeInTheDocument()
    expect(screen.getByText('No risk assessments')).toBeInTheDocument()
    expect(screen.getByText('No security events')).toBeInTheDocument()
  })

  it('surfaces feed errors per panel and offers retry', async () => {
    installMocks({ reject: ['risksApi'] })
    renderDash()

    expect(await screen.findByTestId('dashboard-error')).toBeInTheDocument()
    expect(screen.getByText('Risk data is unavailable.')).toBeInTheDocument()
    expect(screen.getByText('Incident data is unavailable.')).toBeInTheDocument()

    const callsBefore = RISKS_API.recent.mock.calls.length
    await userEvent.click(screen.getByRole('button', { name: /retry all/i }))
    expect(RISKS_API.recent.mock.calls.length).toBeGreaterThan(callsBefore)
  })

  it('shows skeletons while feeds load, then fills them in', async () => {
    installMocks()
    let resolveDetections!: (value: DetectionResult[]) => void
    const pending = new Promise<DetectionResult[]>((resolve) => {
      resolveDetections = resolve
    })
    DETECTION_API.recent.mockReturnValue(pending)

    renderDash()

    expect(screen.getAllByTestId('loading-rows').length).toBeGreaterThan(0)

    await act(async () => {
      resolveDetections([detection()])
    })
    expect(await screen.findByTestId('detection-row', undefined, { timeout: 3000 })).toBeInTheDocument()
  })

  it('shows the pending approvals feed only to SOC roles and restricts others', async () => {
    useAuthStore.getState().setUser({
      id: 'u-1',
      email: 'analyst@sentinel.dev',
      is_active: true,
      role: 'analyst',
    })
    installMocks({
      approvals: [
        approval({ id: 'app-1', approval_id: 'APPROVAL-1', target: '10.0.0.8', policy_rule_id: 'rule-elevated-01' }),
        approval({
          id: 'app-2',
          approval_id: 'APPROVAL-2',
          target: 'malicious.example',
          action_type: 'block_domain',
          risk_level: 'critical',
          requested_by_role: 'ciso',
          requested_at: at(3 * DAY),
        }),
      ],
    })
    renderDash()

    expect(await screen.findByTestId('pending-approvals')).toBeInTheDocument()
    const rows = await screen.findAllByTestId('approval-row')
    expect(rows).toHaveLength(2)
    expect(within(rows[0]!).getByText('10.0.0.8')).toBeInTheDocument()
    expect(within(rows[0]!).getByText('rule-elevated-01')).toBeInTheDocument()
    expect(within(rows[0]!).getByText('block_ip')).toBeInTheDocument()
    expect(within(rows[0]!).getByRole('button', { name: 'Approve' })).toBeInTheDocument()
    expect(within(rows[0]!).getByRole('button', { name: 'Reject' })).toBeInTheDocument()
    expect(within(rows[1]!).getByText('malicious.example')).toBeInTheDocument()
    expect(within(rows[1]!).getByText('ciso')).toBeInTheDocument()
    expect(APPROVALS_API.recent).toHaveBeenCalledWith(10, 'pending')
  })

  it('withholds the approvals feed from roles the backend does not authorize', async () => {
    useAuthStore.getState().setUser({
      id: 'u-2',
      email: 'viewer@sentinel.dev',
      is_active: true,
      role: 'viewer',
    })
    installMocks()
    renderDash()

    const panel = await screen.findByTestId('pending-approvals')
    expect(panel).toHaveTextContent('Approval access restricted')
    expect(panel).toHaveTextContent('viewer')
    expect(APPROVALS_API.recent).not.toHaveBeenCalled()
    expect(screen.queryByTestId('approval-row')).toBeNull()
  })

  it('approves a pending approval with a required comment and refreshes the feed', async () => {
    useAuthStore.getState().setUser({
      id: 'u-1',
      email: 'analyst@sentinel.dev',
      is_active: true,
      role: 'analyst',
    })
    installMocks({ approvals: [approval()] })
    APPROVALS_API.approve.mockResolvedValue(
      approval({ id: 'app-1', approval_id: 'APPROVAL-1', status: 'approved' }),
    )
    renderDash()

    const row = (await screen.findAllByTestId('approval-row'))[0]!
    await userEvent.click(within(row).getByRole('button', { name: 'Approve' }))

    const comment = within(row).getByTestId('approval-comment')
    expect(within(row).getByTestId('approval-confirm')).toBeDisabled()
    await userEvent.type(comment, 'looks good')
    await userEvent.click(within(row).getByTestId('approval-confirm'))

    await waitFor(() => {
      expect(APPROVALS_API.approve).toHaveBeenCalledWith('APPROVAL-1', { comment: 'looks good' })
    })
    await waitFor(() => {
      expect(APPROVALS_API.recent.mock.calls.length).toBeGreaterThanOrEqual(2)
    })
    expect(screen.queryByTestId('approval-confirm')).toBeNull()
  })

  it('rejects with a required comment and surfaces resolution errors inline', async () => {
    useAuthStore.getState().setUser({
      id: 'u-1',
      email: 'analyst@sentinel.dev',
      is_active: true,
      role: 'analyst',
    })
    installMocks({ approvals: [approval()] })
    APPROVALS_API.reject.mockRejectedValue(new Error('Insufficient permissions'))
    renderDash()

    const row = (await screen.findAllByTestId('approval-row'))[0]!
    await userEvent.click(within(row).getByRole('button', { name: 'Reject' }))
    await userEvent.type(within(row).getByTestId('approval-comment'), 'not warranted')
    await userEvent.click(within(row).getByTestId('approval-confirm'))

    await waitFor(() => {
      expect(APPROVALS_API.reject).toHaveBeenCalledWith('APPROVAL-1', { comment: 'not warranted' })
      expect(within(row).getByText('Insufficient permissions')).toBeInTheDocument()
    })
  })

  it('shows an empty approvals state when nothing awaits a decision', async () => {
    useAuthStore.getState().setUser({
      id: 'u-1',
      email: 'analyst@sentinel.dev',
      is_active: true,
      role: 'analyst',
    })
    installMocks({ approvals: [] })
    renderDash()

    const panel = await screen.findByTestId('pending-approvals')
    await waitFor(() => {
      expect(panel).toHaveTextContent('No pending approvals')
      expect(panel).toHaveTextContent('human decision')
    })
  })
})