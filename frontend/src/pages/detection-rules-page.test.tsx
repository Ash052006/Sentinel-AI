import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DetectionRulesPage } from './detection-rules-page'
import { renderWithProviders } from '../test/utils'
import type {
  DetectionRule,
  DetectionRuleAnalytics,
  DetectionRuleDetail,
} from '../types/api'

function makeRule(overrides: Partial<DetectionRule> = {}): DetectionRule {
  return {
    rule_id: overrides.rule_id ?? '11111111-1111-4111-8111-111111111111',
    name: overrides.name ?? 'Suspicious PowerShell Execution',
    description: overrides.description ?? 'Detects obfuscated powershell.',
    rule_type: overrides.rule_type ?? 'sigma',
    severity: overrides.severity ?? 'high',
    enabled: overrides.enabled ?? true,
    version: overrides.version ?? '1.0.0',
    category: overrides.category ?? 'process',
    tags: overrides.tags ?? [],
    author: overrides.author ?? 'Team',
    date: overrides.date ?? '2024-06-15',
    status: overrides.status ?? 'stable',
    source_file: overrides.source_file ?? 'sigma/01-test.yml',
    match_count: overrides.match_count ?? 0,
    last_matched_at: overrides.last_matched_at ?? null,
  }
}

function makeDetail(rule: DetectionRule, content: string): DetectionRuleDetail {
  return { ...rule, content, content_format: 'yaml' }
}

function makeAnalytics(overrides: Partial<DetectionRuleAnalytics> = {}): DetectionRuleAnalytics {
  return {
    window: overrides.window ?? '30d',
    total_detections: overrides.total_detections ?? 0,
    buckets: overrides.buckets ?? [],
    by_severity: overrides.by_severity ?? [
      { severity: 'low', count: 0 },
      { severity: 'medium', count: 0 },
      { severity: 'high', count: 0 },
      { severity: 'critical', count: 0 },
    ],
    rules_with_matches: overrides.rules_with_matches ?? 0,
  }
}

vi.mock('../api/detectionRules', () => ({
  detectionRulesApi: {
    list: vi.fn(),
    get: vi.fn(),
    analytics: vi.fn(),
  },
}))

vi.mock('../api/detections', () => ({
  detectionsApi: {
    recent: vi.fn(),
  },
}))

const detectionRulesApi = (await import('../api/detectionRules')).detectionRulesApi
const detectionsApi = (await import('../api/detections')).detectionsApi

describe('DetectionRulesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(detectionRulesApi.list).mockResolvedValue([
      makeRule({ rule_id: 'r1', name: 'Alpha Rule', rule_type: 'sigma', severity: 'high', match_count: 3 }),
      makeRule({ rule_id: 'r2', name: 'Beta Rule', rule_type: 'yara', severity: 'critical', match_count: 0 }),
    ])
    vi.mocked(detectionRulesApi.analytics).mockResolvedValue(
      makeAnalytics({
        total_detections: 3,
        buckets: [{ bucket_start: '2026-09-01T00:00:00Z', detections: 3 }],
        by_severity: [
          { severity: 'critical', count: 0 },
          { severity: 'high', count: 3 },
          { severity: 'medium', count: 0 },
          { severity: 'low', count: 0 },
        ],
      }),
    )
    vi.mocked(detectionRulesApi.get).mockResolvedValue(
      makeDetail(makeRule({ rule_id: 'r1', name: 'Alpha Rule' }), 'title: Alpha Rule\nid: r1\n'),
    )
    vi.mocked(detectionsApi.recent).mockResolvedValue([])
  })

  it('computes KPIs from the loaded rule list', async () => {
    renderWithProviders(<DetectionRulesPage />)

    expect((await screen.findAllByText('2')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('1').length).toBeGreaterThan(0)
    expect(screen.getAllByText('3').length).toBeGreaterThan(0)
    expect(screen.getByText('Total rules')).toBeInTheDocument()
    expect(screen.getAllByText('Sigma').length).toBeGreaterThan(0)
    expect(screen.getAllByText('YARA').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Enabled').length).toBeGreaterThan(0)
  })

  it('renders rule rows with type and severity badges', async () => {
    renderWithProviders(<DetectionRulesPage />)

    expect(await screen.findByText('Alpha Rule')).toBeInTheDocument()
    expect(screen.getByText('Beta Rule')).toBeInTheDocument()
    expect(screen.getAllByText('sigma').length).toBeGreaterThan(0)
    expect(screen.getAllByText('yara').length).toBeGreaterThan(0)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('shows honest match counts of zero for rules that never matched', async () => {
    renderWithProviders(<DetectionRulesPage />)

    expect(await screen.findByText('Alpha Rule')).toBeInTheDocument()
    expect(screen.getAllByText('never').length).toBeGreaterThan(0)
    expect(
      screen.getByText(/rules with persisted matches: 1/),
    ).toBeInTheDocument()
  })

  it('opens the preview panel for a selected rule', async () => {
    const user = userEvent.setup()
    renderWithProviders(<DetectionRulesPage />)

    const rows = await screen.findAllByTestId('rule-row')
    await user.click(rows[0])

    await waitFor(() =>
      expect(screen.getByTestId('rule-preview')).toBeInTheDocument(),
    )
    expect(screen.getByText(/title: Alpha Rule/i)).toBeInTheDocument()
  })

  it('shows an empty state when no analytics data exists (never fabricates)', async () => {
    vi.mocked(detectionRulesApi.analytics).mockResolvedValue(makeAnalytics())
    renderWithProviders(<DetectionRulesPage />)

    expect(
      await screen.findByText('Historical match data unavailable'),
    ).toBeInTheDocument()
  })
})