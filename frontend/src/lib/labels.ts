import type {
  AttackPathNodeType,
  CorrelationStatus,
  DetectionSeverity,
  MemoryType,
  Provenance,
  RiskLevel,
  RuleType,
} from '../types/api'

export type Tone =
  | 'neutral'
  | 'muted'
  | 'accent'
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'

export const severityTone: Record<DetectionSeverity, Tone> = {
  low: 'low',
  medium: 'medium',
  high: 'high',
  critical: 'critical',
}

export const riskTone: Record<RiskLevel, Tone> = {
  low: 'low',
  medium: 'medium',
  high: 'high',
  critical: 'critical',
}

export const statusMeta: Record<CorrelationStatus, { label: string; tone: Tone }> = {
  candidate: { label: 'candidate', tone: 'neutral' },
  active: { label: 'active', tone: 'accent' },
  closed: { label: 'closed', tone: 'muted' },
}

export const ruleTypeLabel: Record<RuleType, string> = {
  sigma: 'sigma',
  yara: 'yara',
}

export const memoryTypeLabel: Record<MemoryType, string> = {
  incident_summary: 'incident summary',
  indicator_observation: 'indicator',
  attack_pattern: 'attack pattern',
  investigation_finding: 'investigation finding',
  mitigation_outcome: 'mitigation outcome',
}

export function provenanceLabel(provenance: Provenance): string {
  return provenance.replace(/_/g, ' ')
}

export const provenanceTone: Record<Provenance, Tone> = {
  observed: 'low',
  enriched: 'accent',
  reconstructed: 'medium',
  detected: 'high',
  correlated: 'accent',
  risk_assessed: 'medium',
  ai_generated: 'neutral',
  attribution_assessed: 'neutral',
  recalled: 'muted',
  learned: 'muted',
  policy_decided: 'neutral',
  response_executed: 'neutral',
  approval_reviewed: 'neutral',
}

export const NODE_LABELS: Record<AttackPathNodeType, string> = {
  correlation: 'Correlation',
  detection: 'Detection',
  indicator: 'Indicator',
  risk: 'Risk',
  memory: 'Memory',
  hunt: 'Hunt',
  policy_decision: 'Policy',
  approval: 'Approval',
  soar_execution: 'SOAR',
}

export const NODE_COLORS: Record<AttackPathNodeType, string> = {
  correlation: '#4cc2ff',
  detection: '#ff9f43',
  indicator: '#ffd166',
  risk: '#ff5b5b',
  memory: '#3dd68c',
  hunt: '#58c7c7',
  policy_decision: '#8f8fff',
  approval: '#c78bff',
  soar_execution: '#5ce1b0',
}