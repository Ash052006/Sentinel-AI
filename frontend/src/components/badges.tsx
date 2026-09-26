import { Badge } from './ui/badge'
import {
  memoryTypeLabel,
  provenanceLabel,
  provenanceTone,
  riskTone,
  ruleTypeLabel,
  severityTone,
  statusMeta,
} from '../lib/labels'
import type {
  CorrelationStatus,
  DetectionSeverity,
  MemoryType,
  Provenance,
  RiskLevel,
  RuleType,
} from '../types/api'

export function SeverityBadge({ severity }: { severity: DetectionSeverity }) {
  return <Badge tone={severityTone[severity]}>{severity}</Badge>
}

export function RiskLevelBadge({ level }: { level: RiskLevel }) {
  return <Badge tone={riskTone[level]}>{level}</Badge>
}

export function CorrelationStatusBadge({
  status,
}: {
  status: CorrelationStatus
}) {
  const meta = statusMeta[status]
  return <Badge tone={meta.tone}>{meta.label}</Badge>
}

export function ProvenanceBadge({ provenance }: { provenance: Provenance }) {
  return <Badge tone={provenanceTone[provenance]}>{provenanceLabel(provenance)}</Badge>
}

export function MemoryTypeBadge({ type }: { type: MemoryType }) {
  return <Badge tone="muted">{memoryTypeLabel[type]}</Badge>
}

export function RuleTypeBadge({ ruleType }: { ruleType: RuleType }) {
  return <Badge tone="muted">{ruleTypeLabel[ruleType]}</Badge>
}