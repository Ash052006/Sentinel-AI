import { Badge } from './ui/badge'
import {
  approvalStatusMeta,
  memoryTypeLabel,
  policyDecisionMeta,
  provenanceLabel,
  provenanceTone,
  riskTone,
  ruleTypeLabel,
  severityTone,
  statusMeta,
} from '../lib/labels'
import type {
  ApprovalStatus,
  CorrelationStatus,
  DetectionSeverity,
  MemoryType,
  PolicyDecisionStatus,
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

export function ApprovalStatusBadge({ status }: { status: ApprovalStatus }) {
  const meta = approvalStatusMeta[status]
  return <Badge tone={meta.tone}>{meta.label}</Badge>
}

export function PolicyDecisionBadge({ status }: { status: PolicyDecisionStatus }) {
  const meta = policyDecisionMeta[status]
  return <Badge tone={meta.tone}>{meta.label}</Badge>
}