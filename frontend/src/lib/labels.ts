import type {
  ApprovalStatus,
  AttackPathNodeType,
  ConfidenceBand,
  CorrelationStatus,
  DebateAgentRole,
  DebateConsensusState,
  DebateRoundKind,
  DebateStance,
  DebateWeaknessKind,
  DetectionSeverity,
  EvidenceStance,
  EvidenceSupport,
  IndicatorLookupStatus,
  IndicatorType,
  KnowledgeNodeType,
  KnowledgeRelationshipType,
  LimitationKind,
  LookupStatusLabel,
  MemoryType,
  PolicyDecisionStatus,
  PredictionBasis,
  PredictionDepth,
  PredictionKind,
  PredictionStatus,
  Provenance,
  RiskLevel,
  RuleType,
  TargetBasis,
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

export const approvalStatusMeta: Record<
  ApprovalStatus,
  { label: string; tone: Tone }
> = {
  pending: { label: 'pending', tone: 'medium' },
  approved: { label: 'approved', tone: 'low' },
  rejected: { label: 'rejected', tone: 'critical' },
  expired: { label: 'expired', tone: 'muted' },
  cancelled: { label: 'cancelled', tone: 'muted' },
}

export const policyDecisionMeta: Record<
  PolicyDecisionStatus,
  { label: string; tone: Tone }
> = {
  allowed: { label: 'allowed', tone: 'low' },
  denied: { label: 'denied', tone: 'critical' },
  requires_approval: { label: 'requires approval', tone: 'medium' },
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
// ---------------------------------------------------------------------------
// Threat Intelligence
// ---------------------------------------------------------------------------

/**
 * Indicator type labels.  SOC consoles conventionally read these as short
 * uppercase column values, matching the `memoryTypeLabel` precedent of a
 * small, total lookup table rather than a free-form transform.
 */
export const indicatorTypeLabel: Record<IndicatorType, string> = {
  ip: 'IP',
  domain: 'DOMAIN',
  url: 'URL',
  hash: 'HASH',
}

export const indicatorTypeTone: Record<IndicatorType, Tone> = {
  ip: 'accent',
  domain: 'medium',
  url: 'high',
  hash: 'neutral',
}

/**
 * Indicator lookup-rollup status.
 *
 * `muted` for `no_lookup` because "we never asked" is an absence, not a
 * finding.  `low` for `enriched` because a provider returned data — which
 * is *not* a statement that the indicator is benign.  `high` for `partial`
 * and `critical` for `failed` because a provider that could not answer is an
 * operational problem the analyst must see, not a threat judgement.
 */
export const indicatorLookupStatusMeta: Record<
  IndicatorLookupStatus,
  { label: string; tone: Tone }
> = {
  no_lookup: { label: 'no lookup', tone: 'muted' },
  enriched: { label: 'enriched', tone: 'low' },
  partial: { label: 'partial', tone: 'high' },
  failed: { label: 'failed', tone: 'critical' },
}

/**
 * Per-lookup provider status.
 *
 * `ENRICHED` (provider returned data) is `low`, `NO DATA` (queried, nothing
 * held) is `muted`, and every failure label is `high`/`critical`.  There is
 * deliberately no 'malicious' label in this map: Step 8A persists no
 * verdict, so the UI has no honest way to render one.
 */
export const lookupStatusMeta: Record<LookupStatusLabel, { tone: Tone }> = {
  ENRICHED: { tone: 'low' },
  'NO DATA': { tone: 'muted' },
  FAILED: { tone: 'critical' },
  'RATE LIMITED': { tone: 'high' },
  'TIMED OUT': { tone: 'high' },
  REJECTED: { tone: 'muted' },
  UNAVAILABLE: { tone: 'critical' },
}

// ---------------------------------------------------------------------------
// V3.22 Knowledge Graph
// ---------------------------------------------------------------------------

/**
 * Knowledge-graph node labels and colours.
 *
 * Kept separate from the V2.21 `NODE_LABELS` map rather than merged: the two
 * vocabularies are different closed sets with different meanings for the same
 * concept (V2.21 "risk" is a projection, V3.22 `RISK_ASSESSMENT` is the
 * persisted `risk_assessments` row), so sharing one map would invite a UI that
 * conflates a projection with evidence.
 */
export const KG_NODE_LABELS: Record<KnowledgeNodeType, string> = {
  EVENT: 'Event',
  DETECTION: 'Detection',
  CORRELATION: 'Correlation',
  RISK_ASSESSMENT: 'Risk',
  THREAT_INDICATOR: 'Indicator',
  INCIDENT_MEMORY: 'Memory',
  THREAT_HUNT: 'Hunt',
  APPROVAL: 'Approval',
  SOAR_EXECUTION: 'SOAR',
  INCIDENT_REPORT: 'Report',
}

export const KG_NODE_COLORS: Record<KnowledgeNodeType, string> = {
  EVENT: '#8fa3bd',
  DETECTION: '#ff9f43',
  CORRELATION: '#4cc2ff',
  RISK_ASSESSMENT: '#ff5b5b',
  THREAT_INDICATOR: '#ffd166',
  INCIDENT_MEMORY: '#3dd68c',
  THREAT_HUNT: '#58c7c7',
  APPROVAL: '#c78bff',
  SOAR_EXECUTION: '#5ce1b0',
  INCIDENT_REPORT: '#c3a6ff',
}

/**
 * Column order for the layered layout.  Anchored on the evidence chain a SOC
 * analyst reads left to right: the correlation, the detections it correlates,
 * then the assessment and the corroborating records around it.
 */
export const KG_TYPE_ORDER: Record<KnowledgeNodeType, number> = {
  CORRELATION: 0,
  EVENT: 1,
  DETECTION: 2,
  RISK_ASSESSMENT: 3,
  INCIDENT_MEMORY: 4,
  THREAT_HUNT: 5,
  THREAT_INDICATOR: 6,
  APPROVAL: 7,
  SOAR_EXECUTION: 8,
  INCIDENT_REPORT: 9,
}

/**
 * Relationship labels.  Phrased as the reading of the edge, e.g. an event
 * `produced_detection` a detection — the auditor always sees which side is
 * the subject.
 */
export const KG_RELATIONSHIP_LABELS: Record<KnowledgeRelationshipType, string> = {
  produced_detection: 'produced',
  member_of_correlation: 'member of',
  assessed_by: 'assessed by',
  associated_with_indicator: 'associated with',
  recalled_by: 'recalled by',
  requires_approval: 'requires',
  authorized_execution: 'authorized',
  responded_by_execution: 'responded by',
  reported_by: 'reported by',
  investigated_by_hunt: 'investigated by',
}

// ---------------------------------------------------------------------------
// V3.23 — debate vocabulary
//
// The backend vocabularies are closed sets (app/agents/debate/vocabulary.py),
// so these maps are exhaustive and a new server-side value is a type error here
// rather than a blank badge at runtime.
// ---------------------------------------------------------------------------

export const DEBATE_ROLE_LABELS: Record<DebateAgentRole, string> = {
  detection_analyst: 'Detection Analyst',
  threat_intelligence_analyst: 'Threat Intelligence Analyst',
  behavioral_analyst: 'Behavioral Analyst',
  incident_investigator: 'Incident Investigator',
  skeptic: 'Skeptic / Contrarian',
}

export const DEBATE_ROUND_LABELS: Record<DebateRoundKind, string> = {
  round_0_shared_evidence: 'Shared evidence',
  round_1_independent_assessments: 'Independent assessments',
  round_2_cross_agent_arguments: 'Cross-agent arguments',
  round_3_counterarguments: 'Counterarguments',
  round_4_reconciliation: 'Reconciliation',
}

export const DEBATE_STANCE_LABELS: Record<DebateStance, string> = {
  supports: 'supports',
  opposes: 'opposes',
}

export const DEBATE_WEAKNESS_LABELS: Record<DebateWeaknessKind, string> = {
  contradictory_evidence: 'contradictory evidence',
  weak_evidence: 'weak evidence',
  missing_evidence: 'missing evidence',
  alternative_explanation: 'alternative explanation',
  overconfidence: 'overconfidence',
}

/**
 * Tone reflects how settled the conclusion is, not how alarming it is.
 * `consensus` is the only state reserved for full agreement, so it is the only
 * one rendered as settled; `insufficient_evidence` is deliberately muted — it
 * is an honest "the graph cannot answer this", not a weak finding.
 */
export const DEBATE_CONSENSUS_META: Record<
  DebateConsensusState,
  { label: string; tone: Tone }
> = {
  consensus: { label: 'consensus', tone: 'low' },
  partial_consensus: { label: 'partial consensus', tone: 'medium' },
  contested: { label: 'contested', tone: 'high' },
  insufficient_evidence: { label: 'insufficient evidence', tone: 'muted' },
}

/**
 * Tone reflects how settled the projection is. As with the debate consensus,
 * `insufficient_evidence` is deliberately muted: the engine correctly declined
 * to speculate, which is an honest answer rather than a weak finding.
 */
export const PREDICTION_STATUS_META: Record<
  PredictionStatus,
  { label: string; tone: Tone }
> = {
  PREDICTED: { label: 'predicted', tone: 'medium' },
  LOW_CONFIDENCE: { label: 'low confidence', tone: 'muted' },
  INSUFFICIENT_EVIDENCE: { label: 'insufficient evidence', tone: 'muted' },
  CONTESTED: { label: 'contested', tone: 'high' },
}

export const PREDICTION_KIND_LABELS: Record<PredictionKind, string> = {
  NEXT_TACTIC: 'Next tactic',
  NEXT_TECHNIQUE: 'Next technique',
  NEXT_ACTIVITY: 'Next activity',
  ESCALATION: 'Escalation',
  LATERAL_MOVEMENT: 'Lateral movement',
  PERSISTENCE: 'Persistence',
  CREDENTIAL_ACCESS: 'Credential access',
  EXFILTRATION: 'Exfiltration',
  COMMAND_AND_CONTROL: 'Command and control',
}

/**
 * Depth is the horizon, and the wording keeps it explicit: a projection is not
 * an observation. `immediate` is the next stage, `subsequent` the one after.
 */
export const PREDICTION_DEPTH_LABELS: Record<PredictionDepth, string> = {
  immediate: 'next stage',
  subsequent: 'one stage beyond',
}

/**
 * `basis` is why a candidate was allowed to exist at all. `analytical_hypothesis`
 * is deliberately the weakest and is never rendered as grounded, because it is
 * the one basis that did not come from a persisted mapping or a debate claim.
 */
export const PREDICTION_BASIS_LABELS: Record<PredictionBasis, string> = {
  persisted_attack_mapping: 'persisted ATT&CK mapping',
  debate_hypothesis: 'debate hypothesis',
  persisted_relationship: 'persisted relationship',
  analytical_hypothesis: 'analytical hypothesis',
}

export const PREDICTION_TARGET_BASIS_LABELS: Record<TargetBasis, string> = {
  persisted_attack_mapping: 'persisted ATT&CK mapping',
  debate_referenced: 'debate reference',
  analytical_hypothesis: 'analytical hypothesis',
}

export const PREDICTION_EVIDENCE_SUPPORT_LABELS: Record<EvidenceSupport, string> = {
  persisted_evidence: 'persisted evidence',
  debate_claim: 'debate claim',
  mixed: 'persisted evidence and debate',
}

export const PREDICTION_CONFIDENCE_BAND_LABELS: Record<ConfidenceBand, string> = {
  very_low: 'very low',
  low: 'low',
  moderate: 'moderate',
  high: 'high',
}

export const PREDICTION_LIMITATION_LABELS: Record<LimitationKind, string> = {
  no_persisted_attack_mapping: 'No persisted ATT&CK mapping',
  no_debate_artifact: 'No debate available',
  debate_insufficient_evidence: 'Debate found insufficient evidence',
  debate_contested: 'Debate was contested',
  single_source_evidence: 'Single source',
  no_contradicting_evidence_available: 'No contradicting evidence available',
  graph_truncated: 'Graph truncated',
  input_source_unavailable: 'Input source unavailable',
  horizon_capped: 'Horizon capped',
  analytical_inference_only: 'Analytical inference only',
  no_persisted_technique: 'No persisted technique',
}

/** Ties a contradicting citation to the reading that is challenging. */
export const PREDICTION_STANCE_TONES: Record<EvidenceStance, Tone> = {
  supporting: 'low',
  contradicting: 'high',
}

export const PREDICTION_STANCE_LABELS: Record<EvidenceStance, string> = {
  supporting: 'supporting',
  contradicting: 'contradicting',
}
