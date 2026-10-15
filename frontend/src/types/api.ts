/**
 * Typed mirrors of the SentinelAI backend read-model contracts.
 *
 * Field names and shapes match the FastAPI response schemas exactly
 * (backend/app/schemas/*_query.py, audit.py, auth.py, soc_query.py,
 * routes/health.py). Timestamps arrive as ISO-8601 UTC strings.
 */

export type Provenance =
  | 'observed'
  | 'enriched'
  | 'reconstructed'
  | 'detected'
  | 'correlated'
  | 'risk_assessed'
  | 'ai_generated'
  | 'attribution_assessed'
  | 'recalled'
  | 'learned'
  | 'policy_decided'
  | 'response_executed'
  | 'approval_reviewed'

export type RuleType = 'sigma' | 'yara'
export type DetectionSeverity = 'low' | 'medium' | 'high' | 'critical'
export type CorrelationStatus = 'candidate' | 'active' | 'closed'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type MemoryType =
  | 'incident_summary'
  | 'indicator_observation'
  | 'attack_pattern'
  | 'investigation_finding'
  | 'mitigation_outcome'

export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

// ---------------------------------------------------------------------------
// Detections (app/schemas/detection_query.py)
// ---------------------------------------------------------------------------

export interface DetectionResult {
  id: string
  event_id: string
  detection_id: string
  rule_id: string
  rule_type: RuleType
  rule_version: string
  severity: DetectionSeverity
  matched: boolean
  confidence: number
  evidence: Record<string, unknown>
  result_metadata: Record<string, unknown>
  detected_at: string
  provenance: Provenance
  created_at: string
  updated_at: string
}

export interface DetectionFailure {
  id: string
  event_id: string
  engine: string
  rule_id: string
  error_type: string
  error_message: string
  failed_at: string
  provenance: Provenance
  created_at: string
  updated_at: string
}

export interface DetectionAnalysis {
  event_id: string
  result_count: number
  failure_count: number
  first_detected_at: string | null
  last_detected_at: string | null
  first_failed_at: string | null
  last_failed_at: string | null
  provenance: Provenance
  results: DetectionResult[]
  failures: DetectionFailure[]
}

// ---------------------------------------------------------------------------
// Detection Rules (app/schemas/detection_rule_query.py) — Step 26
// ---------------------------------------------------------------------------

export interface DetectionRule {
  rule_id: string
  name: string
  description: string
  rule_type: RuleType
  severity: DetectionSeverity
  enabled: boolean
  version: string
  category: string | null
  tags: string[]
  author: string | null
  date: string | null
  status: string | null
  source_file: string | null
  match_count: number
  last_matched_at: string | null
}

export interface DetectionRuleDetail extends DetectionRule {
  content: string
  content_format: 'yaml' | 'yara'
}

export interface DetectionRuleSeverityCount {
  severity: DetectionSeverity
  count: number
}

export interface DetectionRuleMatchBucket {
  bucket_start: string
  detections: number
}

export interface DetectionRuleAnalytics {
  window: '1h' | '6h' | '24h' | '7d' | '30d'
  total_detections: number
  buckets: DetectionRuleMatchBucket[]
  by_severity: DetectionRuleSeverityCount[]
  rules_with_matches: number
}

// ---------------------------------------------------------------------------
// Detection-as-Code governed lifecycle (app/schemas/detection_as_code.py)
// ---------------------------------------------------------------------------

export type BumpClass = 'major' | 'minor' | 'patch'
export type ValidationOutcome = 'none' | 'validating' | 'validated' | 'failed'
export type ReleaseState = 'draft' | 'validating' | 'validated' | 'released' | 'failed'
export type DeploymentState = 'undeployed' | 'deployed'
export type ChangeKind = 'initialized' | 'version_added' | 'rolled_back'

export interface DetectionRuleVersionRecord {
  version_id: string
  rule_id: string
  version: string
  rule_type: RuleType
  severity: DetectionSeverity
  title: string
  description: string
  author: string | null
  status: string | null
  category: string | null
  source_path: string
  source_hash: string
  hash_algorithm: string
  tags: string[]
  enabled: boolean
  validation_status: ValidationOutcome
  validation_error: string | null
  compiled: boolean
  positive_passed: boolean
  negative_passed: boolean
  release_state: ReleaseState
  deployment_state: DeploymentState
  rollback_from: string | null
  created_by: string | null
  created_by_role: string | null
  created_at: string
  updated_at: string
}

export interface DetectionRuleReleaseRecord {
  release_id: string
  version_id: string
  rule_id: string
  version: string
  release_state: ReleaseState
  deployment_state: DeploymentState
  validated_at: string | null
  released_at: string | null
  deployed_at: string | null
  rollback_target_version: string | null
  created_at: string
  updated_at: string
}

export interface DetectionRuleChangeRecord {
  change_id: string
  rule_id: string
  change_kind: ChangeKind
  from_version: string | null
  to_version: string
  to_source_hash: string
  bump_class: BumpClass | null
  change_reason: string | null
  created_by: string | null
  created_at: string
}

export interface DetectionAsCodeValidationDetail {
  rule_id: string
  version: string
  outcome: ValidationOutcome
  manifest_valid: boolean
  source_exists: boolean
  source_hash_match: boolean
  path_safe: boolean
  secret_safe: boolean
  rule_type_matches: boolean
  severity_valid: boolean
  metadata_complete: boolean
  compiles: boolean
  positive_passed: boolean
  negative_passed: boolean
  errors: string[]
}

export type DetectionAsCodeRulePage = Page<DetectionRuleVersionRecord>

export interface DetectionAsCodeRuleDetail {
  current: DetectionRuleVersionRecord
  validation: DetectionAsCodeValidationDetail
  releases: DetectionRuleReleaseRecord[]
  changes: DetectionRuleChangeRecord[]
}

export interface ValidateRuleRequest {
  rule_id: string
  version?: string | null
  bump_class?: BumpClass | null
  change_reason?: string | null
}

export interface SetEnabledRequest {
  rule_id: string
  version: string
  enabled: boolean
}

// ---------------------------------------------------------------------------
// Correlations (app/schemas/correlation_query.py)
// ---------------------------------------------------------------------------

export interface CorrelationMember {
  id: string
  correlation_id: string
  detection_id: string
  event_id: string
  timestamp: string
  member_order: number
  created_at: string
  updated_at: string
}

export interface CorrelationResult {
  id: string
  correlation_id: string
  status: CorrelationStatus
  confidence: number | null
  evidence: Record<string, unknown>
  result_metadata: Record<string, unknown>
  timestamp: string
  provenance: Provenance
  members: CorrelationMember[]
  created_at: string
  updated_at: string
}

// ---------------------------------------------------------------------------
// Risk assessments (app/schemas/risk_query.py)
// ---------------------------------------------------------------------------

export interface RiskAssessment {
  id: string
  risk_assessment_id: string
  correlation_id: string
  score: number
  level: RiskLevel
  /** Null means the source correlation asserted no confidence; it is not zero. */
  confidence: number | null
  factors: Array<Record<string, unknown>>
  evidence: Array<Record<string, unknown>>
  assessment_metadata: Record<string, unknown>
  timestamp: string
  provenance: Provenance
  created_at: string
  updated_at: string
}

// ---------------------------------------------------------------------------
// Incident memories (app/schemas/incident_memory_query.py)
// ---------------------------------------------------------------------------

export interface IncidentMemory {
  id: string
  memory_id: string
  memory_type: MemoryType
  title: string
  summary: string
  correlation_id: string | null
  sources: Array<Record<string, unknown>>
  indicators: Array<Record<string, unknown>>
  entities: Array<Record<string, unknown>>
  techniques: Array<Record<string, unknown>>
  findings: Array<Record<string, unknown>>
  actions: Array<Record<string, unknown>>
  outcomes: Record<string, unknown>
  memory_metadata: Record<string, unknown>
  confidence: number | null
  provenance: Provenance
  created_at: string
  updated_at: string
}

// ---------------------------------------------------------------------------
// Audit (app/schemas/audit.py), auth (app/schemas/auth.py), users
// ---------------------------------------------------------------------------

export interface AuditLog {
  id: string
  user_id: string | null
  action: string
  resource: string | null
  details: string | null
  ip_address: string | null
  created_at: string
}

export interface AuditLogList {
  items: AuditLog[]
  total: number
  skip: number
  limit: number
}

export interface TokenResponse {
  access_token: string
  token_type: string
}

export interface LoginRequest {
  email: string
  password: string
}

export interface RegisterRequest {
  email: string
  password: string
}

export interface RegisterResponse {
  message: string
  user_id: string
}

export interface UserMe {
  id: string
  email: string
  is_active: boolean
  role: string | null
}

// ---------------------------------------------------------------------------
// Health (routes/health.py)
// ---------------------------------------------------------------------------

export interface DatabaseHealth {
  database?: string
  user?: string
  status: 'connected' | 'unhealthy'
  detail?: string
}

export interface KafkaHealth {
  kafka?: 'connected' | 'unreachable'
  status: 'healthy' | 'unhealthy'
  detail?: string
}

// ---------------------------------------------------------------------------
// Natural Language SOC (app/schemas/soc_query.py)
// ---------------------------------------------------------------------------

export type SOCResource =
  | 'detections'
  | 'correlations'
  | 'risk_assessments'
  | 'incident_memories'

export type SOCOperation =
  | 'get'
  | 'list'
  | 'recent'
  | 'by_event'
  | 'by_correlation'
  | 'by_detection'
  | 'by_rule'

export type SOCExecutionMode = 'exact_lookup' | 'paged_query' | 'recent_feed'

export interface SOCExecutionMetadata {
  resource: SOCResource
  operation: SOCOperation
  mode: SOCExecutionMode
  page: number | null
  page_size: number | null
  limit: number | null
  applied_filters: string[]
  parser_provider: string | null
  parser_model: string | null
  recorded_at: string
}

export interface SOCQueryResponse {
  intent: {
    resource: SOCResource
    operation: SOCOperation
    mode: SOCExecutionMode
    target: Record<string, unknown>
    filters: Record<string, unknown>
    pagination: Record<string, unknown>
  }
  metadata: SOCExecutionMetadata
  read_only: true
  found: boolean
  count: number
  total: number | null
  items: Array<Record<string, unknown>>
  semantics: string[]
  note: string
}

// ---------------------------------------------------------------------------
// Approval Workflow (app/schemas/approval.py)
// ---------------------------------------------------------------------------

export type ResponseActionType =
  | 'block_ip'
  | 'block_domain'
  | 'quarantine_file'
  | 'disable_account'
  | 'terminate_session'
  | 'isolate_endpoint'

export type ApprovalStatus =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'expired'
  | 'cancelled'

export type PolicyDecisionStatus =
  | 'allowed'
  | 'denied'
  | 'requires_approval'

export interface PolicyEvidence {
  evidence_type: string
  reference_id: string | null
  source_provenance: Provenance | null
  role: string | null
  metadata: Record<string, unknown>
}

/** Gate evaluation recorded on the decision under `metadata.evaluation`. */
export interface PolicyGateResult {
  gate: string
  passed: boolean
  required: boolean
}

export interface PolicyEvaluation {
  decision_path: PolicyDecisionStatus
  selected_rule: string | null
  candidates: string[]
  gate_results: PolicyGateResult[]
}

export interface PolicyDecision {
  policy_decision_id: string
  correlation_id: string
  requested_action: ResponseActionType
  decision: PolicyDecisionStatus
  reason: string
  policy_rule_id: string
  risk_level: RiskLevel
  risk_score: number | null
  confidence: number | null
  requires_approval: boolean
  evidence: PolicyEvidence[]
  metadata: {
    policy?: string
    evaluation?: PolicyEvaluation
    input?: Record<string, unknown>
    [key: string]: unknown
  }
  timestamp: string
  provenance: Provenance
}

export interface ApprovalRecord {
  /** Verbatim Step 24 decision this approval was routed from. */
  decision?: PolicyDecision | null
  id: string
  approval_id: string
  policy_decision_id: string
  correlation_id: string
  action_type: ResponseActionType
  target: string
  status: ApprovalStatus
  reason: string
  policy_rule_id: string
  risk_level: RiskLevel
  risk_score: number | null
  confidence: number | null
  evidence: Array<Record<string, unknown>>
  request_note: string | null
  requested_by: string
  requested_by_role: string
  requested_at: string
  expires_at: string
  resolved_at: string | null
  resolved_by: string | null
  resolution_reason: string | null
  response_status: string | null
  response_provider: string | null
  response_error_code: string | null
  provenance: Provenance
  metadata: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface ApprovalDecisionInput {
  comment: string
}

// ---------------------------------------------------------------------------
// V2.18 — SOAR
// ---------------------------------------------------------------------------

export type SoarExecutionStatus =
  | 'pending'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'partial'
  | 'cancelled'
  | 'rejected'

export type SoarStepStatus =
  | 'pending'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'skipped'
  | 'timed_out'
  | 'cancelled'

export type SoarFailurePolicy = 'stop_on_failure' | 'continue_on_failure'

export interface SoarPlaybookStep {
  step_number: number
  label: string
  provider_id: string
  operation: ResponseActionType
  target: string | null
  params: Record<string, unknown>
  retries: number
  timeout_seconds: number
}

export interface SoarPlaybookRecord {
  id: string
  playbook_id: string
  name: string
  description: string
  schema_version: string
  version: string
  version_id: string
  primary_action: ResponseActionType
  failure_policy: SoarFailurePolicy
  enabled: boolean
  step_count: number
  steps: SoarPlaybookStep[]
  created_at: string
  updated_at: string
}

export interface SoarStepExecutionRecord {
  step_execution_id: string
  execution_id: string
  step_number: number
  label: string
  provider_id: string
  operation: ResponseActionType
  target: string
  status: SoarStepStatus
  retries_attempted: number
  error_code: string | null
  message: string | null
  started_at: string | null
  completed_at: string | null
  metadata: Record<string, unknown>
}

export interface SoarExecutionRecord {
  id: string
  execution_id: string
  idempotency_key: string
  policy_decision_id: string
  correlation_id: string
  approval_id: string | null
  response_id: string
  playbook_id: string
  playbook_version: string
  primary_action: ResponseActionType
  target: string
  status: SoarExecutionStatus
  failure_policy: SoarFailurePolicy
  simulated: boolean
  error_code: string | null
  started_at: string | null
  completed_at: string | null
  created_by: string
  created_by_role: string
  metadata: Record<string, unknown>
  steps: SoarStepExecutionRecord[]
  created_at: string
  updated_at: string
}

export interface SoarDryRunResult {
  simulated: boolean
  playbook_id: string
  playbook_version: string
  policy_decision_id: string
  correlation_id: string
  response_id: string
  approval_id: string | null
  target: string
  status: SoarExecutionStatus
  steps: SoarStepExecutionRecord[]
  message: string | null
  created_at: string
}

export interface SoarExecutionRequest {
  // The canonical persisted decision, not a local re-declaration: a governed
  // run submits the verbatim snapshot stored on its approval request, so the
  // request type and the read model cannot drift apart.
  decision: PolicyDecision
  target: string
  approval_id?: string | null
  response_id: string
  playbook_id: string
  metadata?: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// V2.19 — Threat Hunting
// ---------------------------------------------------------------------------

export type ThreatHuntStatus = 'draft' | 'running' | 'completed' | 'failed' | 'cancelled'

export type HuntType =
  | 'authentication_anomaly'
  | 'indicator_hunt'
  | 'privilege_activity'
  | 'multi_stage_activity'
  | 'detection_review'

export interface ThreatHuntFilter {
  field: string
  operator: string
  value: string | null
  values: string[] | null
}

export interface ThreatHuntSummary {
  hunt_id: string
  name: string
  hunt_type: HuntType
  status: ThreatHuntStatus
  start_time: string
  end_time: string
  created_by: string
  created_by_role: string
  created_at: string
  started_at: string | null
  completed_at: string | null
  result_count: number
  finding_count: number
  timeline_count: number
  error_code: string | null
  error_message: string | null
}

export interface ThreatHuntRecord extends ThreatHuntSummary {
  description: string
  filters: ThreatHuntFilter[]
}

export interface ThreatHuntCreateRequest {
  name: string
  hunt_type: HuntType
  description: string
  start_time: string
  end_time: string
  filters: ThreatHuntFilter[]
}

export interface ThreatHuntEvidenceRecord {
  evidence_id: string
  evidence_type: string
  reference_id: string
  event_id: string | null
  correlation_id: string | null
  provenance: string
  severity: string | null
  observed_at: string | null
  title: string
  summary: string
}

export interface ThreatHuntFindingRecord {
  finding_id: string
  title: string
  description: string
  severity: string | null
  provenance: string
  observed_at: string | null
  evidence_ids: string[]
  context: Record<string, unknown>
}

export interface ThreatHuntTimelineItemRecord {
  timeline_item_id: string
  evidence_id: string
  observed_at: string | null
  evidence_type: string
  evidence_summary: string
  provenance: string
}

// ---------------------------------------------------------------------------
// Incident Reports (app/schemas/incident_report.py · V2.20)
// ---------------------------------------------------------------------------

export type ReportStatus = 'generated' | 'failed'

export interface ReportSummary {
  report_id: string
  correlation_id: string
  status: ReportStatus
  title: string | null
  model: string | null
  generated_by: string
  generated_by_role: string
  generated_at: string | null
  error_code: string | null
  error_message: string | null
  created_at: string
  updated_at: string
}

export interface IncidentReportFinding {
  title: string
  summary: string
  evidence_references: string[]
  provenance: string
}

export interface IncidentReportPayload {
  schema_version: '2.20'
  report_id: string
  correlation_id: string
  generated_at: string
  generated_by: string
  generated_by_role: string
  model: string
  availability: Record<string, string>
  incident: Record<string, unknown>
  correlation: Array<Record<string, unknown>>
  detections: Array<Record<string, unknown>>
  threat_intelligence: Array<Record<string, unknown>>
  risk_assessment: Record<string, unknown> | null
  incident_memories: Array<Record<string, unknown>>
  threat_hunts: Array<Record<string, unknown>>
  approvals: Array<Record<string, unknown>>
  soar_executions: Array<Record<string, unknown>>
  timeline: Array<Record<string, unknown>>
  evidence_catalog: Array<{ reference_id: string }>
  source_limitations: string[]
  ai: {
    title: string
    executive_summary: string
    incident_overview: string
    investigation_summary: string
    attribution_summary: string
    threat_hunting_summary: string
    response_summary: string
    findings: IncidentReportFinding[]
    limitations: string[]
    recommended_follow_up: string[]
  }
}

export interface IncidentReportRecord extends ReportSummary {
  payload: IncidentReportPayload | null
}

export interface IncidentReportListPage extends Page<ReportSummary> {
  correlation_id: string | null
}

export interface IncidentReportGenerateRequest {
  correlation_id: string
  report_version?: '2.20'
}

// ---------------------------------------------------------------------------
// Attack Path Visualization (app/schemas/attack_path.py) — V2.21
//
// Read-only, evidence-grounded graph projection of already-persisted
// relationships for one correlation. Every node/edge is backed by a
// persisted record; no inference or fabricated attack step.
// ---------------------------------------------------------------------------

export type AttackPathNodeType =
  | 'correlation'
  | 'detection'
  | 'indicator'
  | 'risk'
  | 'memory'
  | 'hunt'
  | 'policy_decision'
  | 'approval'
  | 'soar_execution'

export type AttackPathEdgeType =
  | 'correlation_has_detection'
  | 'detection_has_indicator'
  | 'correlation_has_risk'
  | 'correlation_has_memory'
  | 'correlation_has_hunt'
  | 'correlation_has_policy_decision'
  | 'policy_has_approval'
  | 'correlation_has_approval'
  | 'correlation_has_soar_execution'
  | 'policy_has_soar_execution'
  | 'approval_has_soar_execution'

export type InputAvailability = 'provided' | 'not_provided' | 'none_found'

export interface AttackPathNode {
  node_id: string
  node_type: AttackPathNodeType
  label: string
  provenance: Provenance
  source_reference: string
  occurrence: string | null
  status: string | null
  severity: string | null
  fields: Record<string, string>
  evidence_references: string[]
}

export interface AttackPathEdge {
  edge_id: string
  source_node_id: string
  target_node_id: string
  relationship_type: AttackPathEdgeType
  provenance: Provenance
  source_reference: string
  evidence_references: string[]
}

export interface AttackPathGraph {
  nodes: AttackPathNode[]
  edges: AttackPathEdge[]
}

export interface AttackPathMetadata {
  correlation_id: string
  generated_at: string
  node_count: number
  edge_count: number
  truncated: boolean
  limitation: string | null
  bounds: Record<string, number>
}

export interface AttackPathAvailability {
  correlation: InputAvailability
  detections: InputAvailability
  indicators: InputAvailability
  risk_assessment: InputAvailability
  incident_memory: InputAvailability
  threat_hunts: InputAvailability
  policy_decisions: InputAvailability
  approvals: InputAvailability
  soar_executions: InputAvailability
  investigation: InputAvailability
  attribution: InputAvailability
  security_events: InputAvailability
}

export interface AttackPathResponse {
  graph: AttackPathGraph
  metadata: AttackPathMetadata
  availability: AttackPathAvailability
}

// ---------------------------------------------------------------------------
// Threat Intelligence (app/schemas/threat_intelligence_query.py)
//
// Mirrors the Step 8A read models one-for-one.  Note what is absent: there
// is no `verdict`, `malicious`, `severity`, or `risk` field anywhere,
// because Step 8A persists none.  The UI therefore has nothing to render as
// a threat judgement even if it wanted to.
// ---------------------------------------------------------------------------

/** Persisted indicator type: ip, domain, url, or hash. */
export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash'

/** Persisted `LookupStatus`: 'success' or 'error'. */
export type LookupStatus = 'success' | 'error'

/**
 * Rollup of an indicator's persisted lookups.
 *
 * - `no_lookup` — the indicator exists but was never looked up.
 * - `enriched`  — at least one provider returned data, none failed.
 * - `partial`   — some providers returned data, some failed.
 * - `failed`    — every recorded lookup failed.
 *
 * None of these is a malicious or benign verdict.
 */
export type IndicatorLookupStatus = 'no_lookup' | 'enriched' | 'partial' | 'failed'

/**
 * Human-facing rollup of one persisted lookup outcome, computed server-side
 * from stored values only.
 *
 * `ENRICHED` means the provider returned data.  `NO DATA` means it was
 * queried and held nothing — explicitly *not* a benign verdict.  The failure
 * labels report what went wrong and are never rendered as a verdict.
 */
export type LookupStatusLabel =
  | 'ENRICHED'
  | 'NO DATA'
  | 'FAILED'
  | 'RATE LIMITED'
  | 'TIMED OUT'
  | 'REJECTED'
  | 'UNAVAILABLE'

export interface ThreatIntelLookupRecord {
  lookup_id: string
  indicator_id: string
  event_id: string
  provider: string
  status: LookupStatus
  status_label: LookupStatusLabel
  /** Null on a failed lookup. `false` means 'queried, nothing found'. */
  found: boolean | null
  /** True only when the lookup succeeded and stored provider data. */
  provider_result_available: boolean
  confidence: number | null
  performed_at: string
  result_timestamp: string | null
  error_type: string | null
  error_message: string | null
  retryable: boolean | null
  evidence: Record<string, unknown> | null
  result_metadata: Record<string, unknown> | null
  provenance: Provenance
  created_at: string
  updated_at: string
}

export interface ThreatIntelIndicatorRecord {
  indicator_id: string
  indicator_type: IndicatorType
  value: string
  canonical_key: string
  first_seen: string
  last_seen: string
  providers: string[]
  lookup_count: number
  success_count: number
  error_count: number
  latest_lookup_at: string | null
  status: IndicatorLookupStatus
  provenance: Provenance
  created_at: string
  updated_at: string
}

export interface ThreatIntelIndicatorPage extends Page<ThreatIntelIndicatorRecord> {
  read_only: boolean
  verdict_available: boolean
}

export interface ThreatIntelIndicatorDetail {
  indicator: ThreatIntelIndicatorRecord
  lookups: ThreatIntelLookupRecord[]
  lookups_truncated: boolean
  events: string[]
  events_truncated: boolean
  read_only: boolean
  verdict_available: boolean
}

export interface ThreatIntelIndicatorEvents {
  indicator_id: string
  events: string[]
  total: number
  truncated: boolean
  read_only: boolean
  note: string
}

// ---------------------------------------------------------------------------
// V3.22 Knowledge Graph
// ---------------------------------------------------------------------------

/**
 * Closed node vocabulary.  The backend is the source of truth and exposes it
 * at `/api/knowledge-graph/vocabulary`; this union exists so the renderer
 * cannot silently accept an unknown type.
 */
export type KnowledgeNodeType =
  | 'EVENT'
  | 'DETECTION'
  | 'CORRELATION'
  | 'RISK_ASSESSMENT'
  | 'THREAT_INDICATOR'
  | 'INCIDENT_MEMORY'
  | 'THREAT_HUNT'
  | 'APPROVAL'
  | 'SOAR_EXECUTION'
  | 'INCIDENT_REPORT'

/**
 * Closed relationship vocabulary.  Every one of these is backed by a persisted
 * V2 row; none is inferred.
 */
export type KnowledgeRelationshipType =
  | 'produced_detection'
  | 'member_of_correlation'
  | 'assessed_by'
  | 'associated_with_indicator'
  | 'recalled_by'
  | 'requires_approval'
  | 'authorized_execution'
  | 'responded_by_execution'
  | 'reported_by'
  | 'investigated_by_hunt'

export interface KnowledgeNode {
  id: string
  node_type: KnowledgeNodeType
  source_id: string
  label: string
  source_reference: string
  provenance: string
  metadata: Record<string, unknown>
  observed_at: string | null
}

export interface KnowledgeEdge {
  id: string
  relationship_type: KnowledgeRelationshipType
  source_node_id: string
  target_node_id: string
  source_reference: string
  evidence_references: string[]
}

export interface KnowledgeBounds {
  max_nodes: number
  max_edges: number
  max_depth: number
  max_page_size: number
}

/**
 * Entity kinds V2 persists no identity for.  Surfaced in the UI so the graph's
 * gaps are stated rather than implied.
 */
export type UnavailableEntityTypes = Record<string, string>

export interface KnowledgeTraversal {
  root_node_id: string | null
  nodes: KnowledgeNode[]
  edges: KnowledgeEdge[]
  node_count: number
  edge_count: number
  max_depth_reached: number
  truncated: boolean
  truncated_reason: string | null
  bounds: KnowledgeBounds
  unavailable_entity_types?: UnavailableEntityTypes
}

export interface KnowledgeVocabulary {
  node_types: Record<string, unknown>[]
  relationship_types: Record<string, unknown>[]
  unavailable_entity_types: UnavailableEntityTypes
  bounds: Record<string, number>
}

// ---------------------------------------------------------------------------
// V3.23 — Multi-Agent Debate Engine
//
// Mirrors backend/app/schemas/debate.py.  Every object here is AI-generated
// analytical reasoning over persisted V2 evidence, never evidence itself, so
// `provenance` is pinned to 'ai_generated' throughout.
// ---------------------------------------------------------------------------

export type DebateAgentRole =
  | 'detection_analyst'
  | 'threat_intelligence_analyst'
  | 'behavioral_analyst'
  | 'incident_investigator'
  | 'skeptic'

export type DebateRoundKind =
  | 'round_0_shared_evidence'
  | 'round_1_independent_assessments'
  | 'round_2_cross_agent_arguments'
  | 'round_3_counterarguments'
  | 'round_4_reconciliation'

export type DebateStatus = 'pending' | 'running' | 'completed' | 'failed'

export type DebateConsensusState =
  | 'consensus'
  | 'partial_consensus'
  | 'contested'
  | 'insufficient_evidence'

export type DebateClaimKind = 'observation' | 'hypothesis'

export type DebateStance = 'supports' | 'opposes'

export type DebateWeaknessKind =
  | 'contradictory_evidence'
  | 'weak_evidence'
  | 'missing_evidence'
  | 'alternative_explanation'
  | 'overconfidence'

/** One pointer to a persisted V2 entity that exists in the knowledge graph. */
export interface EvidenceReference {
  reference: string
  entity_kind: string
  node_id: string
}

export interface DebateClaim {
  claim_id: string
  claim_kind: DebateClaimKind
  statement: string
  evidence_references: EvidenceReference[]
  confidence: number
  provenance: 'ai_generated'
  author_role: DebateAgentRole
}

/**
 * An engine-derived fact.  `claim_kind` is always 'fact' and is produced by the
 * deterministic engine from the graph — never by a model — so it carries no
 * author role and its provenance is that of the underlying V2 entity.
 */
export interface DebateFact {
  fact_id: string
  claim_kind: 'fact'
  statement: string
  evidence_references: EvidenceReference[]
  provenance: Provenance | null
}

export interface DebateAgent {
  agent_id: string
  role: DebateAgentRole
  display_name: string
  objective: string
  focus_node_types: string[]
}

export interface AgentAssessment {
  agent_id: string
  role: DebateAgentRole
  objective: string
  observations: DebateClaim[]
  hypotheses: DebateClaim[]
  confidence: number
  evidence_references: EvidenceReference[]
  limitations: string[]
  provenance: 'ai_generated'
}

export interface DebateArgument {
  argument_id: string
  round_kind: 'round_2_cross_agent_arguments'
  author_agent_id: string
  author_role: DebateAgentRole
  target_agent_id: string
  target_role: DebateAgentRole
  target_hypothesis_id: string
  stance: DebateStance
  statement: string
  evidence_references: EvidenceReference[]
  provenance: 'ai_generated'
}

export interface DebateCounterargument {
  counterargument_id: string
  round_kind: 'round_3_counterarguments'
  author_agent_id: string
  author_role: DebateAgentRole
  target_argument_id: string
  weakness: DebateWeaknessKind
  statement: string
  evidence_references: EvidenceReference[]
  provenance: 'ai_generated'
}

export interface DebateDissent {
  dissent_id: string
  raised_by_role: DebateAgentRole
  position: string
  reason: string
  evidence_references: EvidenceReference[]
  provenance: 'ai_generated'
}

export interface DebateConsensus {
  state: DebateConsensusState
  leading_hypothesis: string | null
  leading_hypothesis_id: string | null
  supporting_arguments: DebateArgument[]
  opposing_arguments: DebateArgument[]
  consensus_strength: number
  confidence: number
  dissent: DebateDissent[]
  unresolved_questions: string[]
  evidence_gaps: string[]
  evidence_references: EvidenceReference[]
  provenance: 'ai_generated'
}

export interface DebateRound {
  round_number: number
  round_kind: DebateRoundKind
  summary: string
  agent_ids: string[]
  argument_ids: string[]
  counterargument_ids: string[]
}

export interface DebateEvidenceScope {
  correlation_id: string
  graph_node_count: number
  graph_edge_count: number
  evidence_reference_count: number
  node_type_counts: Record<string, number>
  graph_truncated: boolean
  graph_truncated_reason: string | null
  unavailable_entity_types: Record<string, string>
}

export interface DebateMetadata {
  provider: string
  model: string | null
  engine_version: string
  configuration_digest: string
  graph_snapshot_digest: string
  graph_node_count: number
  graph_edge_count: number
  agent_count: number
  max_rounds: number
  observations_count: number
  hypotheses_count: number
  arguments_count: number
  counterarguments_count: number
  prompt_bytes: number
  created_at: string | null
  provenance: 'ai_generated'
}

export interface DebateSession {
  debate_id: string
  correlation_id: string
  status: DebateStatus
  agents: DebateAgent[]
  facts: DebateFact[]
  assessments: AgentAssessment[]
  arguments: DebateArgument[]
  counterarguments: DebateCounterargument[]
  rounds: DebateRound[]
  consensus: DebateConsensus
  evidence_scope: DebateEvidenceScope
  metadata: DebateMetadata
  limitations: string[]
}

/**
 * Governed failure body.  The backend never synthesizes a consensus to fill a
 * gap, so a failed debate carries a code and a detail instead.
 */
export interface DebateFailure {
  debate_id: string | null
  correlation_id: string | null
  status: 'failed'
  failure_code: string
  detail: string
  provenance: 'ai_generated'
}

/* ------------------------------------------------------------------------- *
 * V3.24 — Attack Prediction Engine
 * ------------------------------------------------------------------------- *
 *
 * A prediction is analysis, not evidence.  Every model below types
 * `provenance` as the literal `'ai_generated'`, matching the backend contract,
 * so the type system prevents a predicted artifact from ever being rendered as
 * an observed finding.
 */

export type PredictionStatus =
  | 'PREDICTED'
  | 'LOW_CONFIDENCE'
  | 'INSUFFICIENT_EVIDENCE'
  | 'CONTESTED'

export type PredictionKind =
  | 'NEXT_TACTIC'
  | 'NEXT_TECHNIQUE'
  | 'NEXT_ACTIVITY'
  | 'ESCALATION'
  | 'LATERAL_MOVEMENT'
  | 'PERSISTENCE'
  | 'CREDENTIAL_ACCESS'
  | 'EXFILTRATION'
  | 'COMMAND_AND_CONTROL'

/** 1 = plausible next stage; 2 = one subsequent stage.  Never deeper. */
export type PredictionDepth = 'immediate' | 'subsequent'

export type PredictionBasis =
  | 'persisted_attack_mapping'
  | 'debate_hypothesis'
  | 'persisted_relationship'
  | 'analytical_hypothesis'

export type TargetBasis =
  | 'persisted_attack_mapping'
  | 'debate_referenced'
  | 'analytical_hypothesis'

export type ConfidenceBand = 'very_low' | 'low' | 'moderate' | 'high'

export type EvidenceSupport =
  | 'persisted_evidence'
  | 'debate_claim'
  | 'mixed'

export type EvidenceStance = 'supporting' | 'contradicting'

export type LimitationKind =
  | 'no_persisted_attack_mapping'
  | 'no_debate_artifact'
  | 'debate_insufficient_evidence'
  | 'debate_contested'
  | 'single_source_evidence'
  | 'no_contradicting_evidence_available'
  | 'graph_truncated'
  | 'input_source_unavailable'
  | 'horizon_capped'
  | 'analytical_inference_only'
  | 'no_persisted_technique'

export type ConfidenceBasisKey =
  | 'evidence_support'
  | 'evidence_diversity'
  | 'debate_support'
  | 'target_specificity'
  | 'contradiction_penalty'

/** One pointer to a persisted source.  Carries no source content. */
export interface PredictionEvidence {
  reference: string
  entity_kind: string
  node_id: string
  stance: EvidenceStance
  detail: string
}

/**
 * The predicted ATT&CK target.
 *
 * `technique_id` is `null` in the normal case: no ATT&CK catalog is embedded, so
 * an id exists only when a persisted detection supplied one.  `technique_id_reason`
 * is always present, so an absent id is explained rather than silent.
 */
export interface PredictionTechnique {
  technique_id: string | null
  technique_name: string | null
  tactic: string | null
  technique_id_reason: string
}

export interface PredictionLimitation {
  kind: LimitationKind
  detail: string
}

export interface PredictionRationale {
  summary: string
  basis: PredictionBasis
  basis_detail: string
  observed_techniques: string[]
  debate_agreement: number | null
}

export interface PredictionUncertainty {
  confidence: number
  confidence_band: ConfidenceBand
  confidence_basis: Record<ConfidenceBasisKey, number>
  supporting_evidence: PredictionEvidence[]
  contradicting_evidence: PredictionEvidence[]
  evidence_gaps: string[]
  unresolved_questions: string[]
  evidence_support: EvidenceSupport
  limitations: PredictionLimitation[]
}

export interface AttackPrediction {
  prediction_id: string
  prediction_kind: PredictionKind
  depth: PredictionDepth
  status: PredictionStatus
  target: string
  target_basis: TargetBasis
  technique: PredictionTechnique
  rationale: PredictionRationale
  uncertainty: PredictionUncertainty
  provenance: 'ai_generated'
}

export interface PredictionMetadata {
  engine_version: string
  prediction_configuration_digest: string
  graph_snapshot_digest: string
  /** Identifies the *consumed* V3.23 debate, not a call this engine made. */
  debate_id: string | null
  debate_consensus_state: string | null
  debate_provider: string | null
  debate_model: string | null
  graph_node_count: number
  graph_edge_count: number
  observed_technique_count: number
  max_depth: number
  unavailable_inputs: Record<string, string>
  limitations: PredictionLimitation[]
}

export interface PredictionResult {
  prediction_session_id: string
  correlation_id: string
  status: PredictionStatus
  predictions: AttackPrediction[]
  current_state: PredictionEvidence[]
  observed_techniques: string[]
  metadata: PredictionMetadata
  limitations: PredictionLimitation[]
  limitations_note: string
  provenance: 'ai_generated'
}

/**
 * Governed failure body.  The backend never fabricates a prediction to cover a
 * gap, so a failed run carries a code and a detail instead of a result.
 */
export interface PredictionFailure {
  correlation_id: string | null
  prediction_session_id: string | null
  status: 'failed'
  failure_code: string
  detail: string
  provenance: 'ai_generated'
}

// ---------------------------------------------------------------------------
// Investigation result (app/schemas/investigation.py, Step 12A)
// ---------------------------------------------------------------------------

export interface InvestigationEvidence {
  evidence_id: string
  evidence_type: string
  provenance: Provenance
  detection_id: string | null
  event_id: string | null
  correlation_id: string | null
  risk_assessment_id: string | null
  metadata: Record<string, unknown>
}

export interface InvestigationObservation {
  observation_type: string
  observation_text: string
  provenance: Provenance
  metadata: Record<string, unknown>
}

export interface InvestigationFinding {
  finding_type: string
  title: string
  summary: string | null
  confidence: number
  evidence_ids: string[]
  metadata: Record<string, unknown>
  provenance: Provenance
}

// ---------------------------------------------------------------------------
// Explainability (app/schemas/explainability.py)
// ---------------------------------------------------------------------------

/** Overall outcome of one explanation request. */
export type ExplanationStatus =
  | 'explained'
  | 'insufficient_evidence'
  | 'ai_unavailable'

/** The security concepts an explanation accounts for. */
export type ExplanationDimension =
  | 'detection'
  | 'correlation'
  | 'risk'
  | 'mitre'
  | 'policy'
  | 'response'
  | 'audit'

/**
 * How completely a dimension could be grounded in persisted records.
 * `unavailable` means the platform persists no such source (stated, never
 * invented); `none_found` means the source exists but holds nothing here.
 */
export type DimensionCoverage = 'grounded' | 'none_found' | 'unavailable'

export interface ExplanationClaim {
  text: string
  evidence_ids: string[]
}

export interface DimensionExplanation {
  dimension: ExplanationDimension
  coverage: DimensionCoverage
  title: string
  summary: string
  provenance: Provenance
  claims: ExplanationClaim[]
  reference_ids: string[]
  unavailable_reason: string | null
}

export interface ExplainabilityResult {
  correlation_id: string
  generated_at: string
  status: ExplanationStatus
  dimensions: DimensionExplanation[]
  ai_provider: string | null
  ai_model: string | null
  narrative: InvestigationFinding[]
  observations: InvestigationObservation[]
  evidence: InvestigationEvidence[]
  unsupported_claims: string[]
  limitations: string[]
  metadata: Record<string, unknown>
  provenance: Provenance
}

export interface ExplanationRequest {
  use_ai: boolean
}
