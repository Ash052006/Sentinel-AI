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
  confidence: number
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

export interface ApprovalRecord {
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
  decision: {
    policy_decision_id: string
    correlation_id: string
    requested_action: ResponseActionType
    decision: 'allowed' | 'denied' | 'requires_approval'
    reason: string
    policy_rule_id: string
    risk_level: RiskLevel
    risk_score?: number | null
    confidence?: number | null
    requires_approval: boolean
    evidence?: Array<Record<string, unknown>>
    metadata?: Record<string, unknown>
    timestamp: string
    provenance: 'policy_decided'
  }
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