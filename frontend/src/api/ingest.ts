import { api } from './client'
import type { Provenance } from '../types/api'

export interface IngestFieldDoc {
  name: string
  required: boolean
  description: string
}

export interface IngestEventTypeDoc {
  event_type: string
  event_category: string
}

export interface IngestFormat {
  description: string
  content_type: string
  required_fields: IngestFieldDoc[]
  optional_fields: IngestFieldDoc[]
  source_types: string[]
  event_categories: string[]
  recognized_event_types: IngestEventTypeDoc[]
  notes: string[]
  example_lines: string[]
}

export interface IngestError {
  line_number: number
  reason: string
}

/**
 * Mirrors `app/schemas/normalized_event.py`. `actor`, `source_endpoint`,
 * `destination_endpoint`, `process` and `file` are optional entities the
 * agent leaves null when the source event carries no such telemetry — they
 * are never fabricated.
 */
export interface NormalizedActor {
  user_id: string | null
  username: string | null
  domain: string | null
}

export interface NormalizedEndpoint {
  ip: string | null
  hostname: string | null
  port: number | null
  protocol: string | null
}

export interface NormalizedProcess {
  name: string | null
  pid: number | null
  command_line: string | null
  executable: string | null
  parent_process: string | null
}

export interface NormalizedFile {
  name: string | null
  path: string | null
  extension: string | null
  hash: string | null
}

export interface NormalizedSecurityEvent {
  event_id: string
  timestamp: string
  event_category: string
  action: string | null
  outcome: string
  source: string
  source_type: string
  actor: NormalizedActor | null
  source_endpoint: NormalizedEndpoint | null
  destination_endpoint: NormalizedEndpoint | null
  process: NormalizedProcess | null
  file: NormalizedFile | null
  normalized_data: Record<string, unknown>
  provenance: Provenance
}

/**
 * One ingested record as the backend actually processed it: `raw_event` is
 * the untouched JSON object `FileLogCollector` read, `normalized_event` is
 * the `NormalizedSecurityEvent` the NormalizationAgent produced and the
 * DetectionAgent evaluated, and `provenance` is read back from that
 * normalized event. `line_number` is the position among non-blank lines.
 */
export interface IngestEventTrace {
  event_id: string
  line_number: number
  raw_event: Record<string, unknown>
  normalized_event: NormalizedSecurityEvent
  provenance: Provenance
}

export interface IngestSummary {
  total_records: number
  accepted_events: number
  rejected_records: number
  events_processed: number
  detections: number
  events_with_detections: number
  detection_results_created: number
  rule_failures: number
  active_rule_count: number
  errors: IngestError[]
  truncated_errors: boolean
  duration_ms: number
  /**
   * Optional so the page still renders against a backend that predates the
   * trace. When absent the page reports the gap instead of inventing data.
   */
  events?: IngestEventTrace[]
  truncated_events?: boolean
}

export const ingestApi = {
  format: (): Promise<IngestFormat> => api.get<IngestFormat>('/api/ingest/format'),

  events: (file: File): Promise<IngestSummary> => {
    const form = new FormData()
    form.append('file', file)
    return api.upload<IngestSummary>('/api/ingest/events', form)
  },
}
