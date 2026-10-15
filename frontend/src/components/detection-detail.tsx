import { ProvenanceBadge, RuleTypeBadge, SeverityBadge } from './badges'
import { CopyButton } from './ui/copy-button'
import { JsonViewer } from './ui/json-viewer'
import { ConfidenceBar } from './ui/progress'
import { formatTimestamp } from '../lib/formats'
import type { DetectionResult } from '../types/api'

function Field({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] font-semibold uppercase tracking-wider text-ink-faint">
        {label}
      </dt>
      <dd className="mt-1 min-w-0 text-[11px] text-ink-dim">{children}</dd>
    </div>
  )
}

function Identifier({ value }: { value: string }) {
  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <span className="truncate font-mono" data-testid="full-id">
        {value}
      </span>
      <CopyButton value={value} label={`Copy ${value}`} />
    </span>
  )
}

/**
 * Renders every identifier, provenance field and payload that
 * `GET /api/detections/{detection_id}` persists on a detection result.
 * Evidence and result metadata are shown verbatim so rule matches stay auditable.
 */
export function DetectionDetail({ detection }: { detection: DetectionResult }) {
  return (
    <div className="space-y-4" data-testid="detection-detail">
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
        <Field label="Detection id">
          <Identifier value={detection.detection_id} />
        </Field>
        <Field label="Event id">
          <Identifier value={detection.event_id} />
        </Field>
        <Field label="Rule id">
          <Identifier value={detection.rule_id} />
        </Field>
        <Field label="Rule version">
          <span className="font-mono">{detection.rule_version}</span>
        </Field>
        <Field label="Engine">
          <RuleTypeBadge ruleType={detection.rule_type} />
        </Field>
        <Field label="Severity">
          <SeverityBadge severity={detection.severity} />
        </Field>
        <Field label="Confidence">
          <ConfidenceBar value={detection.confidence} />
        </Field>
        <Field label="Provenance">
          <ProvenanceBadge provenance={detection.provenance} />
        </Field>
        <Field label="Matched">
          <span className="font-mono">{detection.matched ? 'true' : 'false'}</span>
        </Field>
        <Field label="Detected at">
          <span className="font-mono">{formatTimestamp(detection.detected_at)}</span>
        </Field>
        <Field label="Persisted at">
          <span className="font-mono">{formatTimestamp(detection.created_at)}</span>
        </Field>
        <Field label="Row id">
          <Identifier value={detection.id} />
        </Field>
      </dl>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <div className="min-w-0">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-faint">
            Evidence
          </div>
          <div className="mt-1">
            <JsonViewer value={detection.evidence} />
          </div>
        </div>
        <div className="min-w-0">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-faint">
            Result metadata
          </div>
          <div className="mt-1">
            <JsonViewer value={detection.result_metadata} />
          </div>
        </div>
      </div>
    </div>
  )
}