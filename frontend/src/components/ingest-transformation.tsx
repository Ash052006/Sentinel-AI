import { useState } from 'react'
import { ArrowDown, Info } from 'lucide-react'
import {
  type IngestEventTrace,
  type IngestSummary,
  type NormalizedSecurityEvent,
} from '../api/ingest'
import { ProvenanceBadge } from './badges'
import { DataTree } from './data-tree'
import { NotAvailable } from './states'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Panel, Skeleton } from './ui/card'
import { Td, Th, Table, TRow } from './ui/table'
import {
  type TraceFieldStatus,
  TRACE_STATUS_LABEL,
  summarizeTrace,
} from '../lib/ingest-trace'
import { formatTimestamp, shorten } from '../lib/formats'
import { cn } from '../lib/utils'

/**
 * Raw -> normalized event transformation view.
 *
 * Everything rendered here comes from the ingestion response: the raw JSON
 * object the collector read and the `NormalizedSecurityEvent` the
 * NormalizationAgent produced. The pipeline diagram is a visualisation of
 * that pairing only -- no transformation happens in the browser, and no
 * field is synthesised when the response does not carry it.
 */

type InspectorTab = 'raw' | 'normalized' | 'provenance'

const TABS: Array<{ id: InspectorTab; label: string }> = [
  { id: 'raw', label: 'Raw' },
  { id: 'normalized', label: 'Normalized' },
  { id: 'provenance', label: 'Provenance' },
]

const STATUS_TONE: Record<TraceFieldStatus, 'low' | 'accent' | 'medium' | 'muted'> = {
  preserved: 'low',
  mapped: 'accent',
  derived: 'medium',
  absent: 'muted',
}

export function IngestTransformation({
  summary,
  pending,
}: {
  summary: IngestSummary | undefined
  pending: boolean
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [tab, setTab] = useState<InspectorTab>('raw')

  if (pending) {
    return (
      <Panel title="Event transformation" subtitle="Collecting and normalizing…" data-testid="ingest-loading">
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, index) => (
            <Skeleton key={index} className="h-4 w-full" />
          ))}
        </div>
        <p className="mt-3 text-[11px] text-ink-faint">
          The backend is running FileLogCollector and NormalizationAgent over
          the uploaded file.
        </p>
      </Panel>
    )
  }

  if (!summary) return null

  const events = summary.events

  if (events === undefined) {
    return (
      <Panel
        title="Event transformation"
        subtitle="Raw and normalized events for this run"
        data-testid="ingest-transformation"
      >
        <NotAvailable
          title="Not available from ingestion response"
          body={
            'This ingestion response carries only run counters — it does not ' +
            'include the raw event or the NormalizedSecurityEvent, so there is ' +
            'nothing to display here. Nothing is generated client-side in its ' +
            'place. Required backend change: POST /api/ingest/events must return ' +
            'IngestSummary.events as a list of raw_event / normalized_event / ' +
            'provenance triples, produced by the NormalizationAgent that the ' +
            'DetectionAgent already consumes.'
          }
        />
      </Panel>
    )
  }

  if (events.length === 0) {
    return (
      <Panel
        title="Event transformation"
        subtitle="Raw and normalized events for this run"
        data-testid="ingest-transformation"
      >
        <NotAvailable
          title="No event was normalized"
          body={
            'The backend returned an empty trace for this run: it processed ' +
            `${summary.events_processed} of ${summary.total_records} record(s) ` +
            'and normalized none, so there is no raw/normalized pair to show. ' +
            'The rejected lines are listed in the Result panel above.'
          }
        />
      </Panel>
    )
  }

  const selected = events.find((e) => e.event_id === selectedId) ?? events[0]

  return (
    <div className="space-y-4" data-testid="ingest-transformation">
      <EventSelector
        events={events}
        selected={selected}
        truncated={summary.truncated_events === true}
        onSelect={setSelectedId}
      />

      <div className="grid gap-4 xl:grid-cols-2">
        <PipelinePanel trace={selected} />
        <TransformationSummary trace={selected} />
      </div>

      <Inspector trace={selected} tab={tab} onTab={setTab} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Event selector
// ---------------------------------------------------------------------------

function EventSelector({
  events,
  selected,
  truncated,
  onSelect,
}: {
  events: IngestEventTrace[]
  selected: IngestEventTrace
  truncated: boolean
  onSelect: (id: string) => void
}) {
  return (
    <Panel
      title="Ingested events"
      subtitle={
        `Raw and normalized pairs returned by the backend${
          truncated ? ' (list truncated)' : ''
        }.`
      }
      padded={false}
    >
      <Table>
        <thead>
          <tr className="border-b border-edge">
            <Th>Line</Th>
            <Th>Source</Th>
            <Th>Event type</Th>
            <Th>Category</Th>
            <Th>Outcome</Th>
            <Th>Provenance</Th>
          </tr>
        </thead>
        <tbody className="divide-y divide-edge-soft">
          {events.map((trace) => {
            const active = trace.event_id === selected.event_id
            return (
              <TRow
                key={trace.event_id}
                onClick={() => onSelect(trace.event_id)}
                aria-selected={active}
                data-testid="ingest-event-row"
                className={cn('cursor-pointer', active && 'bg-accent/5')}
              >
                <Td className="font-mono text-[11px] text-ink-faint">
                  {trace.line_number || '—'}
                </Td>
                <Td className="font-mono text-[11px] text-ink">
                  {trace.normalized_event.source}
                </Td>
                <Td className="font-mono text-[11px] text-ink-dim">
                  {rawField(trace, 'event_type')}
                </Td>
                <Td className="font-mono text-[11px] text-ink">
                  {trace.normalized_event.event_category}
                </Td>
                <Td className="font-mono text-[11px] text-ink-dim">
                  {trace.normalized_event.outcome}
                </Td>
                <Td>
                  <ProvenanceBadge provenance={trace.provenance} />
                </Td>
              </TRow>
            )
          })}
        </tbody>
      </Table>
    </Panel>
  )
}

function rawField(trace: IngestEventTrace, key: string): string {
  const value = trace.raw_event?.[key]
  if (value === null || value === undefined || value === '') return '—'
  return typeof value === 'string' ? value : String(value)
}

// ---------------------------------------------------------------------------
// Section 2 — pipeline visualisation
// ---------------------------------------------------------------------------

const STAGES = [
  { key: 'Raw event', note: 'JSON Lines record' },
  { key: 'Ingestion', note: 'FileLogCollector' },
  { key: 'Normalization', note: 'NormalizationAgent' },
  { key: 'Normalized event', note: 'common schema' },
] as const

function PipelinePanel({ trace }: { trace: IngestEventTrace }) {
  return (
    <Panel
      title="Normalization pipeline"
      subtitle="Where this event was transformed"
    >
      <ol className="flex flex-wrap items-center gap-x-1.5 gap-y-1">
        {STAGES.map((stage, index) => (
          <li key={stage.key} className="flex items-center gap-1.5">
            <div className="rounded border border-edge bg-surface-2 px-2 py-1">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-ink">
                {stage.key}
              </div>
              <div className="font-mono text-[10px] text-ink-faint">
                {stage.note}
              </div>
            </div>
            {index < STAGES.length - 1 && (
              <span aria-hidden="true" className="text-ink-faint">
                →
              </span>
            )}
          </li>
        ))}
      </ol>

      <div className="mt-3 flex flex-col items-center">
        <div className="w-full rounded border border-edge bg-surface-2 px-3 py-2">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-ink">
              Raw security event
            </span>
            <ProvenanceBadge provenance={trace.provenance} />
          </div>
          <div className="mt-0.5 truncate font-mono text-[10px] text-ink-faint">
            raw_event · {Object.keys(trace.raw_event ?? {}).length} field(s)
          </div>
        </div>

        <ArrowStep label="NormalizationAgent" />

        <div className="w-full rounded border border-accent/40 bg-accent/5 px-3 py-2">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-ink">
              Normalized security event
            </span>
            <ProvenanceBadge provenance={trace.normalized_event.provenance} />
          </div>
          <div className="mt-0.5 truncate font-mono text-[10px] text-ink-faint">
            {trace.normalized_event.event_category} ·{' '}
            {trace.normalized_event.source}
          </div>
        </div>
      </div>

      <p className="mt-3 flex items-start gap-1.5 text-[10px] leading-relaxed text-ink-faint">
        <Info className="mt-px h-3 w-3 shrink-0" aria-hidden="true" />
        <span>
          Visualization only. The transformation was performed by the backend
          NormalizationAgent; both boxes above are the exact objects it
          received and returned for this run.
        </span>
      </p>
    </Panel>
  )
}

function ArrowStep({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center py-1.5" data-testid="pipeline-agent">
      <ArrowDown className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
      <span className="font-mono text-[10px] text-accent">{label}</span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Section 4 — transformation summary
// ---------------------------------------------------------------------------

function TransformationSummary({ trace }: { trace: IngestEventTrace }) {
  const rows = summarizeTrace(trace)
  return (
    <Panel
      title="Transformation summary"
      subtitle="Each row is verified against the ingestion response"
      padded={false}
    >
      <Table>
        <thead>
          <tr className="border-b border-edge">
            <Th>Field</Th>
            <Th>Normalized value</Th>
            <Th>Status</Th>
          </tr>
        </thead>
        <tbody className="divide-y divide-edge-soft" data-testid="ingest-summary-table">
          {rows.map((row) => (
            <TRow key={row.field} data-summary-field={row.field}>
              <Td className="font-mono text-[11px] text-ink-dim">{row.field}</Td>
              <Td className="max-w-[260px]">
                <span
                  className="break-all font-mono text-[11px] text-ink"
                  title={row.value}
                >
                  {shorten(row.value, 90)}
                </span>
              </Td>
              <Td>
                <Badge tone={STATUS_TONE[row.status]} title={row.note}>
                  {TRACE_STATUS_LABEL[row.status]}
                </Badge>
              </Td>
            </TRow>
          ))}
        </tbody>
      </Table>
      <p className="border-t border-edge-soft px-3 py-2 text-[10px] leading-relaxed text-ink-faint">
        <span className="font-medium text-ink-dim">preserved</span> — same value
        in both halves. <span className="font-medium text-ink-dim">mapped</span> —
        present in both, translated by the agent.{' '}
        <span className="font-medium text-ink-dim">derived</span> — produced by
        the agent; the raw record carries no such field. Timestamps are
        compared as instants, since the backend re-emits them as UTC.
      </p>
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// Section 5 — inspector
// ---------------------------------------------------------------------------

function Inspector({
  trace,
  tab,
  onTab,
}: {
  trace: IngestEventTrace
  tab: InspectorTab
  onTab: (tab: InspectorTab) => void
}) {
  return (
    <Panel
      title="Event inspector"
      subtitle={`Line ${trace.line_number || '—'} · ${trace.event_id}`}
      padded={false}
    >
      <div
        role="tablist"
        aria-label="Event inspector view"
        className="flex gap-1.5 border-b border-edge-soft px-3 py-2"
      >
        {TABS.map((entry) => (
          <Button
            key={entry.id}
            role="tab"
            type="button"
            size="sm"
            variant={tab === entry.id ? 'default' : 'outline'}
            aria-selected={tab === entry.id}
            onClick={() => onTab(entry.id)}
            data-testid={`ingest-tab-${entry.id}`}
          >
            {entry.label}
          </Button>
        ))}
      </div>

      <div role="tabpanel" className="p-3">
        {tab === 'raw' && <RawView trace={trace} />}
        {tab === 'normalized' && <NormalizedView event={trace.normalized_event} />}
        {tab === 'provenance' && <ProvenanceView trace={trace} />}
      </div>
    </Panel>
  )
}

function RawView({ trace }: { trace: IngestEventTrace }) {
  const keys = Object.keys(trace.raw_event ?? {})
  if (keys.length === 0) {
    return (
      <p className="text-[11px] text-ink-faint">
        The response carries no raw record for this event.
      </p>
    )
  }
  return (
    <div className="space-y-2" data-testid="ingest-raw-panel">
      <p className="text-[10px] uppercase tracking-wider text-ink-faint">
        Raw event · as received
      </p>
      <DataTree value={trace.raw_event} />
    </div>
  )
}

function NormalizedView({ event }: { event: NormalizedSecurityEvent }) {
  return (
    <div className="space-y-3" data-testid="ingest-normalized-panel">
      <div>
        <p className="mb-1 text-[10px] uppercase tracking-wider text-ink-faint">
          Core fields
        </p>
        <FieldList
          rows={[
            ['event_id', event.event_id],
            ['timestamp', formatTimestamp(event.timestamp)],
            ['event_category', event.event_category],
            ['action', event.action],
            ['outcome', event.outcome],
            ['source', event.source],
            ['source_type', event.source_type],
            ['provenance', event.provenance],
          ]}
        />
      </div>

      <div>
        <p className="mb-1 text-[10px] uppercase tracking-wider text-ink-faint">
          Structured entities
        </p>
        <div className="space-y-2">
          <Entity label="actor" value={event.actor} />
          <Entity label="source_endpoint" value={event.source_endpoint} />
          <Entity
            label="destination_endpoint"
            value={event.destination_endpoint}
          />
          <Entity label="process" value={event.process} />
          <Entity label="file" value={event.file} />
        </div>
      </div>

      <div data-testid="ingest-normalized-data">
        <p className="mb-1 text-[10px] uppercase tracking-wider text-ink-faint">
          normalized_data
        </p>
        <DataTree value={event.normalized_data} />
      </div>
    </div>
  )
}

function Entity({ label, value }: { label: string; value: unknown }) {
  if (value === null || value === undefined) {
    return (
      <div data-testid={`ingest-entity-${label}`}>
        <div className="font-mono text-[10px] text-ink-faint">{label}</div>
        <div className="font-mono text-[11px] text-ink-faint">
          — not present in the source event
        </div>
      </div>
    )
  }
  return (
    <div data-testid={`ingest-entity-${label}`}>
      <div className="font-mono text-[10px] text-ink-dim">{label}</div>
      <DataTree value={value} />
    </div>
  )
}

function FieldList({ rows }: { rows: Array<[string, string | null]> }) {
  return (
    <div className="rounded border border-edge-soft bg-surface-0/60">
      {rows.map(([field, value]) => (
        <div
          key={field}
          className="grid grid-cols-[minmax(96px,30%)_minmax(0,1fr)] items-start gap-x-3 border-b border-edge-soft/60 px-2 py-1 last:border-b-0"
        >
          <div className="truncate font-mono text-[10px] text-ink-faint">
            {field}
          </div>
          <div
            className="break-all font-mono text-[11px] text-ink"
            data-normalized-field={field}
          >
            {value === null || value === undefined || value === '' ? '—' : value}
          </div>
        </div>
      ))}
    </div>
  )
}

function ProvenanceView({ trace }: { trace: IngestEventTrace }) {
  const normalized = trace.normalized_event
  const agrees = trace.provenance === normalized.provenance

  return (
    <div className="space-y-3" data-testid="ingest-provenance-panel">
      <div className="rounded border border-edge-soft bg-surface-0/60">
        <div className="grid grid-cols-[minmax(96px,30%)_minmax(0,1fr)] items-start gap-x-3 border-b border-edge-soft/60 px-2 py-1">
          <div className="font-mono text-[10px] text-ink-faint">
            trace.provenance
          </div>
          <div>
            <ProvenanceBadge provenance={trace.provenance} />
          </div>
        </div>
        <div className="grid grid-cols-[minmax(96px,30%)_minmax(0,1fr)] items-start gap-x-3 border-b border-edge-soft/60 px-2 py-1">
          <div className="font-mono text-[10px] text-ink-faint">
            normalized_event.provenance
          </div>
          <div>
            <ProvenanceBadge provenance={normalized.provenance} />
          </div>
        </div>
        <div className="grid grid-cols-[minmax(96px,30%)_minmax(0,1fr)] items-start gap-x-3 px-2 py-1">
          <div className="font-mono text-[10px] text-ink-faint">Consistency</div>
          <div className="text-[11px] text-ink-dim">
            {agrees
              ? 'Both values in the response agree. The event was collected as observed, and normalization did not change its provenance.'
              : 'The two provenance values in the response disagree; treat this run as suspect.'}
          </div>
        </div>
      </div>

      <p className="text-[10px] leading-relaxed text-ink-faint">
        SentinelAI collects every ingested record as <code>observed</code>. The
        NormalizationAgent passes that marker through untouched: mapping a
        record into the common schema is not an enrichment, a reconstruction
        or a synthesis, so it does not change provenance.
      </p>

      <NotAvailable
        title="Not available from ingestion response"
        body={
          'A per-field provenance trail and a stage-by-stage record of which ' +
          'agents touched this event are not part of the response — the ' +
          'pipeline currently exposes only the single event-level marker. ' +
          'Required backend change: IngestEventTrace would need to carry a ' +
          'field-level provenance list and the ordered list of stages that ' +
          'processed the event. Until then this view deliberately shows ' +
          'nothing beyond what the response carries.'
        }
      />
    </div>
  )
}
