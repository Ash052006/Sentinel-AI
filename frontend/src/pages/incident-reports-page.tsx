import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FileText, Plus } from 'lucide-react'
import { incidentReportsApi } from '../api/incident-reports'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { MonoId } from '../components/ui/mono-id'
import { Input, Select, Textarea } from '../components/ui/input'
import { Td, Th, TRow, Table } from '../components/ui/table'
import { formatTimestamp } from '../lib/formats'
import type {
  IncidentReportFinding,
  IncidentReportPayload,
  IncidentReportRecord,
  ReportStatus,
} from '../types/api'

const PAGE_SIZE = 50

function statusLabel(status: ReportStatus): { label: string; tone: 'low' | 'critical' | 'muted' } {
  switch (status) {
    case 'generated':
      return { label: 'GENERATED', tone: 'low' }
    case 'failed':
      return { label: 'FAILED', tone: 'critical' }
  }
}

export function IncidentReportsPage() {
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [selectedReport, setSelectedReport] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const reports = useQuery({
    queryKey: ['incident-reports', 'reports', page, PAGE_SIZE],
    queryFn: () => incidentReportsApi.list(page, PAGE_SIZE),
  })

  const reportDetail = useQuery({
    queryKey: ['incident-reports', 'report', selectedReport],
    queryFn: () => incidentReportsApi.report(selectedReport as string),
    enabled: selectedReport !== null,
  })

  const mutation = useMutation({
    mutationFn: (body: Parameters<typeof incidentReportsApi.generate>[0]) =>
      incidentReportsApi.generate(body),
    onSuccess: () => {
      setNotice('Report generated — the read-only writer persisted a deterministic decision exactly once.')
      void queryClient.invalidateQueries({ queryKey: ['incident-reports'] })
    },
    onError: () => {
      setNotice('Generation rejected (bounded output, unknown correlation, or provider failure).')
    },
  })

  const generate = (body: Parameters<typeof incidentReportsApi.generate>[0]): void =>
    mutation.mutate(body)

  const rows = useMemo(() => reports.data?.items ?? [], [reports.data])
  const selected = reportDetail.data

  const generated = useMemo(
    () => rows.filter((r) => r.status === 'generated').length,
    [rows],
  )
  const failed = useMemo(
    () => rows.filter((r) => r.status === 'failed').length,
    [rows],
  )

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Incident Reports"
        description="V2.20 read-only AI report generation — the LLM composes a narrative over only persisted evidence and may cite only cataloged signals, never fabricating attribution, timestamps or response actions."
      />

      {notice && (
        <div className="rounded border border-low/40 bg-low/10 px-3 py-2 text-xs text-ink" data-testid="report-notice">
          {notice}
        </div>
      )}

      <div className="rounded border border-accent/30 bg-accent/5 px-3 py-2 text-[11px] leading-relaxed text-ink-dim" data-testid="report-disclaimer">
        <span className="font-medium text-ink">Generation only.</span> The report reads persisted
        correlation, detection, intelligence, memory and hunt history and writes one deterministic
        decision row. It never executes policy, responses or SOAR, never fabricates events, and bounds
        every field — overlong values are rejected, never truncated.
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Reports" value={reports.data?.total ?? 0} />
        <Stat label="Generated" value={generated} tone="text-low" />
        <Stat label="Failed" value={failed} tone="text-critical" />
        <Stat label="Visible" value={rows.length} tone="text-accent" />
      </div>

      <Panel
        title="New report"
        subtitle="Generate a V2.20 narrative over a correlation — the LLM may cite only evidence already in the catalog."
        data-testid="report-create-panel"
      >
        <NewReportForm busy={mutation.isPending} onGenerate={generate} />
      </Panel>

      <Panel
        title="Reports"
        subtitle="Persisted report decisions, newest first — failed generations keep their error so the surface stays auditable."
        padded={false}
        data-testid="reports-panel"
      >
        {reports.isLoading ? (
          <LoadingRows rows={8} />
        ) : reports.isError ? (
          <ErrorState message={String(reports.error)} onRetry={() => void reports.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            title="No reports yet"
            body="Generate a report above or through the governed API to see decisions here."
          />
        ) : (
          <>
            <Table>
              <thead>
                <tr className="border-b border-edge">
                  <Th>Status</Th>
                  <Th>Report</Th>
                  <Th>Correlation</Th>
                  <Th>Model</Th>
                  <Th>By</Th>
                  <Th>Generated</Th>
                  <Th />
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {rows.map((record) => {
                  const label = statusLabel(record.status)
                  return (
                    <TRow
                      key={record.report_id}
                      onClick={() => setSelectedReport(record.report_id)}
                      className="cursor-pointer"
                      data-testid="incident-report-row"
                    >
                      <Td>
                        <Badge tone={label.tone}>{label.label}</Badge>
                      </Td>
                      <Td className="max-w-[220px]">
                        <div className="truncate text-xs font-medium text-ink" title={record.title ?? 'Decision without title'}>
                          {record.title ?? 'Failed generation'}
                        </div>
                        <MonoId id={record.report_id} />
                      </Td>
                      <Td>
                        <MonoId id={record.correlation_id} />
                      </Td>
                      <Td className="font-mono text-[11px] text-ink-dim">{record.model ?? '—'}</Td>
                      <Td className="whitespace-nowrap text-[11px] text-ink-dim">{record.generated_by_role}</Td>
                      <Td className="font-mono text-[10px] text-ink-faint">
                        {record.generated_at ? formatTimestamp(record.generated_at) : '—'}
                      </Td>
                      <Td className="text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={record.status !== 'generated'}
                          onClick={(event) => {
                            event.stopPropagation()
                            setSelectedReport(record.report_id)
                          }}
                          data-testid={`view-${record.report_id}`}
                        >
                          <FileText className="h-3 w-3" aria-hidden="true" />
                          View
                        </Button>
                      </Td>
                    </TRow>
                  )
                })}
              </tbody>
            </Table>
            {reports.data && reports.data.total > PAGE_SIZE && (
              <div className="flex items-center justify-between border-t border-edge-soft px-4 py-2 text-[11px] text-ink-dim">
                <span>
                  Page {reports.data.page} of {Math.max(1, Math.ceil(reports.data.total / PAGE_SIZE))} ·{' '}
                  {reports.data.total} reports
                </span>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                    Prev
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page >= Math.ceil(reports.data.total / PAGE_SIZE)}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </Panel>

      <Panel
        title="Report detail"
        subtitle={selected ? `${selected.title ?? 'Failed generation'} · ${selected.report_id}` : 'Select a report row to inspect the generated narrative and its evidence surface.'}
        padded={false}
      >
        {reportDetail.isLoading ? (
          <LoadingRows rows={6} />
        ) : reportDetail.isError ? (
          <ErrorState message={String(reportDetail.error)} />
        ) : selected ? (
          <ReportDetail detail={selected} />
        ) : (
          <div className="p-4">
            <NotAvailable
              title="No report selected"
              body="Select a report from the table to inspect its bounded V2.20 payload and the determined evidence catalog."
            />
          </div>
        )}
      </Panel>
    </div>
  )
}

function NewReportForm({
  busy,
  onGenerate,
}: {
  busy: boolean
  onGenerate: (body: Parameters<typeof incidentReportsApi.generate>[0]) => void
}) {
  const [correlationId, setCorrelationId] = useState('')
  const [note, setNote] = useState('Cite only catalog-observed evidence; attribution and response intent stay NOT_PROVIDED.')

  const valid = correlationId.trim().length > 0

  const submit = (event: React.FormEvent): void => {
    event.preventDefault()
    if (!valid) return
    onGenerate({ correlation_id: correlationId.trim(), report_version: '2.20' })
  }

  return (
    <form
      className="flex flex-wrap items-end gap-3"
      data-testid="report-generate-form"
      onSubmit={submit}
    >
      <div className="space-y-1">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">Correlation ID</div>
        <Input
          aria-label="Correlation ID"
          className="h-8 w-72 text-[11px] font-mono"
          placeholder="cor_…"
          value={correlationId}
          onChange={(event) => setCorrelationId(event.target.value)}
        />
      </div>
      <div className="space-y-1">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">Version</div>
        <Select aria-label="Report version" className="h-8 text-[11px]" value="2.20" disabled>
          <option value="2.20">2.20</option>
        </Select>
      </div>
      <div className="flex gap-2">
        <Button size="sm" disabled={busy || !valid} type="submit">
          <Plus className="h-3 w-3" aria-hidden="true" />
          Generate report
        </Button>
      </div>
      <div className="w-full">
        <Textarea
          aria-label="Generation note"
          className="h-12 text-[11px]"
          value={note}
          onChange={(event) => setNote(event.target.value)}
        />
      </div>
      <p className="w-full text-[11px] leading-relaxed text-ink-dim">
        Unknown correlations are rejected with a 404 and record no failed row; every other failure
        persists the failed decision so the audit trail is complete.
      </p>
    </form>
  )
}

function ReportDetail({ detail }: { detail: IncidentReportRecord }) {
  const payload = detail.payload
  const label = statusLabel(detail.status)
  return (
    <div className="space-y-0" data-testid="report-detail-panel">
      <div className="space-y-3 border-b border-edge-soft p-4">
        <div className="flex flex-wrap items-center gap-2 text-[11px]">
          <Badge tone={label.tone}>{label.label}</Badge>
          <span className="text-ink-dim">schema</span>
          <span className="font-mono text-ink-faint">{payload?.schema_version ?? '—'}</span>
          <span className="text-ink-dim">· model</span>
          <span className="font-mono text-ink-faint">{payload?.model ?? detail.model ?? '—'}</span>
          {detail.generated_at && (
            <>
              <span className="text-ink-dim">· at</span>
              <span className="font-mono text-ink-faint">{formatTimestamp(detail.generated_at)}</span>
            </>
          )}
          <span className="text-ink-dim">· by {detail.generated_by_role}</span>
        </div>
        {detail.error_code && (
          <div className="rounded border border-critical/30 bg-critical/5 px-2 py-1 font-mono text-[10px] text-critical" data-testid="report-error">
            {detail.error_code}: {detail.error_message}
          </div>
        )}
        {payload && (
          <div className="grid grid-cols-2 gap-2 text-[11px] md:grid-cols-4">
            <PayloadStat label="Correlation" value={payload.correlation.length} />
            <PayloadStat label="Detections" value={payload.detections.length} />
            <PayloadStat label="Timeline" value={payload.timeline.length} />
            <PayloadStat label="Evidence cited" value={payload.evidence_catalog.length} />
          </div>
        )}
      </div>

      <div className="p-4">
        {detail.status !== 'generated' || !payload ? (
          <NotAvailable
            title="No payload"
            body="Only generated decisions carry a bounded V2.20 payload; failed rows keep their error surface."
          />
        ) : (
          <ReportPayloadView payload={payload} />
        )}
      </div>
    </div>
  )
}

function PayloadStat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-ink-faint">{label}</div>
      <div className="mt-0.5 font-mono text-ink">{value}</div>
    </div>
  )
}

function ReportPayloadView({ payload }: { payload: IncidentReportPayload }) {
  return (
    <div className="space-y-4" data-testid="report-payload">
      <section className="space-y-2 rounded border border-edge-soft p-3">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">AI narrative</div>
        <Narrative block={payload.ai.title} label="Title" />
        <Narrative block={payload.ai.executive_summary} label="Executive summary" />
        <Narrative block={payload.ai.incident_overview} label="Incident overview" />
        <Narrative block={payload.ai.attribution_summary} label="Attribution" />
        <Narrative block={payload.ai.response_summary} label="Response" />
      </section>

      <section className="space-y-2 rounded border border-edge-soft p-3">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">Findings</div>
        {payload.ai.findings.length === 0 ? (
          <p className="text-[11px] text-ink-faint">No findings.</p>
        ) : (
          <FindingsTable records={payload.ai.findings} />
        )}
      </section>

      <section className="space-y-2 rounded border border-edge-soft p-3">
        <div className="text-[10px] uppercase tracking-wider text-ink-faint">Evidence catalog</div>
        {payload.evidence_catalog.length === 0 ? (
          <p className="text-[11px] text-ink-faint">No cataloged evidence.</p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {payload.evidence_catalog.map((evidence) => (
              <span
                key={evidence.reference_id}
                className="rounded border border-edge-soft bg-surface-2 px-2 py-0.5 font-mono text-[10px] text-ink-dim"
              >
                {evidence.reference_id}
              </span>
            ))}
          </div>
        )}
      </section>

      {payload.source_limitations.length > 0 && (
        <section className="space-y-2 rounded border border-edge-soft p-3">
          <div className="text-[10px] uppercase tracking-wider text-ink-faint">Source limitations</div>
          <ul className="list-disc space-y-0.5 pl-4 text-[11px] text-ink-dim">
            {payload.source_limitations.map((limited) => (
              <li key={limited}>{limited}</li>
            ))}
          </ul>
        </section>
      )}

      {payload.ai.limitations.length + payload.ai.recommended_follow_up.length > 0 && (
        <section className="grid gap-4 md:grid-cols-2">
          <div className="space-y-1.5 rounded border border-edge-soft p-3">
            <div className="text-[10px] uppercase tracking-wider text-ink-faint">Limitations</div>
            <ul className="list-disc space-y-0.5 pl-4 text-[11px] text-ink-dim">
              {payload.ai.limitations.map((limited) => (
                <li key={limited}>{limited}</li>
              ))}
            </ul>
          </div>
          <div className="space-y-1.5 rounded border border-edge-soft p-3">
            <div className="text-[10px] uppercase tracking-wider text-ink-faint">Recommended follow-up</div>
            <ul className="list-disc space-y-0.5 pl-4 text-[11px] text-ink-dim">
              {payload.ai.recommended_follow_up.map((action) => (
                <li key={action}>{action}</li>
              ))}
            </ul>
          </div>
        </section>
      )}
    </div>
  )
}

function Narrative({ block, label }: { block: string | null | undefined; label: string }) {
  if (!block) return null
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-ink-faint">{label}</div>
      <p className="mt-0.5 text-[11px] leading-relaxed text-ink-dim">{block}</p>
    </div>
  )
}

function FindingsTable({ records }: { records: IncidentReportFinding[] }) {
  return (
    <Table>
      <thead>
        <tr className="border-b border-edge">
          <Th>Finding</Th>
          <Th>Evidence refs</Th>
          <Th>Provenance</Th>
        </tr>
      </thead>
      <tbody className="divide-y divide-edge-soft">
        {records.map((record) => (
          <tr key={record.title}>
            <Td className="max-w-[260px]">
              <span className="block truncate text-xs font-medium text-ink" title={record.title}>
                {record.title}
              </span>
              <span className="block truncate text-[10px] text-ink-faint" title={record.summary}>
                {record.summary}
              </span>
            </Td>
            <Td className="font-mono text-[10px] text-ink-dim">{record.evidence_references.length}</Td>
            <Td className="font-mono text-[10px] text-ink-dim">{record.provenance}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  )
}