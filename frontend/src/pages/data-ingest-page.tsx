import { useCallback, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { AlertTriangle, FileUp, Upload, X } from 'lucide-react'
import { ingestApi, type IngestFormat, type IngestSummary } from '../api/ingest'
import { ApiError } from '../api/client'
import { Button } from '../components/ui/button'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { TBody, Td, Th, THead, Table, TRow } from '../components/ui/table'
import { ErrorState } from '../components/states'
import { IngestTransformation } from '../components/ingest-transformation'
import { cn } from '../lib/utils'

const MAX_BYTES = 10 * 1024 * 1024

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function DataIngestPage() {
  const queryClient = useQueryClient()
  const inputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)

  const format = useQuery({
    queryKey: ['ingest', 'format'],
    queryFn: () => ingestApi.format(),
    staleTime: 5 * 60 * 1000,
  })

  const upload = useMutation({
    mutationFn: (target: File) => ingestApi.events(target),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['detections'] })
    },
  })

  const accept = useCallback((candidate: File | undefined) => {
    if (!candidate) return
    if (candidate.size === 0) return
    if (candidate.size > MAX_BYTES) return
    setFile(candidate)
    upload.reset()
  }, [upload])

  const onDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault()
      setDragging(false)
      accept(event.dataTransfer.files?.[0])
    },
    [accept],
  )

  const submit = useCallback(() => {
    if (file) upload.mutate(file)
  }, [file, upload])

  const clear = useCallback(() => {
    setFile(null)
    upload.reset()
    if (inputRef.current) inputRef.current.value = ''
  }, [upload])

  const summary: IngestSummary | undefined = upload.data

  return (
    <>
      <PageHeader
        title="Data Ingest"
        description="Load a JSON Lines file of security events. Records are collected, normalized by the NormalizationAgent, evaluated against the deployed rule set, and any matches are written to the Detections view."
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Panel
            title="Upload"
            subtitle="One JSON object per line. Max 10 MB."
            action={
              file ? (
                <Button variant="ghost" size="sm" onClick={clear} data-testid="ingest-clear">
                  <X className="h-3 w-3" />
                  Clear
                </Button>
              ) : null
            }
          >
            <div
              onDragOver={(event) => {
                event.preventDefault()
                setDragging(true)
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              className={cn(
                'rounded-md border border-dashed px-4 py-8 text-center transition-colors',
                dragging ? 'border-accent bg-accent/5' : 'border-edge',
              )}
            >
              <FileUp className="mx-auto h-6 w-6 text-ink-faint" />
              <div className="mt-2 text-xs text-ink-dim">
                Drop a <span className="font-mono">.jsonl</span> file here, or
              </div>
              <Button
                variant="outline"
                size="sm"
                className="mt-3"
                onClick={() => inputRef.current?.click()}
                data-testid="ingest-browse"
              >
                Browse files
              </Button>
              <input
                ref={inputRef}
                type="file"
                accept=".jsonl,.ndjson,.json,application/x-ndjson,application/json"
                className="hidden"
                data-testid="ingest-input"
                onChange={(event) => accept(event.target.files?.[0])}
              />
            </div>

            {file && (
              <div className="mt-3 flex items-center justify-between gap-3 rounded border border-edge-soft bg-surface-2 px-3 py-2">
                <div className="min-w-0">
                  <div className="truncate font-mono text-xs text-ink">
                    {file.name}
                  </div>
                  <div className="text-[11px] text-ink-faint">
                    {formatBytes(file.size)}
                  </div>
                </div>
                <Button
                  onClick={submit}
                  disabled={upload.isPending}
                  data-testid="ingest-submit"
                >
                  <Upload className="h-3 w-3" />
                  {upload.isPending ? 'Ingesting…' : 'Ingest'}
                </Button>
              </div>
            )}

            {upload.isError && (
              <div className="mt-3">
                <ErrorState
                  message={
                    upload.error instanceof ApiError
                      ? upload.error.message
                      : String(upload.error)
                  }
                  onRetry={submit}
                />
              </div>
            )}
          </Panel>

          {summary && <ResultPanel summary={summary} />}
        </div>

        <FormatPanel format={format.data} loading={format.isLoading} />
      </div>

      {(summary || upload.isPending) && (
        <div className="mt-4">
          <IngestTransformation summary={summary} pending={upload.isPending} />
        </div>
      )}
    </>
  )
}

function ResultPanel({ summary }: { summary: IngestSummary }) {
  const clean = summary.rejected_records === 0
  return (
    <Panel
      title="Result"
      subtitle={`Completed in ${summary.duration_ms} ms against ${summary.active_rule_count} active rules.`}
      data-testid="ingest-result"
    >
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <Stat label="Records read" value={summary.total_records} />
        <Stat label="Accepted" value={summary.accepted_events} />
        <Stat
          label="Rejected"
          value={summary.rejected_records}
          tone={clean ? undefined : 'text-warn'}
        />
        <Stat label="Processed" value={summary.events_processed} />
        <Stat
          label="Detections"
          value={summary.detections}
          tone={summary.detections > 0 ? 'text-critical' : undefined}
        />
        <Stat label="Results written" value={summary.detection_results_created} />
      </div>

      {summary.detections > 0 && (
        <div className="mt-4 flex items-center justify-between gap-3 rounded border border-critical/30 bg-critical/5 px-3 py-2">
          <span className="text-xs text-ink">
            {summary.detections} match
            {summary.detections === 1 ? '' : 'es'} across{' '}
            {summary.events_with_detections} event
            {summary.events_with_detections === 1 ? '' : 's'}.
          </span>
          <Link
            to="/detections"
            className="shrink-0 text-xs text-accent hover:underline"
          >
            View detections →
          </Link>
        </div>
      )}

      {summary.errors.length > 0 && (
        <div className="mt-4">
          <div className="mb-2 flex items-center gap-1.5 text-xs font-medium text-warn">
            <AlertTriangle className="h-3.5 w-3.5" />
            Rejected lines
            {summary.truncated_errors && (
              <span className="text-ink-faint">
                (showing {summary.errors.length})
              </span>
            )}
          </div>
          <Table>
            <THead>
              <TRow>
                <Th>Line</Th>
                <Th>Reason</Th>
              </TRow>
            </THead>
            <TBody>
              {summary.errors.map((error, index) => (
                <TRow key={`${error.line_number}-${index}`}>
                  <Td className="font-mono text-[11px]">
                    {error.line_number || '—'}
                  </Td>
                  <Td className="text-[11px]">{error.reason}</Td>
                </TRow>
              ))}
            </TBody>
          </Table>
        </div>
      )}

      {summary.rule_failures > 0 && (
        <p className="mt-4 text-[11px] text-ink-faint">
          {summary.rule_failures} rule evaluation
          {summary.rule_failures === 1 ? '' : 's'} could not run against these
          events (typically YARA rules with no file content). This is expected
          and does not affect the results above.
        </p>
      )}
    </Panel>
  )
}

function FormatPanel({
  format,
  loading,
}: {
  format: IngestFormat | undefined
  loading: boolean
}) {
  if (loading) {
    return (
      <Panel title="Expected format">
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, index) => (
            <div
              key={index}
              className="h-3 animate-pulse rounded bg-surface-2"
            />
          ))}
        </div>
      </Panel>
    )
  }

  if (!format) {
    return (
      <Panel title="Expected format">
        <ErrorState message="Could not load the format contract." />
      </Panel>
    )
  }

  return (
    <Panel title="Expected format" subtitle={format.description}>
      <div className="space-y-4 text-[11px]">
        <div>
          <div className="mb-1 font-semibold uppercase tracking-wider text-ink-dim">
            Required per line
          </div>
          <ul className="space-y-1">
            {format.required_fields.map((field) => (
              <li key={field.name}>
                <span className="font-mono text-ink">{field.name}</span>
                <span className="text-ink-faint"> — {field.description}</span>
              </li>
            ))}
          </ul>
        </div>

        <div>
          <div className="mb-1 font-semibold uppercase tracking-wider text-ink-dim">
            Optional
          </div>
          <ul className="space-y-1">
            {format.optional_fields.map((field) => (
              <li key={field.name}>
                <span className="font-mono text-ink">{field.name}</span>
                <span className="text-ink-faint"> — {field.description}</span>
              </li>
            ))}
          </ul>
        </div>

        <div>
          <div className="mb-1 font-semibold uppercase tracking-wider text-ink-dim">
            source_type
          </div>
          <div className="flex flex-wrap gap-1">
            {format.source_types.map((value) => (
              <span
                key={value}
                className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-ink-dim"
              >
                {value}
              </span>
            ))}
          </div>
        </div>

        <div>
          <div className="mb-1 font-semibold uppercase tracking-wider text-ink-dim">
            event_type → category
          </div>
          <div className="flex flex-wrap gap-1">
            {format.recognized_event_types.map((entry) => (
              <span
                key={entry.event_type}
                title={entry.event_category}
                className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-ink-dim"
              >
                {entry.event_type}
              </span>
            ))}
          </div>
        </div>

        {format.notes.length > 0 && (
          <div>
            <div className="mb-1 font-semibold uppercase tracking-wider text-ink-dim">
              Notes
            </div>
            <ul className="list-disc space-y-1 pl-4 text-ink-faint">
              {format.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          </div>
        )}

        <div>
          <div className="mb-1 font-semibold uppercase tracking-wider text-ink-dim">
            Example
          </div>
          <pre className="overflow-x-auto rounded bg-surface-2 p-2 font-mono text-[10px] leading-relaxed text-ink-dim">
            {format.example_lines[0]}
          </pre>
        </div>
      </div>
    </Panel>
  )
}
