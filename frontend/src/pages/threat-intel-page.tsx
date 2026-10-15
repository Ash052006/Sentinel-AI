import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { BookKey, ExternalLink } from 'lucide-react'

import { threatIntelligenceApi } from '../api/threat-intelligence'
import { ApiError } from '../api/client'
import { EmptyState, ErrorState, LoadingRows, NotAvailable } from '../components/states'
import { DataTree } from '../components/data-tree'
import { PageHeader, Panel, Stat } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Input, Select } from '../components/ui/input'
import { Pagination } from '../components/ui/pagination'
import { Table, Td, Th, TRow } from '../components/ui/table'
import {
  indicatorLookupStatusMeta,
  indicatorTypeLabel,
  indicatorTypeTone,
  lookupStatusMeta,
} from '../lib/labels'
import { formatDateTime, shortId } from '../lib/formats'
import type {
  IndicatorLookupStatus,
  IndicatorType,
  ThreatIntelIndicatorRecord,
  ThreatIntelLookupRecord,
} from '../types/api'

/**
 * Threat Intelligence — Step 8A read surface.
 *
 * Renders what the Threat Intelligence Agent actually persisted: the
 * extracted indicators, and for each one the provider lookups that ran
 * against it.
 *
 * What this view deliberately does not do
 * ---------------------------------------
 * Step 8A persists no malicious/benign verdict, no severity, and no risk, so
 * this page renders none.  The four states a lookup can be in are kept
 * distinct rather than collapsed into a good/bad binary:
 *
 *   queried and returned data  -> ENRICHED
 *   queried, provider had none -> NO DATA       (not a clean bill of health)
 *   provider could not answer  -> FAILED / RATE LIMITED / TIMED OUT /
 *                                 REJECTED / UNAVAILABLE
 *   never asked                -> the provider is simply absent from `providers`
 *
 * A provider failing is an operational fact, not evidence that an indicator
 * is malicious, and the UI never converts one into the other.
 */

const PAGE_SIZE = 50
const INDICATOR_TYPES: IndicatorType[] = ['ip', 'domain', 'url', 'hash']

/** Lookup statuses that represent a provider problem rather than a result. */
const FAILURE_LABELS = new Set([
  'FAILED',
  'RATE LIMITED',
  'TIMED OUT',
  'REJECTED',
  'UNAVAILABLE',
])

function isAccessError(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 401 || error.status === 403)
}

function LookupRow({ lookup }: { lookup: ThreatIntelLookupRecord }) {
  const tone = lookupStatusMeta[lookup.status_label]?.tone ?? 'neutral'
  const status = lookup.status_label
  const summary = lookup.error_message ?? null

  return (
    <TRow data-testid="ti-lookup-row" className="align-top">
      <Td className="whitespace-nowrap font-medium text-ink">{lookup.provider}</Td>
      <Td>
        <Badge tone={tone} data-testid="ti-lookup-status">
          {status}
        </Badge>
      </Td>
      <Td className="whitespace-nowrap text-[11px] text-ink-dim">
        {formatDateTime(lookup.performed_at)}
      </Td>
      <Td className="text-[11px] text-ink-dim">
        {lookup.status === 'success' ? (
          <>
            {lookup.provider_result_available ? 'Provider returned data' : 'No provider data stored'}
            {lookup.found === null ? null : lookup.found ? (
              <span className="ml-1 text-ink">· record found</span>
            ) : (
              <span className="ml-1 text-ink">· no record for this indicator</span>
            )}
          </>
        ) : (
          <span data-testid="ti-lookup-error">
            {summary ??
              (lookup.error_type ? `Provider error (${lookup.error_type})` : 'Provider error')}
            {lookup.retryable ? ' · retryable' : ''}
          </span>
        )}
        {lookup.confidence !== null && (
          <div className="mt-1 text-ink-faint">
            provider confidence {lookup.confidence.toFixed(2)}
          </div>
        )}
      </Td>
    </TRow>
  )
}

function IndicatorDetail({ indicatorId }: { indicatorId: string }) {
  const detail = useQuery({
    queryKey: ['threat-intelligence', 'indicator', indicatorId],
    queryFn: () => threatIntelligenceApi.indicator(indicatorId),
    enabled: indicatorId !== null,
  })

  if (detail.isLoading) return <LoadingRows rows={5} />
  if (detail.isError) {
    return (
      <ErrorState
        message={String(detail.error)}
        onRetry={() => void detail.refetch()}
      />
    )
  }
  if (!detail.data) return null

  const { indicator, lookups, lookups_truncated, events, events_truncated } = detail.data
  const statusMeta = indicatorLookupStatusMeta[indicator.status]

  // One row per provider, newest first, so a provider that was queried
  // several times does not silently collapse into a single status.
  const byProvider = new Map<string, ThreatIntelLookupRecord[]>()
  for (const lookup of lookups) {
    const bucket = byProvider.get(lookup.provider)
    if (bucket) bucket.push(lookup)
    else byProvider.set(lookup.provider, [lookup])
  }

  const failureCount = lookups.filter((l) => FAILURE_LABELS.has(l.status_label)).length
  const enrichedCount = lookups.filter((l) => l.status_label === 'ENRICHED').length
  const noDataCount = lookups.filter((l) => l.status_label === 'NO DATA').length

  return (
    <div className="space-y-3 p-4" data-testid="ti-detail">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Lookups" value={indicator.lookup_count} />
        <Stat label="Provider data" value={enrichedCount} tone="text-low" />
        <Stat label="No data" value={noDataCount} />
        <Stat
          label="Provider failures"
          value={failureCount}
          tone={failureCount > 0 ? 'text-critical' : undefined}
        />
      </div>

      <dl className="grid grid-cols-1 gap-2 text-[11px] sm:grid-cols-2" data-testid="ti-detail-summary">
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-ink-faint">Type</dt>
          <dd>
            <Badge tone={indicatorTypeTone[indicator.indicator_type]}>
              {indicatorTypeLabel[indicator.indicator_type]}
            </Badge>
          </dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-ink-faint">Status</dt>
          <dd data-testid="ti-detail-status">
            <Badge tone={statusMeta.tone}>{statusMeta.label}</Badge>
          </dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-ink-faint">First seen</dt>
          <dd className="font-mono text-ink">{formatDateTime(indicator.first_seen)}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-ink-faint">Last seen</dt>
          <dd className="font-mono text-ink">{formatDateTime(indicator.last_seen)}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-ink-faint">Canonical key</dt>
          <dd className="font-mono text-ink-dim" data-testid="ti-canonical-key">
            {indicator.canonical_key}
          </dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-ink-faint">Indicator</dt>
          <dd className="break-all font-mono text-ink">{indicator.value}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-ink-faint">Indicator ID</dt>
          <dd className="font-mono text-ink-dim">{indicator.indicator_id}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-ink-faint">Extraction</dt>
          <dd className="text-ink-dim">provenance {indicator.provenance.replace(/_/g, ' ')}</dd>
        </div>
      </dl>

      <div>
        <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-dim">
          Provider lookups
        </div>
        <div className="h-px bg-edge" />
      </div>

      {lookups.length === 0 ? (
        <EmptyState
          title="No lookups recorded"
          body="This indicator was extracted from a security event but no provider lookup was persisted for it, so there is no provider status to show."
        />
      ) : (
        <>
          <Table>
            <thead className="border-b border-edge">
              <tr>
                <Th>Provider</Th>
                <Th>Status</Th>
                <Th>Lookup timestamp</Th>
                <Th>Result</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge-soft">
              {lookups.map((lookup) => (
                <LookupRow key={lookup.lookup_id} lookup={lookup} />
              ))}
            </tbody>
          </Table>
          {lookups_truncated && (
            <p className="mt-2 text-[11px] text-ink-faint" data-testid="ti-lookups-truncated">
              Lookup history truncated — showing the most recent records only.
            </p>
          )}
        </>
      )}

      {enrichedCount > 0 && (
        <>
          <div>
            <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-dim">
              Provider evidence
            </div>
            <div className="h-px bg-edge" />
          </div>
          <p className="text-[11px] text-ink-faint">
            Safe fields as persisted by the provider lookup. Credentials and raw provider
            response bodies are withheld server-side.
          </p>
          <div className="space-y-2" data-testid="ti-evidence">
            {lookups
              .filter((lookup) => lookup.provider_result_available && lookup.evidence)
              .map((lookup) => (
                <div key={lookup.lookup_id} data-testid="ti-evidence-block">
                  <div className="mb-1 text-[10px] uppercase tracking-wider text-ink-faint">
                    {lookup.provider}
                  </div>
                  <DataTree value={lookup.evidence} />
                </div>
              ))}
          </div>
        </>
      )}

      <div>
        <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-dim">
          Correlated events
        </div>
        <div className="h-px bg-edge" />
      </div>
      {events.length === 0 ? (
        <p className="text-[11px] text-ink-faint" data-testid="ti-no-events">
          No correlated security events are recorded for this indicator.
        </p>
      ) : (
        <div className="flex flex-wrap gap-1" data-testid="ti-events">
          {events.map((eventId) => (
            <span
              key={eventId}
              className="rounded border border-edge bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-ink-dim"
            >
              {shortId(eventId)}
            </span>
          ))}
          {events_truncated && (
            <span className="text-[10px] text-ink-faint">additional events not shown</span>
          )}
        </div>
      )}
      <p className="text-[10px] text-ink-faint">
        Event ids are correlation keys recorded on lookups. SentinelAI persists no
        security-event store, so they are not dereferenced here.
      </p>
    </div>
  )
}

export function ThreatIntelPage() {
  const [page, setPage] = useState(1)
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<string | null>(null)

  const indicators = useQuery({
    queryKey: ['threat-intelligence', 'indicators', page, typeFilter, query],
    queryFn: () =>
      threatIntelligenceApi.listIndicators(page, PAGE_SIZE, typeFilter || undefined, query || undefined),
  })

  // Memoized so the derived `useMemo` counters below do not recompute on
  // every render while the query is refetching.
  const rows = useMemo(() => indicators.data?.items ?? [], [indicators.data])
  const total = indicators.data?.total ?? 0
  const selectedRecord = useMemo<ThreatIntelIndicatorRecord | undefined>(
    () => rows.find((row) => row.indicator_id === selected),
    [rows, selected],
  )

  const enriched = useMemo(
    () => rows.filter((r) => r.status === 'enriched').length,
    [rows],
  )
  const partial = useMemo(() => rows.filter((r) => r.status === 'partial').length, [rows])
  const failed = useMemo(() => rows.filter((r) => r.status === 'failed').length, [rows])
  const noLookup = useMemo(() => rows.filter((r) => r.status === 'no_lookup').length, [rows])
  const lookups = useMemo(
    () => rows.reduce((sum, row) => sum + row.lookup_count, 0),
    [rows],
  )
  const failures = useMemo(
    () => rows.reduce((sum, row) => sum + row.error_count, 0),
    [rows],
  )

  const accessDenied = isAccessError(indicators.error)

  function applySearch(event: React.FormEvent) {
    event.preventDefault()
    setPage(1)
    setQuery(search.trim())
  }

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Threat Intelligence"
        description="Indicators extracted from normalized security events, with the provider lookups persisted against them."
      />

      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1">
          <span className="text-[10px] uppercase tracking-wider text-ink-dim">Type</span>
          <Select
            aria-label="Filter by indicator type"
            value={typeFilter}
            className="h-8 w-36 text-[11px] font-mono"
            onChange={(event) => {
              setPage(1)
              setTypeFilter(event.target.value)
            }}
          >
            <option value="">All types</option>
            {INDICATOR_TYPES.map((type) => (
              <option key={type} value={type}>
                {indicatorTypeLabel[type]}
              </option>
            ))}
          </Select>
        </label>

        <form onSubmit={applySearch} className="flex items-end gap-2">
          <label className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-wider text-ink-dim">Search</span>
            <Input
              aria-label="Search indicators"
              value={search}
              placeholder="indicator value or canonical key"
              className="h-8 w-72 text-[11px] font-mono"
              onChange={(event) => setSearch(event.target.value)}
            />
          </label>
          <Button type="submit" size="sm" variant="outline">
            Search
          </Button>
          {(query || typeFilter) && (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => {
                setSearch('')
                setQuery('')
                setTypeFilter('')
                setPage(1)
              }}
            >
              Clear
            </Button>
          )}
        </form>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Indicators" value={total} />
        <Stat label="Lookups" value={lookups} tone="text-accent" />
        <Stat label="Provider failures" value={failures} tone={failures > 0 ? 'text-critical' : undefined} />
        <Stat label="On this page" value={rows.length} />
      </div>

      {rows.length > 0 && (
        <p className="text-[11px] text-ink-faint" data-testid="ti-status-legend">
          This view reports provider outcomes only. Step 8A persists no malicious/benign
          verdict, severity, or risk, so none is shown — on this page: {enriched} enriched,{' '}
          {partial} partial, {failed} failed, {noLookup} never looked up.
        </p>
      )}

      <Panel
        title="Indicators"
        subtitle="Most recently observed first"
        padded={false}
        data-testid="ti-indicators-panel"
      >
        {indicators.isLoading ? (
          <LoadingRows rows={8} />
        ) : indicators.isError ? (
          accessDenied ? (
            <div className="p-4">
              <NotAvailable
                title="Threat intelligence is not available to your role"
                body="The read surface requires an admin, analyst, or ciso role. This account cannot read persisted threat-intelligence indicators."
              />
            </div>
          ) : (
            <ErrorState
              message={String(indicators.error)}
              onRetry={() => void indicators.refetch()}
            />
          )
        ) : rows.length === 0 ? (
          <div className="p-4">
            <EmptyState
              title={query || typeFilter ? 'No indicators match' : 'No indicators recorded'}
              body={
                query || typeFilter
                  ? 'No persisted indicator matches the current filters. Clear them to see every recorded indicator.'
                  : 'No threat-intelligence indicator has been persisted yet. Indicators are created by the Threat Intelligence Agent when it extracts one from a normalized security event; none have been recorded.'
              }
            />
          </div>
        ) : (
          <>
            <Table>
              <thead className="border-b border-edge">
                <tr>
                  <Th>Type</Th>
                  <Th>Indicator</Th>
                  <Th>First seen</Th>
                  <Th>Last seen</Th>
                  <Th>Providers</Th>
                  <Th>Status</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge-soft">
                {rows.map((row) => {
                  const meta = indicatorLookupStatusMeta[row.status as IndicatorLookupStatus]
                  return (
                    <TRow
                      key={row.indicator_id}
                      onClick={() => setSelected(row.indicator_id)}
                      className="cursor-pointer"
                      data-testid="ti-indicator-row"
                      aria-selected={selected === row.indicator_id}
                    >
                      <Td>
                        <Badge tone={indicatorTypeTone[row.indicator_type]}>
                          {indicatorTypeLabel[row.indicator_type]}
                        </Badge>
                      </Td>
                      <Td className="max-w-md break-all font-mono text-[11px] text-ink">
                        {row.value}
                      </Td>
                      <Td className="whitespace-nowrap text-[11px] text-ink-dim">
                        {formatDateTime(row.first_seen)}
                      </Td>
                      <Td className="whitespace-nowrap text-[11px] text-ink-dim">
                        {formatDateTime(row.last_seen)}
                      </Td>
                      <Td className="text-[11px] text-ink-dim" data-testid="ti-row-providers">
                        {row.providers.length > 0 ? row.providers.join(', ') : '—'}
                      </Td>
                      <Td>
                        <Badge tone={meta.tone} data-testid="ti-row-status">
                          {meta.label}
                        </Badge>
                      </Td>
                    </TRow>
                  )
                })}
              </tbody>
            </Table>
            <div className="border-t border-edge p-3">
              <Pagination
                page={page}
                pageSize={PAGE_SIZE}
                total={total}
                onPage={setPage}
                onPageSize={() => {
                  /* page size is fixed for this read surface */
                }}
              />
            </div>
          </>
        )}
      </Panel>

      <Panel
        title="Indicator detail"
        subtitle={
          selectedRecord
            ? `${indicatorTypeLabel[selectedRecord.indicator_type]} · ${selectedRecord.value}`
            : 'Select an indicator to inspect its provider lookups'
        }
        padded={false}
        data-testid="ti-detail-panel"
      >
        {selected ? (
          <>
            <div className="flex items-center gap-2 border-b border-edge px-4 py-2">
              <BookKey className="h-3.5 w-3.5 text-ink-dim" aria-hidden="true" />
              <span className="font-mono text-[11px] text-ink-dim">{shortId(selected)}</span>
              <Button
                size="sm"
                variant="ghost"
                className="ml-auto"
                onClick={() => setSelected(null)}
              >
                Clear selection
              </Button>
            </div>
            <IndicatorDetail indicatorId={selected} />
          </>
        ) : (
          <div className="p-4">
            <NotAvailable
              title="No indicator selected"
              body="Select an indicator from the table to inspect its persisted provider lookups, provider status, and safe result summary."
            />
          </div>
        )}
      </Panel>

      <p className="flex items-center gap-1 text-[10px] text-ink-faint">
        <ExternalLink className="h-3 w-3" aria-hidden="true" />
        Read-only surface. Indicators and lookups are created by the Threat Intelligence
        Agent; this API never writes.
      </p>
    </div>
  )
}
