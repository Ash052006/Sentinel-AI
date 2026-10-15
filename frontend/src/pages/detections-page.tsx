import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { detectionsApi } from '../api/detections'
import { PageHeader, Panel } from '../components/ui/card'
import { EmptyState, ErrorState, LoadingRows } from '../components/states'
import { ProvenanceBadge, RuleTypeBadge, SeverityBadge } from '../components/badges'
import { MonoId } from '../components/ui/mono-id'
import { ConfidenceBar } from '../components/ui/progress'
import { Select } from '../components/ui/input'
import { formatTimestamp } from '../lib/formats'
import { MonoCell, Td, Th, TRow, Table } from '../components/ui/table'
import { DetectionDetail } from '../components/detection-detail'
import type { DetectionSeverity, RuleType } from '../types/api'

export function DetectionsPage() {
  const [limit, setLimit] = useState(100)
  const [severity, setSeverity] = useState<'all' | DetectionSeverity>('all')
  const [ruleType, setRuleType] = useState<'all' | RuleType>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const detections = useQuery({
    queryKey: ['detections', 'recent', limit],
    queryFn: () => detectionsApi.recent(limit),
  })

  const selected = useQuery({
    queryKey: ['detections', 'get', selectedId],
    queryFn: () => detectionsApi.get(selectedId as string),
    enabled: selectedId !== null,
    retry: false,
  })

  const rows = useMemo(() => {
    const items = detections.data ?? []
    return items.filter(
      (item) =>
        (severity === 'all' || item.severity === severity) &&
        (ruleType === 'all' || item.rule_type === ruleType),
    )
  }, [detections.data, severity, ruleType])

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Detections"
        description="Persisted detection matches from the Sigma/YARA rule engines (bounded recent feed). Only matching, non-failure results are listed here."
      >
        <Select
          aria-label="Filter by severity"
          value={severity}
          onChange={(event) => setSeverity(event.target.value as typeof severity)}
        >
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </Select>
        <Select
          aria-label="Filter by rule type"
          value={ruleType}
          onChange={(event) => setRuleType(event.target.value as typeof ruleType)}
        >
          <option value="all">All engines</option>
          <option value="sigma">Sigma</option>
          <option value="yara">Yara</option>
        </Select>
        <Select
          aria-label="Feed size"
          value={String(limit)}
          onChange={(event) => setLimit(Number(event.target.value))}
        >
          {[25, 50, 100, 200].map((size) => (
            <option key={size} value={size}>
              {size} shown
            </option>
          ))}
        </Select>
        {selectedId && (
          <button
            type="button"
            onClick={() => setSelectedId(null)}
            className="text-[11px] text-accent hover:underline"
          >
            close detail
          </button>
        )}
      </PageHeader>

      {selectedId && (
        <Panel
          title="Detection detail"
          subtitle="Served by GET /api/detections/{detection_id}"
        >
          {selected.isLoading ? (
            <LoadingRows rows={3} />
          ) : selected.isError ? (
            <ErrorState
              message={String(selected.error)}
              onRetry={() => selected.refetch()}
            />
          ) : selected.data ? (
            <DetectionDetail detection={selected.data} />
          ) : (
            <EmptyState title="Detection not found" />
          )}
        </Panel>
      )}

      <Panel padded={false}>
        {detections.isLoading ? (
          <LoadingRows rows={8} />
        ) : detections.isError ? (
          <ErrorState message={String(detections.error)} onRetry={() => detections.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            title="No detections"
            body="No persisted detections matched the selected filters within the bounded feed."
          />
        ) : (
          <Table>
            <thead>
              <tr className="border-b border-edge">
                <Th>Severity</Th>
                <Th>Rule</Th>
                <Th>Engine</Th>
                <Th>Confidence</Th>
                <Th>Provenance</Th>
                <Th>Detected at</Th>
                <Th>Event</Th>
                <Th>Detection id</Th>
                <Th />
              </tr>
            </thead>
            <tbody className="divide-y divide-edge-soft">
              {rows.map((item) => (
                <TRow key={item.id}>
                  <Td>
                    <SeverityBadge severity={item.severity} />
                  </Td>
                  <Td>
                    <span data-mono className="text-[11px] text-ink">{item.rule_id}</span>
                  </Td>
                  <Td>
                    <RuleTypeBadge ruleType={item.rule_type} />
                  </Td>
                  <Td>
                    <ConfidenceBar value={item.confidence} />
                  </Td>
                  <Td>
                    <ProvenanceBadge provenance={item.provenance} />
                  </Td>
                  <Td className="text-xs text-ink-dim">{formatTimestamp(item.detected_at)}</Td>
                  <MonoCell>
                    <MonoId id={item.event_id} />
                  </MonoCell>
                  <MonoCell>
                    <MonoId id={item.detection_id} />
                  </MonoCell>
                  <Td>
                    <button
                      type="button"
                      onClick={() => setSelectedId(item.detection_id)}
                      className="cursor-pointer select-none text-[11px] text-accent hover:underline"
                    >
                      detail
                    </button>
                  </Td>
                </TRow>
              ))}
            </tbody>
          </Table>
        )}
      </Panel>
    </div>
  )
}