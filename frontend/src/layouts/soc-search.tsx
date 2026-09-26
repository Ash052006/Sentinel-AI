import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Loader2, Search, X } from 'lucide-react'
import { socApi } from '../api/soc'
import type { SOCQueryResponse } from '../types/api'
import { cn } from '../lib/utils'

interface ItemView {
  id: string
  label: string
  meta: string
}

function describeItem(resource: SOCQueryResponse['metadata']['resource'], row: Record<string, unknown>): ItemView {
  switch (resource) {
    case 'detections':
      return {
        id: String(row.detection_id ?? row.id ?? ''),
        label: String(row.rule_id ?? ''),
        meta: String(row.severity ?? ''),
      }
    case 'correlations':
      return {
        id: String(row.correlation_id ?? row.id ?? ''),
        label: 'correlation',
        meta: String(row.status ?? ''),
      }
    case 'risk_assessments':
      return {
        id: String(row.risk_assessment_id ?? row.id ?? ''),
        label: `score ${row.score}`,
        meta: String(row.level ?? ''),
      }
    case 'incident_memories':
      return {
        id: String(row.memory_id ?? row.id ?? ''),
        label: String(row.title ?? ''),
        meta: String(row.memory_type ?? ''),
      }
    default:
      return { id: String(row.id ?? ''), label: '', meta: '' }
  }
}

export function SocSearch() {
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<'idle' | 'loading' | 'error' | 'done'>('idle')
  const [result, setResult] = useState<SOCQueryResponse | null>(null)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(false)

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    const q = query.trim()
    if (!q) return
    setStatus('loading')
    setError('')
    setOpen(true)
    try {
      const response = await socApi.query(q)
      setResult(response)
      setStatus('done')
    } catch (err) {
      setResult(null)
      setStatus('error')
      setError(err instanceof Error ? err.message : 'The SOC querier could not answer.')
    }
  }

  function close(): void {
    setOpen(false)
  }

  return (
    <div className="relative min-w-0 flex-1 max-w-xl">
      <form onSubmit={(event) => void submit(event)} className="relative">
        <Search
          className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-faint"
          aria-hidden="true"
        />
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Escape') close()
          }}
          placeholder="Search incidents, detections, IPs, domains, hashes…"
          aria-label="SOC search"
          data-testid="soc-search-input"
          className="h-8 w-full rounded-md border border-edge bg-surface-0 pl-8 pr-3 text-xs text-ink placeholder:text-ink-faint focus:outline-none focus:ring-1 focus:ring-accent"
        />
      </form>

      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={close} aria-hidden="true" />
          <div
            className="absolute left-0 right-0 top-full z-20 mt-1 overflow-hidden rounded-md border border-edge bg-surface-2 shadow-lg"
            data-testid="soc-search-panel"
          >
            <div className="flex items-center justify-between gap-3 border-b border-edge-soft bg-surface-1 px-3 py-2">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-dim">
                SOC querier
              </span>
              <button
                type="button"
                onClick={close}
                className="rounded p-0.5 text-ink-faint hover:text-ink"
                aria-label="Close search results"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>

            {status === 'loading' ? (
              <div className="flex items-center gap-2 px-4 py-4 text-[11px] text-ink-faint">
                <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" aria-hidden="true" />
                Interpreting intent…
              </div>
            ) : status === 'error' ? (
              <div className="px-4 py-4 text-[11px] text-critical">{error}</div>
            ) : !result ? (
              <div className="px-4 py-4 text-[11px] text-ink-faint">
                Ask something like “show high risk incidents” or “recent detections”.
              </div>
            ) : result.found === false ? (
              <div className="px-4 py-4 text-[11px] text-ink-faint">
                {result.note || 'The SOC querier found nothing to prepare. It is read-only and never fabricates data.'}
              </div>
            ) : (
              <div className="max-h-64 overflow-y-auto">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-edge-soft px-4 py-2 text-[10px] font-mono text-ink-faint">
                  <span>resource · {result.metadata.resource}</span>
                  <span>op · {result.metadata.operation}</span>
                  <span>mode · {result.metadata.mode}</span>
                  <span className="text-ink-dim">
                    {result.count} of {result.total ?? '—'}
                  </span>
                </div>
                <ul className="divide-y divide-edge-soft">
                  {result.items.length === 0 ? (
                    <li className="px-4 py-3 text-[11px] text-ink-faint">No matching records.</li>
                  ) : (
                    result.items.slice(0, 6).map((row, index) => {
                      const item = describeItem(result.metadata.resource, row)
                      return (
                        <li key={`${item.id}-${index}`} className="flex items-center gap-2 px-4 py-1.5">
                          <span data-mono className={cn('truncate text-[11px]', item.id ? 'text-ink' : 'text-ink-faint')}>
                            {item.id || '—'}
                          </span>
                          {item.label && (
                            <span className="truncate text-[11px] text-ink-dim">{item.label}</span>
                          )}
                          {item.meta && (
                            <span className="ml-auto shrink-0 rounded border border-edge px-1 font-mono text-[10px] uppercase text-ink-faint">
                              {item.meta}
                            </span>
                          )}
                        </li>
                      )
                    })
                  )}
                </ul>
              </div>
            )}

            <div className="flex items-center justify-between gap-3 border-t border-edge-soft bg-surface-1 px-3 py-2">
              <span className="text-[10px] text-ink-faint">read-only · routed by POST /api/soc/query</span>
              {query.trim().length > 0 && (
                <Link
                  to={`/search?q=${encodeURIComponent(query.trim())}`}
                  onClick={close}
                  className="text-[11px] font-medium text-accent hover:underline"
                >
                  Open full results →
                </Link>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}