import { useState } from 'react'
import { ChevronRight } from 'lucide-react'
import { cn } from '../lib/utils'

/**
 * Dense, expandable renderer for arbitrary backend JSON.
 *
 * Used wherever a response contains nested structures the console must show
 * readably instead of dumping as a raw blob. Rendering is generic: keys come
 * from the payload, never from a hardcoded field list, so a schema the
 * backend adds later appears without a frontend change.
 */

interface TreeEntry {
  key: string
  value: unknown
}

function entriesOf(value: unknown): TreeEntry[] {
  if (Array.isArray(value)) {
    return value.map((item, index) => ({ key: String(index), value: item }))
  }
  if (value && typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).map(([key, item]) => ({
      key,
      value: item,
    }))
  }
  return []
}

function isContainer(value: unknown): boolean {
  return Array.isArray(value) || (typeof value === 'object' && value !== null)
}

function isEmptyContainer(value: unknown): boolean {
  return isContainer(value) && entriesOf(value).length === 0
}

function typeName(value: unknown): string {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  if (typeof value === 'object') return 'object'
  return typeof value
}

function scalarText(value: unknown): string {
  if (value === null) return 'null'
  if (value === undefined) return '—'
  if (typeof value === 'string') return value
  return String(value)
}

export function DataTree({ value }: { value: unknown }) {
  const entries = entriesOf(value)
  if (entries.length === 0) {
    return <span className="text-[11px] text-ink-faint">—</span>
  }
  return (
    <div className="rounded border border-edge-soft bg-surface-0/60">
      <TreeRows entries={entries} depth={0} />
    </div>
  )
}

function TreeRows({ entries, depth }: { entries: TreeEntry[]; depth: number }) {
  return (
    <div className={cn(depth > 0 && 'border-l border-edge-soft pl-2')}>
      {entries.map((entry) => (
        <TreeRow key={entry.key} entry={entry} depth={depth} />
      ))}
    </div>
  )
}

function TreeRow({ entry, depth }: { entry: TreeEntry; depth: number }) {
  const [open, setOpen] = useState(false)
  const { key, value } = entry
  const container = isContainer(value)
  const empty = isEmptyContainer(value)
  const children = container ? entriesOf(value) : []

  return (
    <div className="border-b border-edge-soft/60 last:border-b-0" data-field={key}>
      <div className="grid grid-cols-[minmax(84px,28%)_minmax(0,1fr)] items-start gap-x-3 py-1">
        <div
          className="truncate pt-px font-mono text-[10px] text-ink-faint"
          title={key}
        >
          {key}
        </div>

        <div className="min-w-0">
          {!container ? (
            <span
              className="break-words font-mono text-[11px] text-ink"
              data-mono="value"
            >
              {scalarText(value)}
            </span>
          ) : empty ? (
            <span className="font-mono text-[11px] text-ink-faint">
              {Array.isArray(value) ? '[]' : '{}'}
            </span>
          ) : (
            <button
              type="button"
              onClick={() => setOpen((prev) => !prev)}
              aria-expanded={open}
              aria-label={`${open ? 'Collapse' : 'Expand'} ${key}`}
              className="flex w-full items-start gap-1 text-left font-mono text-[11px] text-accent hover:underline"
            >
              <ChevronRight
                className={cn(
                  'mt-px h-3 w-3 shrink-0 transition-transform',
                  open && 'rotate-90',
                )}
                aria-hidden="true"
              />
              <span>
                {Array.isArray(value)
                  ? `[${children.length}]`
                  : `{${children.length}}`}{' '}
                <span className="text-ink-faint">{typeName(value)}</span>
              </span>
            </button>
          )}
        </div>
      </div>

      {container && !empty && open && (
        <TreeRows entries={children} depth={depth + 1} />
      )}
    </div>
  )
}
