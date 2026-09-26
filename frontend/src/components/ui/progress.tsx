import { cn } from '../../lib/utils'
import { percent } from '../../lib/formats'

export function ConfidenceBar({
  value,
  label = 'confidence',
}: {
  value: number | null | undefined
  label?: string
}) {
  if (value === null || value === undefined) {
    return <span className="font-mono text-[11px] text-ink-faint">—</span>
  }
  const tone =
    value >= 0.7 ? 'bg-low' : value >= 0.4 ? 'bg-medium' : 'bg-high'
  return (
    <span className="inline-flex items-center gap-2" role="img" aria-label={`${label}: ${percent(value)}`}>
      <span className="h-1.5 w-16 overflow-hidden rounded-full bg-surface-3">
        <span
          className={cn('block h-full rounded-full', tone)}
          style={{ width: `${value * 100}%` }}
        />
      </span>
      <span className="font-mono text-[11px] text-ink-dim">{percent(value, 0)}</span>
    </span>
  )
}

export function ScoreBar({
  value,
  label = 'risk score',
}: {
  value: number
  label?: string
}) {
  const tone = value >= 0.75 ? 'bg-critical' : value >= 0.5 ? 'bg-high' : value >= 0.25 ? 'bg-medium' : 'bg-low'
  return (
    <span className="inline-flex items-center gap-2" role="img" aria-label={`${label}: ${percent(value)}`}>
      <span className="h-1.5 w-16 overflow-hidden rounded-full bg-surface-3">
        <span
          className={cn('block h-full rounded-full', tone)}
          style={{ width: `${value * 100}%` }}
        />
      </span>
      <span className="font-mono text-[11px] text-ink-dim">
        {value.toFixed(2)}
      </span>
    </span>
  )
}