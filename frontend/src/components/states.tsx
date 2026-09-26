import { AlertTriangle, Inbox, FlaskConical } from 'lucide-react'
import { Button } from './ui/button'
import { Skeleton } from './ui/card'

export function EmptyState({
  title = 'No data',
  body = 'This view has no matching records to display.',
  action,
}: {
  title?: string
  body?: string
  action?: React.ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center">
      <Inbox className="h-6 w-6 text-ink-faint" aria-hidden="true" />
      <div className="text-sm font-medium text-ink-dim">{title}</div>
      <div className="max-w-sm text-[11px] text-ink-faint">{body}</div>
      {action}
    </div>
  )
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string
  onRetry?: () => void
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center">
      <AlertTriangle
        className="h-6 w-6 text-high"
        aria-hidden="true"
      />
      <div className="text-sm font-medium text-ink-dim">Unable to load data</div>
      <div className="max-w-md text-[11px] text-ink-faint">{message}</div>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry} className="mt-1">
          Retry
        </Button>
      )}
    </div>
  )
}

export function LoadingRows({ rows = 6 }: { rows?: number }) {
  return (
    <div className="space-y-2 p-4" data-testid="loading-rows">
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} className="h-5 w-full" />
      ))}
    </div>
  )
}

/**
 * Honest "not available" state — used on views where the backend has no
 * persistence/query layer in V1. Never fabricates placeholder metrics.
 */
export function NotAvailable({
  title = 'Not available',
  body,
  simulation = false,
}: {
  title?: string
  body: string
  simulation?: boolean
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      {simulation ? (
        <FlaskConical className="h-7 w-7 text-accent" aria-hidden="true" />
      ) : (
        <Inbox className="h-7 w-7 text-ink-faint" aria-hidden="true" />
      )}
      <div
        data-testid={simulation ? 'simulation-only' : 'not-available'}
        className="text-sm font-semibold text-ink"
      >
        {simulation ? 'Simulation only' : title}
      </div>
      <div className="max-w-xl text-[11px] leading-relaxed text-ink-faint">
        {body}
      </div>
    </div>
  )
}