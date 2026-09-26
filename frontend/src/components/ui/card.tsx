import type { HTMLAttributes } from 'react'
import { cn } from '../../lib/utils'

export function Card({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('rounded-lg border border-edge bg-surface-1', className)}
      {...props}
    />
  )
}

interface PanelProps extends Omit<HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: string
  subtitle?: string
  action?: React.ReactNode
  padded?: boolean
}

export function Panel({
  title,
  subtitle,
  action,
  className,
  padded = true,
  children,
  ...props
}: PanelProps) {
  return (
    <Card className={cn('overflow-hidden', className)} {...props}>
      {(title || action) && (
        <div className="flex items-start justify-between gap-3 border-b border-edge-soft px-4 py-3">
          <div className="min-w-0">
            {title && (
              <div className="truncate text-xs font-semibold uppercase tracking-wider text-ink-dim">
                {title}
              </div>
            )}
            {subtitle && (
              <div className="mt-0.5 truncate text-[11px] text-ink-faint">
                {subtitle}
              </div>
            )}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </div>
      )}
      <div className={padded ? 'p-4' : ''}>{children}</div>
    </Card>
  )
}

export function PageHeader({
  title,
  description,
  children,
}: {
  title: React.ReactNode
  description?: string
  children?: React.ReactNode
}) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-base font-semibold text-ink">{title}</h1>
        {description && (
          <p className="mt-0.5 max-w-3xl text-xs text-ink-dim">{description}</p>
        )}
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  )
}

export function Stat({ label, value, tone }: { label: string; value: React.ReactNode; tone?: string }) {
  return (
    <Card className="px-4 py-3">
      <div className="text-[11px] font-medium uppercase tracking-wider text-ink-dim">
        {label}
      </div>
      <div className={cn('mt-1 font-mono text-xl leading-none', tone)}>{value}</div>
    </Card>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        'animate-pulse rounded bg-surface-3',
        className ?? 'h-8 w-full',
      )}
    />
  )
}

export function Separator({ className }: { className?: string }) {
  return <div className={cn('h-px w-full bg-edge-soft', className)} />
}