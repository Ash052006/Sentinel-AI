import { cva, type VariantProps } from 'class-variance-authority'
import type { HTMLAttributes } from 'react'
import { cn } from '../../lib/utils'
import type { Tone } from '../../lib/labels'

const badgeToneMap: Record<Tone, string> = {
  neutral: 'border-edge bg-surface-2 text-ink',
  muted: 'border-edge-soft bg-surface-1 text-ink-dim',
  accent: 'border-accent/40 bg-accent/10 text-accent',
  critical: 'border-critical/40 bg-critical/10 text-critical',
  high: 'border-high/40 bg-high/10 text-high',
  medium: 'border-medium/40 bg-medium/10 text-medium',
  low: 'border-low/40 bg-low/10 text-low',
}

const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded border px-1.5 py-px font-mono text-[11px] font-medium leading-4 whitespace-nowrap',
  {
    variants: {
      tone: badgeToneMap,
    },
    defaultVariants: {
      tone: 'neutral',
    },
  },
)

type BadgeProps = HTMLAttributes<HTMLSpanElement> &
  VariantProps<typeof badgeVariants>

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />
}