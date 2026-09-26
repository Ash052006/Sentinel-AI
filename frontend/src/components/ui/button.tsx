import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import type { ButtonHTMLAttributes } from 'react'
import { cn } from '../../lib/utils'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        default:
          'bg-accent text-surface-0 hover:bg-accent/90 shadow-sm',
        outline:
          'border border-edge bg-surface-1 text-ink hover:bg-surface-2',
        ghost: 'text-ink-dim hover:bg-surface-2 hover:text-ink',
        danger:
          'border border-critical/40 bg-critical/10 text-critical hover:bg-critical/20',
      },
      size: {
        default: 'h-8 px-3 text-xs',
        sm: 'h-7 px-2.5 text-xs',
        icon: 'h-8 w-8 p-0',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  },
)

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants> & { asChild?: boolean }

export function Button({
  className,
  variant,
  size,
  asChild = false,
  type = 'button',
  ...props
}: ButtonProps) {
  const Comp = asChild ? Slot : 'button'
  return (
    <Comp
      className={cn(buttonVariants({ variant, size, className }))}
      type={asChild ? undefined : type}
      {...props}
    />
  )
}