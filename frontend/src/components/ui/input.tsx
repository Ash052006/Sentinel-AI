import type {
  InputHTMLAttributes,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from 'react'
import { cn } from '../../lib/utils'

type InputProps = InputHTMLAttributes<HTMLInputElement>

export function Input({ className, ...props }: InputProps) {
  return (
    <input
      className={cn(
        'h-8 w-full rounded-md border border-edge bg-surface-2 px-2.5 text-xs text-ink placeholder:text-ink-faint focus:outline-none focus:ring-1 focus:ring-accent disabled:pointer-events-none disabled:opacity-50',
        className,
      )}
      {...props}
    />
  )
}

type SelectProps = SelectHTMLAttributes<HTMLSelectElement>

export function Select({ className, ...props }: SelectProps) {
  return (
    <select
      className={cn(
        'h-8 rounded-md border border-edge bg-surface-2 px-2 text-xs text-ink focus:outline-none focus:ring-1 focus:ring-accent disabled:pointer-events-none disabled:opacity-50',
        className,
      )}
      {...props}
    />
  )
}

type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement>

export function Textarea({ className, ...props }: TextareaProps) {
  return (
    <textarea
      className={cn(
        'w-full rounded-md border border-edge bg-surface-2 px-2.5 py-2 text-xs text-ink placeholder:text-ink-faint focus:outline-none focus:ring-1 focus:ring-accent disabled:pointer-events-none disabled:opacity-50',
        className,
      )}
      {...props}
    />
  )
}