import type { ThHTMLAttributes, TdHTMLAttributes } from 'react'
import { cn } from '../../lib/utils'

export function Table({
  className,
  ...props
}: React.TableHTMLAttributes<HTMLTableElement>) {
  return (
    <div className="w-full overflow-x-auto">
      <table
        className={cn('w-full border-collapse text-xs', className)}
        {...props}
      />
    </div>
  )
}

export function THead({
  className,
  ...props
}: React.HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <thead className={cn('bg-surface-2', className)}>
      <tr className="border-b border-edge">
        {props.children}
      </tr>
    </thead>
  )
}

export function TBody({
  className,
  ...props
}: React.HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody className={cn('divide-y divide-edge-soft', className)} {...props} />
}

export function TRow({
  className,
  ...props
}: React.HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr
      className={cn(
        'border-b border-edge-soft last:border-0 hover:bg-surface-2/60',
        className,
      )}
      {...props}
    />
  )
}

export function Th({
  className,
  ...props
}: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      className={cn(
        'px-3 py-2 text-left align-middle text-[11px] font-medium uppercase tracking-wider text-ink-dim',
        className,
      )}
      {...props}
    />
  )
}

export function Td({
  className,
  ...props
}: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td
      className={cn('px-3 py-2 align-middle text-xs text-ink', className)}
      {...props}
    />
  )
}

export function MonoCell({
  className,
  ...props
}: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td
      className={cn(
        'px-3 py-2 align-middle font-mono text-[11px] text-ink-dim',
        className,
      )}
      {...props}
    />
  )
}