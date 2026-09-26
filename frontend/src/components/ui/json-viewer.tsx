export function JsonViewer({ value }: { value: Record<string, unknown> | unknown[] }) {
  let text: string
  try {
    text = JSON.stringify(value, null, 2)
  } catch {
    text = String(value)
  }
  if (Object.keys(value as object).length === 0) {
    return <span className="text-[11px] text-ink-faint">—</span>
  }
  return (
    <pre className="max-h-64 overflow-auto rounded-md border border-edge-soft bg-surface-0 p-3 font-mono text-[11px] leading-relaxed text-ink-dim">
      {text}
    </pre>
  )
}

export function EmptyJson() {
  return <span className="text-[11px] text-ink-faint">—</span>
}