export function JsonViewer({
  value,
}: {
  // Optional fields must be renderable: an absent value is "not recorded",
  // not a reason to crash the page that displays it.
  value?: Record<string, unknown> | unknown[] | null
}) {
  // A value that is absent, null, or an empty object/array is shown with the
  // same placeholder: there is nothing to display, and crashing here would
  // blank out an entire detail page.
  if (value === null || value === undefined || Object.keys(value).length === 0) {
    return <span className="text-[11px] text-ink-faint">—</span>
  }
  let text: string
  try {
    text = JSON.stringify(value, null, 2)
  } catch {
    text = String(value)
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