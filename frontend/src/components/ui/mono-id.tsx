import { CopyButton } from './copy-button'
import { shortId } from '../../lib/formats'

export function MonoId({
  id,
  copy = true,
}: {
  id: string | null | undefined
  copy?: boolean
}) {
  if (!id) return <span className="font-mono text-[11px] text-ink-faint">—</span>
  return (
    <span className="inline-flex items-center gap-1 font-mono text-[11px] text-ink-dim">
      <span data-testid="mono-id">{shortId(id)}</span>
      {copy && <CopyButton value={id} label={`Copy ${id}`} />}
    </span>
  )
}