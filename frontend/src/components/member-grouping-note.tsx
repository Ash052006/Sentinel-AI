import { Info } from 'lucide-react'
import { MonoId } from './ui/mono-id'

/**
 * State the event/detection boundary of a correlation explicitly.
 *
 * The correlation engine groups detections by *event ID*, so a legitimate
 * correlation can contain one event ID and seven detection IDs. Rendered
 * naively, a members list reads as seven independent events. Shared by the
 * correlation and incident detail pages so the two cannot drift apart.
 */
export function MemberGroupingNote({
  members,
  className = '',
}: {
  members: Array<{ event_id: string | null }>
  className?: string
}) {
  const eventIds = Array.from(
    new Set(members.map((member) => member.event_id).filter((id): id is string => !!id)),
  )

  if (eventIds.length === 0) return null

  const shell = `flex items-start gap-2 bg-surface-2 px-4 py-2.5 text-xs text-ink-dim ${className}`

  if (eventIds.length === 1) {
    return (
      <div data-testid="member-grouping-note" className={shell}>
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <p>
          All <span className="font-semibold text-ink">{members.length}</span> members reference the
          same single event <MonoId id={eventIds[0]} />. The correlation engine groups detections by
          event ID, so these are {members.length} distinct detections of one event, not{' '}
          {members.length} separate events.
        </p>
      </div>
    )
  }

  return (
    <div data-testid="member-grouping-note" className={shell}>
      <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <p>
        This correlation spans{' '}
        <span className="font-semibold text-ink">{eventIds.length}</span> distinct events across{' '}
        {members.length} member detections. Correlation membership is grouped by event ID.
      </p>
    </div>
  )
}