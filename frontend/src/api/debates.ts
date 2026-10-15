import { api } from './client'
import type { DebateSession } from '../types/api'

/**
 * V3.23 multi-agent debate engine.
 *
 * Two properties shape how the UI must treat these calls:
 *
 * - **Idempotent.** The session id is a deterministic uuid5 over
 *   `(correlation_id, graph_snapshot_digest, configuration_digest)`, so
 *   re-posting over an unchanged graph returns the stored debate rather than
 *   starting a second one. The UI therefore presents the action as "run or
 *   return", not "retry", and never implies a fresh run happened.
 * - **No silent fallback.** When the model provider is unavailable or returns
 *   output that fails structural validation, the backend answers with a
 *   governed failure (502/503/504) rather than a fabricated consensus. The UI
 *   must surface that as a failure, never render it as a result.
 */
export const debatesApi = {
  run: (correlationId: string): Promise<DebateSession> =>
    api.post<DebateSession>(
      `/api/debates/${encodeURIComponent(correlationId)}`,
      undefined,
    ),

  get: (debateId: string): Promise<DebateSession> =>
    api.get<DebateSession>(`/api/debates/${encodeURIComponent(debateId)}`),
}