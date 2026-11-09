import { api } from './client'
import type {
  PlaybookListResult,
  PlaybookResult,
  PlaybookValidationResult,
} from '../types/api'

/**
 * V3.25 AI Playbook Generation engine.
 *
 * Four properties shape how the UI must treat these calls:
 *
 * - **The client cannot define a playbook.** There is no request body: a client
 *   may ask for a proposal but cannot submit an action, a target, a priority or
 *   an approval state and have the server believe it. Every such value is
 *   derived server-side from persisted evidence, the V3.22 graph, the V3.23
 *   debate and the V3.24 prediction.
 * - **Generating is not approving, and proposing is not executing.** No route on
 *   this surface approves or executes. The lifecycles it can return are
 *   `proposed` and `approval_required`, so the UI never offers an "execute"
 *   control for a proposal.
 * - **Idempotent.** The playbook id is derived from immutable inputs, so
 *   re-posting over an unchanged correlation returns the stored proposal rather
 *   than producing a second one. The UI therefore presents the action as "run or
 *   return", never "retry".
 * - **A failure never becomes a playbook.** Governed 404/422/503 failures carry a
 *   `failure_code`, and the UI surfaces them as failures rather than rendering
 *   an empty plan.
 */
export const playbooksApi = {
  generate: (correlationId: string): Promise<PlaybookResult> =>
    api.post<PlaybookResult>(
      `/api/playbooks/${encodeURIComponent(correlationId)}`,
      undefined,
    ),

  get: (playbookId: string): Promise<PlaybookResult> =>
    api.get<PlaybookResult>(`/api/playbooks/${encodeURIComponent(playbookId)}`),

  listForCorrelation: (correlationId: string): Promise<PlaybookListResult> =>
    api.get<PlaybookListResult>(
      `/api/playbooks/correlation/${encodeURIComponent(correlationId)}`,
    ),

  validate: (playbookId: string): Promise<PlaybookValidationResult> =>
    api.post<PlaybookValidationResult>(
      `/api/playbooks/${encodeURIComponent(playbookId)}/validate`,
      undefined,
    ),
}
