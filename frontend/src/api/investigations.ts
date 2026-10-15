import { api } from './client'
import type { ExplainabilityResult } from '../types/api'

/**
 * Evidence-grounded investigation explanations.
 *
 * `explain` returns only the deterministic, source-backed dimensions (no AI
 * provider is contacted). `explainWithAi` additionally asks the configured
 * reasoning provider for a narrative; a provider failure degrades to status
 * `ai_unavailable` with the deterministic dimensions intact rather than erroring.
 */
export const investigationsApi = {
  explain: (correlationId: string): Promise<ExplainabilityResult> =>
    api.get<ExplainabilityResult>(
      `/api/investigations/${encodeURIComponent(correlationId)}/explanation`,
    ),

  explainWithAi: (
    correlationId: string,
    useAi = true,
  ): Promise<ExplainabilityResult> =>
    api.post<ExplainabilityResult>(
      `/api/investigations/${encodeURIComponent(correlationId)}/explanation`,
      { use_ai: useAi },
    ),
}
