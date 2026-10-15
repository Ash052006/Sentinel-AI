import { api } from './client'
import type { PredictionResult } from '../types/api'

/**
 * V3.24 attack prediction engine.
 *
 * Three properties shape how the UI must treat these calls:
 *
 * - **The client cannot define a prediction.** There is no request body: a
 *   client may ask for a prediction but cannot submit a stage, a technique or a
 *   confidence and have the server believe it. Every such value is derived
 *   server-side from persisted evidence, the V3.22 graph and the V3.23 debate.
 * - **Idempotent.** The session id is a deterministic uuid5 over
 *   `(correlation_id, graph_snapshot_digest, debate_id,
 *   prediction_configuration_digest)`, so re-posting over unchanged inputs
 *   returns the stored prediction rather than producing a second one. The UI
 *   presents this as "run or return" and never implies fresh analysis
 *   happened.
 * - **No silent fallback.** When no input source is available the backend still
 *   answers 200 with `INSUFFICIENT_EVIDENCE` and zero predictions — declining
 *   to speculate is a *successful* outcome, not an error, and must never be
 *   rendered as a failure. Genuine failures arrive as governed 404/422/503
 *   bodies carrying a `failure_code`.
 */
export const predictionsApi = {
  run: (correlationId: string): Promise<PredictionResult> =>
    api.post<PredictionResult>(
      `/api/attack-predictions/${encodeURIComponent(correlationId)}`,
      undefined,
    ),

  get: (predictionId: string): Promise<PredictionResult> =>
    api.get<PredictionResult>(
      `/api/attack-predictions/${encodeURIComponent(predictionId)}`,
    ),
}