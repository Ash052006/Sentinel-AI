import { api } from './client'
import type { AttackPathResponse } from '../types/api'

/**
 * V2.21 attack-path visualization — read-only graph projection over
 * already-persisted records for one correlation. Never mutates.
 */
export const attackPathsApi = {
  graph: (correlationId: string): Promise<AttackPathResponse> =>
    api.get<AttackPathResponse>(
      `/api/attack-paths/${encodeURIComponent(correlationId)}`,
    ),
}