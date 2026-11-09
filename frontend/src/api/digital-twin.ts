import { api } from './client'
import type { DigitalTwinHealth } from '../types/api'

/**
 * V3.26 Digital Twin.
 *
 * The backend currently exposes only a health probe
 * (`GET /api/digital-twin/health`). The functional twin API — snapshots,
 * simulation, twin state — is not implemented on the server yet, so this client
 * types only what actually exists rather than inventing a contract the backend
 * cannot satisfy. The Digital Twin page is therefore an honest status surface,
 * not a fabricated twin.
 */
export const digitalTwinApi = {
  health: (): Promise<DigitalTwinHealth> =>
    api.get<DigitalTwinHealth>('/api/digital-twin/health'),
}
