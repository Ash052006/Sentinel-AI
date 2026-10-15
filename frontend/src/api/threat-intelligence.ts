import { api } from './client'
import type {
  ThreatIntelIndicatorDetail,
  ThreatIntelIndicatorEvents,
  ThreatIntelIndicatorPage,
  ThreatIntelIndicatorRecord,
} from '../types/api'

/**
 * Threat Intelligence read client.
 *
 * Read-only by contract: there is no `create`, `update`, or `delete` here,
 * mirroring the backend, which exposes only `GET` routes.  Indicators and
 * lookups are created by the Threat Intelligence Agent, never over HTTP.
 */
export const threatIntelligenceApi = {
  listIndicators: (
    page = 1,
    pageSize = 50,
    indicatorType?: string,
    q?: string,
  ): Promise<ThreatIntelIndicatorPage> =>
    api.get<ThreatIntelIndicatorPage>('/api/threat-intelligence/indicators', {
      page,
      page_size: pageSize,
      indicator_type: indicatorType,
      q,
    }),

  indicator: (indicatorId: string): Promise<ThreatIntelIndicatorDetail> =>
    api.get<ThreatIntelIndicatorDetail>(
      `/api/threat-intelligence/indicators/${encodeURIComponent(indicatorId)}`,
    ),

  events: (indicatorId: string): Promise<ThreatIntelIndicatorEvents> =>
    api.get<ThreatIntelIndicatorEvents>(
      `/api/threat-intelligence/indicators/${encodeURIComponent(indicatorId)}/events`,
    ),
}

export type { ThreatIntelIndicatorRecord }
