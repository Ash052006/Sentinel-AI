import { api } from './client'
import type {
  ManualLookupRequest,
  ManualLookupResponse,
  ThreatIntelIndicatorDetail,
  ThreatIntelIndicatorEvents,
  ThreatIntelIndicatorPage,
  ThreatIntelIndicatorRecord,
} from '../types/api'

/**
 * Threat Intelligence client.
 *
 * Exposes indicator query endpoints and manual indicator lookup.
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

  manualLookup: (payload: ManualLookupRequest): Promise<ManualLookupResponse> =>
    api.post<ManualLookupResponse>('/api/v1/threat-intelligence/lookup', payload),
}

export type { ThreatIntelIndicatorRecord }
