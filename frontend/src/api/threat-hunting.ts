import { api } from './client'
import type {
  HuntType,
  Page,
  ThreatHuntCreateRequest,
  ThreatHuntEvidenceRecord,
  ThreatHuntFindingRecord,
  ThreatHuntRecord,
  ThreatHuntStatus,
  ThreatHuntSummary,
  ThreatHuntTimelineItemRecord,
} from '../types/api'

export const threatHuntingApi = {
  hunts: (
    page = 1,
    pageSize = 50,
    status?: ThreatHuntStatus,
    huntType?: HuntType,
  ): Promise<Page<ThreatHuntSummary>> =>
    api.get<Page<ThreatHuntSummary>>('/api/threat-hunts', {
      page,
      page_size: pageSize,
      status,
      hunt_type: huntType,
    }),

  hunt: (huntId: string): Promise<ThreatHuntRecord> =>
    api.get<ThreatHuntRecord>(
      `/api/threat-hunts/${encodeURIComponent(huntId)}`,
    ),

  create: (body: ThreatHuntCreateRequest): Promise<ThreatHuntRecord> =>
    api.post<ThreatHuntRecord>('/api/threat-hunts', body),

  run: (huntId: string): Promise<ThreatHuntRecord> =>
    api.post<ThreatHuntRecord>(
      `/api/threat-hunts/${encodeURIComponent(huntId)}/run`,
      {},
    ),

  cancel: (huntId: string): Promise<ThreatHuntRecord> =>
    api.post<ThreatHuntRecord>(
      `/api/threat-hunts/${encodeURIComponent(huntId)}/cancel`,
      {},
    ),

  evidence: (
    huntId: string,
    page = 1,
    pageSize = 50,
  ): Promise<Page<ThreatHuntEvidenceRecord>> =>
    api.get<Page<ThreatHuntEvidenceRecord>>(
      `/api/threat-hunts/${encodeURIComponent(huntId)}/evidence`,
      { page, page_size: pageSize },
    ),

  findings: (
    huntId: string,
    page = 1,
    pageSize = 50,
  ): Promise<Page<ThreatHuntFindingRecord>> =>
    api.get<Page<ThreatHuntFindingRecord>>(
      `/api/threat-hunts/${encodeURIComponent(huntId)}/findings`,
      { page, page_size: pageSize },
    ),

  timeline: (
    huntId: string,
    page = 1,
    pageSize = 50,
  ): Promise<Page<ThreatHuntTimelineItemRecord>> =>
    api.get<Page<ThreatHuntTimelineItemRecord>>(
      `/api/threat-hunts/${encodeURIComponent(huntId)}/timeline`,
      { page, page_size: pageSize },
    ),
}