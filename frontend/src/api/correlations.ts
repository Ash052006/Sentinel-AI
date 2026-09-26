import { api } from './client'
import type { CorrelationResult, Page } from '../types/api'

export const correlationsApi = {
  recent: (limit = 50): Promise<CorrelationResult[]> =>
    api.get<CorrelationResult[]>('/api/correlations/recent', { limit }),

  forDetection: (
    detectionId: string,
    page = 1,
    pageSize: number | undefined = 50,
  ): Promise<Page<CorrelationResult>> =>
    api.get<Page<CorrelationResult>>(
      `/api/correlations/detection/${detectionId}`,
      { page, page_size: pageSize },
    ),

  forEvent: (
    eventId: string,
    page = 1,
    pageSize: number | undefined = 50,
  ): Promise<Page<CorrelationResult>> =>
    api.get<Page<CorrelationResult>>(`/api/correlations/event/${eventId}`, {
      page,
      page_size: pageSize,
    }),

  get: (correlationId: string): Promise<CorrelationResult> =>
    api.get<CorrelationResult>(`/api/correlations/${correlationId}`),
}