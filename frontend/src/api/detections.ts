import { api } from './client'
import type {
  DetectionAnalysis,
  DetectionFailure,
  DetectionResult,
  Page,
} from '../types/api'

export const detectionsApi = {
  recent: (limit = 50): Promise<DetectionResult[]> =>
    api.get<DetectionResult[]>('/api/detections/recent', { limit }),

  forEvent: (
    eventId: string,
    page = 1,
    pageSize: number | undefined = 50,
  ): Promise<Page<DetectionResult>> =>
    api.get<Page<DetectionResult>>(`/api/detections/event/${eventId}`, {
      page,
      page_size: pageSize,
    }),

  forRule: (
    ruleId: string,
    page = 1,
    pageSize: number | undefined = 50,
  ): Promise<Page<DetectionResult>> =>
    api.get<Page<DetectionResult>>(
      `/api/detections/rule/${encodeURIComponent(ruleId)}`,
      { page, page_size: pageSize },
    ),

  get: (detectionId: string): Promise<DetectionResult> =>
    api.get<DetectionResult>(`/api/detections/${detectionId}`),

  analysis: (eventId: string): Promise<DetectionAnalysis> =>
    api.get<DetectionAnalysis>(`/api/detection-analyses/${eventId}`),

  failures: (
    eventId: string,
    page = 1,
    pageSize: number | undefined = 50,
  ): Promise<Page<DetectionFailure>> =>
    api.get<Page<DetectionFailure>>(
      `/api/detection-analyses/${eventId}/failures`,
      { page, page_size: pageSize },
    ),
}