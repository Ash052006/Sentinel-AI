import { api } from './client'
import type { Page, RiskAssessment } from '../types/api'

export const risksApi = {
  recent: (limit = 50): Promise<RiskAssessment[]> =>
    api.get<RiskAssessment[]>('/api/risk-assessments/recent', { limit }),

  forCorrelation: (
    correlationId: string,
    page = 1,
    pageSize: number | undefined = 50,
  ): Promise<Page<RiskAssessment>> =>
    api.get<Page<RiskAssessment>>(
      `/api/risk-assessments/correlation/${correlationId}`,
      { page, page_size: pageSize },
    ),

  get: (riskAssessmentId: string): Promise<RiskAssessment> =>
    api.get<RiskAssessment>(`/api/risk-assessments/${riskAssessmentId}`),
}