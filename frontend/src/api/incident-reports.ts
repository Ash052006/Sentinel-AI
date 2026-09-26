import { api } from './client'
import type {
  IncidentReportGenerateRequest,
  IncidentReportListPage,
  IncidentReportPayload,
  IncidentReportRecord,
} from '../types/api'

export const incidentReportsApi = {
  list: (
    page = 1,
    pageSize = 50,
    correlationId?: string,
  ): Promise<IncidentReportListPage> =>
    api.get<IncidentReportListPage>('/api/incident-reports', {
      page,
      page_size: pageSize,
      correlation_id: correlationId,
    }),

  report: (reportId: string): Promise<IncidentReportRecord> =>
    api.get<IncidentReportRecord>(
      `/api/incident-reports/${encodeURIComponent(reportId)}`,
    ),

  generate: (
    body: IncidentReportGenerateRequest,
  ): Promise<IncidentReportRecord> =>
    api.post<IncidentReportRecord>('/api/incident-reports/generate', body),
}

export type { IncidentReportPayload }