import { api } from './client'
import type {
  ApprovalDecisionInput,
  ApprovalRecord,
  ApprovalStatus,
  Page,
} from '../types/api'

export const approvalsApi = {
  list: (
    page = 1,
    pageSize: number | undefined = 50,
    status?: ApprovalStatus,
  ): Promise<Page<ApprovalRecord>> =>
    api.get<Page<ApprovalRecord>>('/api/approvals', {
      page,
      page_size: pageSize,
      status,
    }),

  recent: (limit = 50, status?: ApprovalStatus): Promise<ApprovalRecord[]> =>
    api.get<ApprovalRecord[]>('/api/approvals/recent', { limit, status }),

  get: (approvalId: string): Promise<ApprovalRecord> =>
    api.get<ApprovalRecord>(`/api/approvals/${approvalId}`),

  approve: (
    approvalId: string,
    decision: ApprovalDecisionInput,
  ): Promise<ApprovalRecord> =>
    api.post<ApprovalRecord>(
      `/api/approvals/${approvalId}/approve`,
      decision,
    ),

  reject: (
    approvalId: string,
    decision: ApprovalDecisionInput,
  ): Promise<ApprovalRecord> =>
    api.post<ApprovalRecord>(
      `/api/approvals/${approvalId}/reject`,
      decision,
    ),

  cancel: (
    approvalId: string,
    decision: ApprovalDecisionInput,
  ): Promise<ApprovalRecord> =>
    api.post<ApprovalRecord>(
      `/api/approvals/${approvalId}/cancel`,
      decision,
    ),
}