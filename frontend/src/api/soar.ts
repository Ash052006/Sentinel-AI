import { api } from './client'
import type {
  Page,
  SoarDryRunResult,
  SoarExecutionRecord,
  SoarExecutionRequest,
  SoarExecutionStatus,
  SoarPlaybookRecord,
} from '../types/api'

export const soarApi = {
  playbooks: (page = 1, pageSize = 50): Promise<Page<SoarPlaybookRecord>> =>
    api.get<Page<SoarPlaybookRecord>>('/api/soar/playbooks', {
      page,
      page_size: pageSize,
    }),

  playbook: (playbookId: string): Promise<SoarPlaybookRecord> =>
    api.get<SoarPlaybookRecord>(
      `/api/soar/playbooks/${encodeURIComponent(playbookId)}`,
    ),

  executions: (
    page = 1,
    pageSize = 50,
    status?: SoarExecutionStatus,
  ): Promise<Page<SoarExecutionRecord>> =>
    api.get<Page<SoarExecutionRecord>>('/api/soar/executions', {
      page,
      page_size: pageSize,
      status,
    }),

  execution: (executionId: string): Promise<SoarExecutionRecord> =>
    api.get<SoarExecutionRecord>(
      `/api/soar/executions/${encodeURIComponent(executionId)}`,
    ),

  execute: (body: SoarExecutionRequest): Promise<SoarExecutionRecord> =>
    api.post<SoarExecutionRecord>('/api/soar/executions', body),

  dryRun: (body: SoarExecutionRequest): Promise<SoarDryRunResult> =>
    api.post<SoarDryRunResult>('/api/soar/dry-run', body),

  cancel: (executionId: string): Promise<SoarExecutionRecord> =>
    api.post<SoarExecutionRecord>(
      `/api/soar/executions/${encodeURIComponent(executionId)}/cancel`,
      {},
    ),
}