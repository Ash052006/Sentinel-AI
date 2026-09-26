import { api } from './client'
import type { IncidentMemory, MemoryType, Page } from '../types/api'

export const memoriesApi = {
  list: (
    page = 1,
    pageSize: number | undefined = 50,
    memoryType?: MemoryType,
  ): Promise<Page<IncidentMemory>> =>
    api.get<Page<IncidentMemory>>('/api/incident-memories', {
      page,
      page_size: pageSize,
      memory_type: memoryType,
    }),

  recent: (limit = 50): Promise<IncidentMemory[]> =>
    api.get<IncidentMemory[]>('/api/incident-memories/recent', { limit }),

  forCorrelation: (
    correlationId: string,
    page = 1,
    pageSize: number | undefined = 50,
  ): Promise<Page<IncidentMemory>> =>
    api.get<Page<IncidentMemory>>(
      `/api/incident-memories/correlation/${correlationId}`,
      { page, page_size: pageSize },
    ),

  get: (memoryId: string): Promise<IncidentMemory> =>
    api.get<IncidentMemory>(`/api/incident-memories/${memoryId}`),
}