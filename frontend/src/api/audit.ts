import { api } from './client'
import type { AuditLogList } from '../types/api'

export const auditApi = {
  logs: (
    skip = 0,
    limit: number | undefined = 50,
  ): Promise<AuditLogList> =>
    api.get<AuditLogList>('/api/audit/logs', { skip, limit }),
}