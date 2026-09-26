import { api } from './client'
import type { DatabaseHealth, KafkaHealth } from '../types/api'

export const healthApi = {
  database: (): Promise<DatabaseHealth> =>
    api.get<DatabaseHealth>('/api/health/database'),
  kafka: (): Promise<KafkaHealth> => api.get<KafkaHealth>('/api/health/kafka'),
}