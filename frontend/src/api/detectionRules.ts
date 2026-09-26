import { api } from './client'
import type {
  DetectionRule,
  DetectionRuleAnalytics,
  DetectionRuleDetail,
} from '../types/api'

export type AnalyticsWindow = '1h' | '6h' | '24h' | '7d' | '30d'

export const detectionRulesApi = {
  list: (): Promise<DetectionRule[]> => api.get<DetectionRule[]>('/api/detection-rules'),

  get: (ruleId: string): Promise<DetectionRuleDetail> =>
    api.get<DetectionRuleDetail>(
      `/api/detection-rules/${encodeURIComponent(ruleId)}`,
    ),

  analytics: (window: AnalyticsWindow = '30d'): Promise<DetectionRuleAnalytics> =>
    api.get<DetectionRuleAnalytics>('/api/detection-rules/analytics', { window }),
}