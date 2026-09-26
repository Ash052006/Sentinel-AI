import { api } from './client'
import type {
  BumpClass,
  DetectionAsCodeRuleDetail,
  DetectionAsCodeRulePage,
  DetectionRuleReleaseRecord,
  DetectionRuleVersionRecord,
  SetEnabledRequest,
  ValidateRuleRequest,
} from '../types/api'

export interface LifecycleOutput {
  rule_id: string
  version: string
}

export const detectionAsCodeApi = {
  list: (page = 1, pageSize = 50): Promise<DetectionAsCodeRulePage> =>
    api.get<DetectionAsCodeRulePage>('/api/detection-as-code', {
      page,
      page_size: pageSize,
    }),

  get: (ruleId: string): Promise<DetectionAsCodeRuleDetail> =>
    api.get<DetectionAsCodeRuleDetail>(
      `/api/detection-as-code/${encodeURIComponent(ruleId)}`,
    ),

  validate: (
    body: ValidateRuleRequest,
  ): Promise<DetectionRuleVersionRecord> =>
    api.post<DetectionRuleVersionRecord>('/api/detection-as-code/validate', body),

  release: (ruleId: string, version: string): Promise<DetectionRuleReleaseRecord> =>
    api.post<DetectionRuleReleaseRecord>('/api/detection-as-code/release', {
      rule_id: ruleId,
      version,
    }),

  deploy: (ruleId: string, version: string): Promise<DetectionRuleReleaseRecord> =>
    api.post<DetectionRuleReleaseRecord>('/api/detection-as-code/deploy', {
      rule_id: ruleId,
      version,
    }),

  rollback: (ruleId: string, version: string): Promise<DetectionRuleReleaseRecord> =>
    api.post<DetectionRuleReleaseRecord>('/api/detection-as-code/rollback', {
      rule_id: ruleId,
      version,
    }),

  setEnabled: (body: SetEnabledRequest): Promise<DetectionRuleReleaseRecord> =>
    api.post<DetectionRuleReleaseRecord>('/api/detection-as-code/enabled', body),
}

export type { BumpClass }