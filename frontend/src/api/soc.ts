import { api } from './client'
import type { SOCQueryResponse } from '../types/api'

export const socApi = {
  query: (query: string): Promise<SOCQueryResponse> =>
    api.post<SOCQueryResponse>('/api/soc/query', { query }),
}