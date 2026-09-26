import { api } from './client'
import type {
  LoginRequest,
  RegisterRequest,
  RegisterResponse,
  TokenResponse,
  UserMe,
} from '../types/api'

export const authApi = {
  login: (body: LoginRequest): Promise<TokenResponse> =>
    api.post<TokenResponse>('/api/auth/login', body),
  register: (body: RegisterRequest): Promise<RegisterResponse> =>
    api.post<RegisterResponse>('/api/auth/register', body),
  me: (): Promise<UserMe> => api.get<UserMe>('/api/users/me'),
}