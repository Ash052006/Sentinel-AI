import { tokenStore } from '../lib/utils'

export class ApiError extends Error {
  status: number
  detail: string

  constructor(status: number, detail: string) {
    super(detail)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

/**
 * Fired on any 401 so the shell can route the user back to /login.
 * Dispatch is side-effect free and safe to fire repeatedly.
 */
export const UNAUTHORIZED_EVENT = 'sentinel:unauthorized'

type QueryValue = string | number | boolean | null | undefined

function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  if (!query) return path
  const pairs = Object.entries(query)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(
      ([key, value]) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`,
    )
  if (pairs.length === 0) return path
  return `${path}?${pairs.join('&')}`
}

async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const headers = new Headers(init?.headers)
  headers.set('Accept', 'application/json')
  const token = tokenStore.get()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (init?.body) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(path, { ...init, headers })

  if (response.status === 401) {
    tokenStore.clear()
    window.dispatchEvent(new Event(UNAUTHORIZED_EVENT))
  }

  if (!response.ok) {
    let detail: unknown
    try {
      const body = (await response.json()) as { detail?: unknown }
      detail = body.detail
    } catch {
      /* non-JSON error body */
    }
    const message =
      typeof detail === 'string' && detail.length > 0
        ? detail
        : `Request failed (${response.status})`
    throw new ApiError(response.status, message)
  }

  if (response.status === 204) {
    return undefined as T
  }

  try {
    return (await response.json()) as T
  } catch {
    throw new ApiError(response.status, 'Invalid response payload')
  }
}

export const api = {
  get: <T>(
    path: string,
    query?: Record<string, QueryValue>,
  ): Promise<T> => request<T>(buildUrl(path, query)),

  post: <T>(
    path: string,
    body: unknown,
    query?: Record<string, QueryValue>,
  ): Promise<T> =>
    request<T>(buildUrl(path, query), {
      method: 'POST',
      body: JSON.stringify(body),
    }),
}