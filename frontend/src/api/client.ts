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
 * Extracts a human-readable reason from an error body.
 *
 * FastAPI puts the exception payload under `detail`, so a governed failure
 * arrives one level deeper as an object carrying its own human-readable
 * `detail` (V3.23 debate, V3.24 prediction). Those bodies exist precisely so the
 * UI can explain *why* something failed; flattening them to a bare status code
 * would throw that away. The failure code is folded into the message so the
 * governed code stays visible even when the detail is generic.
 */
function errorMessage(detail: unknown, status: number): string {
  if (typeof detail === 'string' && detail.length > 0) return detail
  if (detail && typeof detail === 'object') {
    const failure = detail as { detail?: unknown; failure_code?: unknown }
    if (typeof failure.detail === 'string' && failure.detail.length > 0) {
      return typeof failure.failure_code === 'string'
        ? `${failure.detail} (${failure.failure_code})`
        : failure.detail
    }
  }
  return `Request failed (${status})`
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
  if (init?.body && !(init.body instanceof FormData)) {
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
    throw new ApiError(response.status, errorMessage(detail, response.status))
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

  /**
   * POST multipart/form-data. The browser sets the multipart boundary, so
   * no Content-Type header is sent from here.
   */
  upload: <T>(path: string, form: FormData): Promise<T> =>
    request<T>(path, { method: 'POST', body: form }),
}