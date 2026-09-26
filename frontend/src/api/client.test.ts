import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, UNAUTHORIZED_EVENT } from './client'
import { tokenStore } from '../lib/utils'

describe('api client', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('attaches the stored bearer token to requests', async () => {
    tokenStore.set('tok-123')
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ok: 'yes' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    )

    const data = await api.get('/api/detections/recent')

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/detections/recent')
    expect((init?.headers as Headers).get('Authorization')).toBe('Bearer tok-123')
    expect(data).toEqual({ ok: 'yes' })
  })

  it('sends no authorization header when no token is stored', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } }),
    )

    await api.get('/api/correlations/recent')

    const [, init] = fetchMock.mock.calls[0]
    expect((init?.headers as Headers).has('Authorization')).toBe(false)
  })

  it('clears the token and dispatches the unauthorized event on 401', async () => {
    tokenStore.set('tok-expired')
    const listener = vi.fn()
    window.addEventListener(UNAUTHORIZED_EVENT, listener)

    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ detail: 'Not authenticated' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      }),
    )

    await expect(api.get('/api/audit')).rejects.toBeInstanceOf(ApiError)

    expect(tokenStore.get()).toBeNull()
    expect(listener).toHaveBeenCalledTimes(1)
  })

  it('throws ApiError carrying status and parsed body', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ detail: 'No such detection' }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      }),
    )

    await expect(api.get('/api/detections/nope')).rejects.toThrowError('No such detection')
  })

  it('parses non-JSON 4xx responses without crashing', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<html>Bad Gateway</html>', { status: 502 }),
    )

    const error = await api.get('/api/something').catch((err: unknown) => err)
    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(502)
  })
})