import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { DigitalTwinPage } from './digital-twin-page'
import { renderWithProviders } from '../test/utils'
import { ApiError } from '../api/client'
import type { DigitalTwinHealth } from '../types/api'

const HEALTH: DigitalTwinHealth = { status: 'ok', module: 'digital_twin' }

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderPage() {
  return renderWithProviders(<DigitalTwinPage />, {
    route: '/digital-twin',
    entries: ['/digital-twin'],
  })
}

describe('DigitalTwinPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('renders the module health status', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(HEALTH))

    renderPage()

    expect(await screen.findByTestId('digital-twin-status')).toHaveTextContent(
      'ok',
    )
    expect(screen.getByTestId('digital-twin-module')).toHaveTextContent(
      'digital_twin',
    )
  })

  it('GETs the health endpoint', async () => {
    const calls: Array<{ url: string; method: string }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      calls.push({ url: String(input), method: init?.method ?? 'GET' })
      return json(HEALTH)
    })

    renderPage()
    await screen.findByTestId('digital-twin-status')

    expect(calls[0]?.url).toBe('/api/digital-twin/health')
    expect(calls[0]?.method).toBe('GET')
  })

  it('does not fabricate twin state while the functional API is unavailable', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(HEALTH))

    renderPage()
    await screen.findByTestId('digital-twin-status')

    // The page states plainly what is missing rather than inventing snapshots
    // or simulation results the backend cannot answer for.
    const stub = screen.getByTestId('digital-twin-stub')
    expect(stub).toBeInTheDocument()
    expect(
      screen.getByText('Twin simulation is not available yet'),
    ).toBeInTheDocument()
  })

  it('surfaces a governed failure without inventing metrics', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      throw new ApiError(503, 'twin module unreachable')
    })

    renderPage()

    await waitFor(() =>
      expect(screen.getByTestId('digital-twin-error')).toBeInTheDocument(),
    )
    expect(screen.getByText('twin module unreachable')).toBeInTheDocument()
    expect(screen.queryByTestId('digital-twin-status')).toBeNull()
  })
})
