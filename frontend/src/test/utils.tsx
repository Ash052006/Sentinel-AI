import type { ReactElement } from 'react'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })
}

export function renderWithProviders(
  ui: ReactElement,
  { route = '/', entries = ['/'] }: { route?: string; entries?: string[] } = {},
) {
  const queryClient = makeQueryClient()
  window.history.pushState({}, '', route)
  return {
    queryClient,
    ...render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={entries}>{ui}</MemoryRouter>
      </QueryClientProvider>,
    ),
  }
}