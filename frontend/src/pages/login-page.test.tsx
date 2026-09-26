import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { LoginPage } from './login-page'
import { renderWithProviders } from '../test/utils'
import { ApiError } from '../api/client'

vi.mock('../api/auth', () => ({
  authApi: {
    login: vi.fn(),
  },
}))

const mocked = await import('../api/auth')

describe('LoginPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the sign-in card', () => {
    renderWithProviders(<LoginPage />)
    expect(screen.getByRole('heading', { name: /sentinelai soc/i })).toBeInTheDocument()
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
  })

  it('shows an inline error on invalid credentials', async () => {
    vi.mocked(mocked.authApi.login).mockRejectedValue(
      new ApiError(401, 'Invalid email or password'),
    )

    renderWithProviders(<LoginPage />)
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'analyst@sentinel.ai' },
    })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'wrongpass' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    expect(await screen.findByTestId('login-error')).toHaveTextContent(
      'Invalid email or password',
    )
  })

  it('stores the token and navigates to the dashboard on success', async () => {
    vi.mocked(mocked.authApi.login).mockResolvedValue({
      access_token: 'jwt-abc',
      token_type: 'bearer',
    })

    renderWithProviders(<LoginPage />, { route: '/login' })
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'analyst@sentinel.ai' },
    })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'secrets' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(localStorage.getItem('sentinel.soc.token')).toBe('jwt-abc')
    })
  })
})