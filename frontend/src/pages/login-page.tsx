import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ScrollText } from 'lucide-react'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/auth'
import { ApiError } from '../api/client'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { Input } from '../components/ui/input'

export function LoginPage() {
  const navigate = useNavigate()
  const setToken = useAuthStore((state) => state.setToken)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      const token = await authApi.login({ email, password })
      setToken(token.access_token)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 401
          ? 'Invalid email or password'
          : err instanceof ApiError
            ? err.detail
            : 'Unable to reach the SentinelAI API',
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-surface-0 px-4">
      <Card className="w-full max-w-sm">
        <div className="flex flex-col items-center border-b border-edge-soft px-6 py-6 text-center">
          <div className="flex h-10 w-10 items-center justify-center rounded bg-accent/15 text-accent">
            <ScrollText className="h-5 w-5" aria-hidden="true" />
          </div>
          <h1 className="mt-3 text-base font-semibold text-ink">SentinelAI SOC</h1>
          <p className="mt-1 text-[11px] text-ink-faint">
            Sign in to the read-only security operations console.
          </p>
        </div>
        <form className="space-y-3 px-6 py-5" onSubmit={submit}>
          <label className="block">
            <span className="mb-1 block text-[11px] font-medium uppercase tracking-wider text-ink-dim">
              Email
            </span>
            <Input
              type="email"
              required
              autoComplete="username"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-[11px] font-medium uppercase tracking-wider text-ink-dim">
              Password
            </span>
            <Input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          {error && (
            <div
              role="alert"
              data-testid="login-error"
              className="rounded-md border border-critical/40 bg-critical/10 px-3 py-2 text-[11px] text-critical"
            >
              {error}
            </div>
          )}
          <Button type="submit" className="w-full" disabled={submitting}>
            {submitting ? 'Signing in…' : 'Sign in'}
          </Button>
        </form>
      </Card>
    </div>
  )
}