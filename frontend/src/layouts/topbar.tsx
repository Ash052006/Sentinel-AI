import {
  Activity,
  Database,
  LogOut,
  Menu,
  Radio,
  ShieldCheck,
  Siren,
  User as UserIcon,
} from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useAuthStore, useUiStore } from '../store/auth'
import { authApi } from '../api/auth'
import { healthApi } from '../api/health'
import { cn } from '../lib/utils'
import { SocSearch } from './soc-search'

export function TopBar() {
  const navigate = useNavigate()
  const toggleSidebar = useUiStore((state) => state.toggleSidebar)
  const user = useAuthStore((state) => state.user)
  const setUser = useAuthStore((state) => state.setUser)
  const logout = useAuthStore((state) => state.logout)

  useQuery({
    queryKey: ['users', 'me'],
    queryFn: async () => {
      const me = await authApi.me()
      setUser(me)
      return me
    },
    enabled: !user,
    retry: false,
  })

  const db = useQuery({
    queryKey: ['health', 'database'],
    queryFn: healthApi.database,
    refetchInterval: 30_000,
  })
  const kafka = useQuery({
    queryKey: ['health', 'kafka'],
    queryFn: healthApi.kafka,
    refetchInterval: 30_000,
  })

  function handleLogout(): void {
    logout()
    navigate('/login', { replace: true })
  }

  const dbOk = db.isSuccess && db.data?.status === 'connected'
  const kafkaOk = kafka.isSuccess && kafka.data?.status === 'healthy'

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-edge bg-surface-1 px-3">
      <button
        type="button"
        className="rounded-md p-1.5 text-ink-dim hover:bg-surface-2 hover:text-ink md:hidden"
        onClick={toggleSidebar}
        aria-label="Open navigation"
      >
        <Menu className="h-4 w-4" />
      </button>

      <div className="hidden shrink-0 leading-tight lg:block" data-testid="brand-block">
        <div className="text-xs font-semibold tracking-wide text-ink">SentinelAI</div>
        <div className="text-[9px] font-mono uppercase tracking-[0.18em] text-ink-faint">
          SOC Operations Center
        </div>
      </div>

      <SocSearch />

      <div className="ml-auto flex items-center gap-2">
        <div className="hidden items-center gap-2 md:flex" data-testid="health-indicator">
          <HealthDot
            label="db"
            ok={dbOk}
            loading={db.isLoading}
          />
          <HealthDot
            label="kafka"
            ok={kafkaOk}
            loading={kafka.isLoading}
          />
        </div>

        <Link
          to="/system"
          aria-label="System health"
          data-testid="nav-system-health"
          className={cn(
            'hidden items-center gap-1.5 rounded-md border border-edge bg-surface-0 px-2 py-1.5 font-mono text-[10px] uppercase sm:inline-flex',
            dbOk && kafkaOk ? 'text-low' : 'text-high',
          )}
        >
          <Activity className="h-3 w-3" aria-hidden="true" />
          Health
        </Link>

        <Link
          to="/incidents"
          aria-label="Incidents and alerts"
          data-testid="nav-alerts"
          className="rounded-md border border-edge bg-surface-0 p-1.5 text-ink-dim hover:text-ink"
        >
          <Siren className="h-3.5 w-3.5" aria-hidden="true" />
        </Link>

        <div className="flex items-center gap-2 rounded-md border border-edge bg-surface-0 px-2 py-1.5">
          <UserIcon className="h-3.5 w-3.5 text-ink-dim" aria-hidden="true" />
          <span className="hidden max-w-40 truncate text-xs text-ink sm:inline">
            {user?.email ?? '…'}
          </span>
          {user?.role && (
            <span className="rounded bg-accent/10 px-1 font-mono text-[10px] uppercase text-accent">
              {user.role}
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={handleLogout}
          className="rounded-md p-1.5 text-ink-dim hover:bg-surface-2 hover:text-ink"
          aria-label="Sign out"
          data-testid="logout"
        >
          <LogOut className="h-4 w-4" />
        </button>
      </div>
    </header>
  )
}

function HealthDot({
  label,
  ok,
  loading,
}: {
  label: string
  ok: boolean
  loading: boolean
}) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md border border-edge bg-surface-0 px-2 py-1 font-mono text-[10px] uppercase text-ink-faint"
      data-testid={`health-${label}`}
    >
      {loading ? (
        <Radio className="h-3 w-3 text-ink-faint" aria-hidden="true" />
      ) : ok ? (
        <Database className="h-3 w-3 text-low" aria-hidden="true" />
      ) : (
        <ShieldCheck className="h-3 w-3 text-critical" aria-hidden="true" />
      )}
      <span className={cn(ok ? 'text-low' : 'text-critical')}>{label}</span>
    </span>
  )
}