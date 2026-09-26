import { Navigate, Outlet, useNavigate } from 'react-router-dom'
import { useEffect } from 'react'
import { Sidebar } from './sidebar'
import { TopBar } from './topbar'
import { UNAUTHORIZED_EVENT } from '../api/client'
import { useAuthStore } from '../store/auth'

export function AppShell() {
  const token = useAuthStore((state) => state.token)
  const navigate = useNavigate()

  useEffect(() => {
    function onUnauthorized(): void {
      navigate('/login', { replace: true })
    }
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  }, [navigate])

  if (!token) {
    return <Navigate to="/login" replace />
  }

  return (
    <div className="flex h-full overflow-hidden">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-4">
          <Outlet />
        </main>
      </div>
    </div>
  )
}