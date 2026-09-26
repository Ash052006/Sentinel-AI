import { Link } from 'react-router-dom'
import { Button } from '../components/ui/button'

export function NotFoundPage() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 text-center">
      <div className="font-mono text-4xl text-ink-faint">404</div>
      <div className="text-sm text-ink-dim">This page does not exist in the SOC console.</div>
      <Button asChild variant="outline">
        <Link to="/dashboard">Back to dashboard</Link>
      </Button>
    </div>
  )
}