import {
  Activity,
  BookKey,
  Braces,
  Crosshair,
  FileClock,
  FileSearch,
  FileText,
  FlaskConical,
  Gavel,
  LayoutDashboard,
  Magnet,
  Network,
  ScanSearch,
  ScrollText,
  Settings,
  ShieldAlert,
  Siren,
  Workflow,
  X,
  type LucideIcon,
} from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { cn } from '../lib/utils'
import { useUiStore } from '../store/auth'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  end?: boolean
}

const NAV_SECTIONS: Array<{ heading: string; items: NavItem[] }> = [
  {
    heading: 'Operations',
    items: [
      { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, end: true },
      { to: '/incidents', label: 'Incidents', icon: Siren },
      { to: '/detections', label: 'Detections', icon: Crosshair },
      { to: '/detection-rules', label: 'Detection Rules', icon: Braces },
      { to: '/detection-as-code', label: 'Detection as Code', icon: Workflow },
      { to: '/correlations', label: 'Correlations', icon: Magnet },
      { to: '/risk', label: 'Risk', icon: ShieldAlert },
    ],
  },
  {
    heading: 'Analysis',
    items: [
      { to: '/threat-intelligence', label: 'Threat Intel', icon: BookKey },
      { to: '/investigations', label: 'Investigation', icon: FileSearch },
      { to: '/policy', label: 'Policy', icon: Gavel },
      { to: '/responses', label: 'Responses', icon: FlaskConical },
      { to: '/soar', label: 'SOAR', icon: Workflow },
      { to: '/threat-hunting', label: 'Hunting', icon: ScanSearch },
      { to: '/incident-reports', label: 'Incident Reports', icon: FileText },
      { to: '/attack-paths', label: 'Attack Paths', icon: Network },
    ],
  },
  {
    heading: 'System',
    items: [
      { to: '/system', label: 'Health', icon: Activity },
      { to: '/audit', label: 'Audit', icon: FileClock },
      { to: '/settings', label: 'Settings', icon: Settings },
    ],
  },
]

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="flex-1 space-y-4 overflow-y-auto px-2 py-3">
      {NAV_SECTIONS.map((section) => (
        <div key={section.heading}>
          <div className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-ink-faint">
            {section.heading}
          </div>
          <ul className="space-y-0.5">
            {section.items.map((item) => {
              const Icon = item.icon
              return (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    onClick={onNavigate}
                    className={({ isActive }) =>
                      cn(
                        'group flex items-center gap-2.5 rounded-md border-l-2 px-2.5 py-1.5 text-xs font-medium transition-colors',
                        isActive
                          ? 'border-accent bg-surface-2 text-ink'
                          : 'border-transparent text-ink-dim hover:bg-surface-2 hover:text-ink',
                      )
                    }
                  >
                    <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                    {item.label}
                  </NavLink>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </nav>
  )
}

export function Sidebar() {
  const sidebarOpen = useUiStore((state) => state.sidebarOpen)
  const closeSidebar = useUiStore((state) => state.closeSidebar)

  return (
    <>
      <aside
        data-testid="sidebar"
        className={cn(
          'flex h-full w-60 shrink-0 flex-col border-r border-edge bg-surface-0 transition-transform',
          'fixed inset-y-0 left-0 z-40 md:static md:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex h-14 shrink-0 items-center gap-2 border-b border-edge px-4">
          <div className="flex h-6 w-6 items-center justify-center rounded bg-accent/15 text-accent">
            <ScrollText className="h-3.5 w-3.5" aria-hidden="true" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-semibold text-ink">SentinelAI</div>
            <div className="text-[10px] uppercase tracking-widest text-ink-faint">
              SOC Console · V1
            </div>
          </div>
          <button
            type="button"
            className="ml-auto rounded p-1 text-ink-dim hover:text-ink md:hidden"
            onClick={closeSidebar}
            aria-label="Close navigation"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <NavList onNavigate={closeSidebar} />
        <div className="border-t border-edge px-4 py-2 text-[10px] leading-relaxed text-ink-faint">
          SentinelAI SOC Dashboard
          <br />
          Read-only · V1
        </div>
      </aside>
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 md:hidden"
          onClick={closeSidebar}
          aria-hidden="true"
        />
      )}
    </>
  )
}