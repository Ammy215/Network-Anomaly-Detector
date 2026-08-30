import { useEffect, useState } from 'react'
import { apiGet } from '../../api'
import Badge from '../ui/Badge'

const NAV_ITEMS = [
  { key: 'overview', label: 'Overview', roles: ['admin', 'analyst', 'viewer'] },
  { key: 'flows', label: 'Flows', roles: ['admin', 'analyst', 'viewer'] },
  { key: 'investigations', label: 'Investigations', roles: ['admin', 'analyst', 'viewer'] },
  { key: 'live-capture', label: 'Live Capture', roles: ['admin', 'analyst', 'viewer'] },
  { key: 'models', label: 'Model dashboard', roles: ['admin', 'analyst', 'viewer'] },
  { key: 'admin', label: 'Admin panel', roles: ['admin'] },
]

const CAPTURE_STATUS_POLL_MS = 5000

export default function Sidebar({ active, onNavigate, health, healthError, role, userEmail, onSignOut }) {
  const dotTone = healthError ? 'bg-accent-red' : health === 'ok' ? 'bg-accent-green' : 'bg-accent-amber'
  const statusText = healthError ? 'backend unreachable' : health === 'ok' ? 'backend online' : 'checking...'
  const visibleItems = NAV_ITEMS.filter((item) => item.roles.includes(role))

  // Polls independently of whichever page is active -- a running capture
  // must stay visible "at all times" (the hard boundary), not just while
  // looking at the Live Capture page itself.
  const [captureRunning, setCaptureRunning] = useState(false)

  useEffect(() => {
    let cancelled = false
    function poll() {
      apiGet('/api/capture/status')
        .then((data) => {
          if (!cancelled) setCaptureRunning(Boolean(data.running))
        })
        .catch(() => {})
    }
    poll()
    const id = setInterval(poll, CAPTURE_STATUS_POLL_MS)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-border bg-bg-card">
      <div className="border-b border-border px-4 py-5">
        <h1 className="font-sans text-lg font-bold text-text-primary">NetSentinel</h1>
        <p className="mt-0.5 text-xs text-text-muted">Network anomaly detection</p>
      </div>
      {captureRunning && (
        <button
          type="button"
          onClick={() => onNavigate('live-capture')}
          className="mx-2 mt-3 flex items-center justify-center"
        >
          <Badge tone="red" critical dot>
            LIVE CAPTURE RUNNING
          </Badge>
        </button>
      )}
      <nav className="flex flex-1 flex-col gap-1 px-2 py-3">
        {visibleItems.map((item) => (
          <button
            key={item.key}
            type="button"
            onClick={() => onNavigate(item.key)}
            className={`rounded-md border px-3 py-2 text-left text-sm font-medium transition-colors ${
              active === item.key
                ? 'border-accent-cyan/30 bg-accent-cyan/10 text-accent-cyan'
                : 'border-transparent text-text-muted hover:bg-bg-elevated hover:text-text-primary'
            }`}
          >
            {item.label}
          </button>
        ))}
      </nav>
      <div className="border-t border-border px-4 py-3">
        <div className="flex items-center gap-2 text-xs">
          <span className={`h-2 w-2 rounded-full ${dotTone}`} />
          <span className="text-text-muted">{statusText}</span>
        </div>
        {userEmail && (
          <div className="mt-3 flex items-center justify-between gap-2">
            <div className="min-w-0">
              <p className="truncate font-mono text-xs text-text-primary" title={userEmail}>
                {userEmail}
              </p>
              <p className="text-xs uppercase tracking-wide text-text-muted">{role}</p>
            </div>
            <button
              type="button"
              onClick={onSignOut}
              className="shrink-0 rounded border border-border px-2 py-1 text-xs text-text-muted hover:border-accent-red/40 hover:text-accent-red"
            >
              Sign out
            </button>
          </div>
        )}
      </div>
    </aside>
  )
}
