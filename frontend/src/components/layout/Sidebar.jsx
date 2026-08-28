const NAV_ITEMS = [
  { key: 'overview', label: 'Overview' },
  { key: 'flows', label: 'Flows' },
  { key: 'investigations', label: 'Investigations' },
  { key: 'models', label: 'Model dashboard' },
]

export default function Sidebar({ active, onNavigate, health, healthError }) {
  const dotTone = healthError ? 'bg-accent-red' : health === 'ok' ? 'bg-accent-green' : 'bg-accent-amber'
  const statusText = healthError ? 'backend unreachable' : health === 'ok' ? 'backend online' : 'checking...'

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-border bg-bg-card">
      <div className="border-b border-border px-4 py-5">
        <h1 className="font-sans text-lg font-bold text-text-primary">NetSentinel</h1>
        <p className="mt-0.5 text-xs text-text-muted">Network anomaly detection</p>
      </div>
      <nav className="flex flex-1 flex-col gap-1 px-2 py-3">
        {NAV_ITEMS.map((item) => (
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
      <div className="flex items-center gap-2 border-t border-border px-4 py-3 text-xs">
        <span className={`h-2 w-2 rounded-full ${dotTone}`} />
        <span className="text-text-muted">{statusText}</span>
      </div>
    </aside>
  )
}
