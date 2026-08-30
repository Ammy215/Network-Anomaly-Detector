import { useEffect, useRef, useState } from 'react'
import { apiGet, apiPost, API_BASE_URL } from '../api'
import { getAccessToken } from '../supabaseClient'
import { useAuth } from '../auth/AuthContext'
import Badge from '../components/ui/Badge'
import Card from '../components/ui/Card'
import Skeleton from '../components/ui/Skeleton'
import { severityBand } from '../severity'

const STATUS_POLL_MS = 5000
const MAX_DISPLAYED_FLOWS = 200

export default function LiveCapturePage() {
  const { role } = useAuth()
  const canControl = role === 'analyst' || role === 'admin'

  const [interfaces, setInterfaces] = useState(null)
  const [interfacesError, setInterfacesError] = useState(null)
  const [selectedInterface, setSelectedInterface] = useState('')

  const [status, setStatus] = useState(null)
  const [actionError, setActionError] = useState(null)
  const [starting, setStarting] = useState(false)
  const [stopping, setStopping] = useState(false)

  const [liveFlows, setLiveFlows] = useState([])
  const eventSourceRef = useRef(null)

  function loadStatus() {
    apiGet('/api/capture/status')
      .then(setStatus)
      .catch(() => {})
  }

  useEffect(() => {
    apiGet('/api/capture/interfaces')
      .then((data) => setInterfaces(data.interfaces))
      .catch((err) => setInterfacesError(err.message))
    loadStatus()
    const id = setInterval(loadStatus, STATUS_POLL_MS)
    return () => clearInterval(id)
  }, [])

  // Only ever open while a capture is actually running -- reflects
  // whichever session (this tab or another) started it, since capture
  // state lives entirely on the server, not in this component.
  useEffect(() => {
    if (!status?.running) return

    let cancelled = false
    let source

    getAccessToken().then((token) => {
      if (cancelled || !token) return
      source = new EventSource(`${API_BASE_URL}/api/capture/stream?token=${encodeURIComponent(token)}`)
      eventSourceRef.current = source

      source.onmessage = (event) => {
        try {
          const flow = JSON.parse(event.data)
          setLiveFlows((prev) => [flow, ...prev].slice(0, MAX_DISPLAYED_FLOWS))
        } catch {
          // ignore malformed event
        }
      }
      source.addEventListener('capture-stopped', () => {
        loadStatus()
      })
    })

    return () => {
      cancelled = true
      source?.close()
      eventSourceRef.current = null
    }
  }, [status?.running])

  function handleStart() {
    if (!selectedInterface) return
    const confirmed = window.confirm(
      `Start a live capture on "${selectedInterface}"?\n\nThis will observe real traffic on this interface, ` +
        'including anything sensitive currently on your network, until you stop it.'
    )
    if (!confirmed) return

    setStarting(true)
    setActionError(null)
    apiPost('/api/capture/start', { interface: selectedInterface })
      .then((data) => {
        setStatus(data)
        setLiveFlows([])
      })
      .catch((err) => setActionError(err.message))
      .finally(() => setStarting(false))
  }

  function handleStop() {
    setStopping(true)
    setActionError(null)
    apiPost('/api/capture/stop', {})
      .then((data) => setStatus({ running: false, interface: null, started_by: null, started_at: null, flow_count: data.flow_count }))
      .catch((err) => setActionError(err.message))
      .finally(() => setStopping(false))
  }

  const isRunning = status?.running === true

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-sans text-xl font-bold text-text-primary">Live Capture</h2>
          <p className="mt-1 text-sm text-text-muted">
            Sniffs a real interface on this machine and scores flows as they complete, same pipeline as a
            PCAP upload.
          </p>
        </div>
        {isRunning && (
          <Badge tone="red" critical dot>
            LIVE
          </Badge>
        )}
      </div>

      <Card>
        {!isRunning ? (
          <div className="flex flex-col gap-3">
            <div className="rounded-md border border-accent-amber/40 bg-accent-amber/10 px-3 py-2 text-sm text-accent-amber">
              Starting a capture observes real network traffic on the interface you select, including
              anything sensitive currently on your network. Use this only on your own machine or a network
              you're authorized to monitor. It never starts automatically, and only runs while you keep it
              running here.
            </div>

            {interfacesError && <p className="text-sm text-accent-red">{interfacesError}</p>}
            {!interfaces && !interfacesError && <Skeleton className="h-9 w-full max-w-sm" />}

            {interfaces && (
              <div className="flex flex-wrap items-center gap-3">
                <select
                  value={selectedInterface}
                  onChange={(e) => setSelectedInterface(e.target.value)}
                  disabled={!canControl}
                  className="min-w-[16rem] rounded border border-border bg-bg-elevated px-3 py-2 text-sm text-text-primary disabled:opacity-50"
                >
                  <option value="">Select an interface…</option>
                  {interfaces.map((iface) => (
                    <option key={iface.id} value={iface.id}>
                      {iface.name}
                    </option>
                  ))}
                </select>
                {canControl && (
                  <button
                    type="button"
                    onClick={handleStart}
                    disabled={!selectedInterface || starting}
                    className="rounded-md bg-accent-red px-3 py-1.5 text-xs font-semibold text-bg-page disabled:opacity-50"
                  >
                    {starting ? 'Starting…' : 'Start capture'}
                  </button>
                )}
              </div>
            )}

            {!canControl && (
              <p className="text-sm text-text-muted">
                Viewing only — starting a capture requires an analyst or admin account.
              </p>
            )}
            {actionError && <p className="text-sm text-accent-red">{actionError}</p>}
          </div>
        ) : (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-sm text-text-muted">
              Capturing on <span className="font-mono text-text-primary">{status.interface}</span> — started
              by <span className="font-mono text-text-primary">{status.started_by}</span> at{' '}
              {new Date(status.started_at).toLocaleTimeString()} — {status.flow_count} flow
              {status.flow_count === 1 ? '' : 's'} recorded
            </div>
            {canControl && (
              <button
                type="button"
                onClick={handleStop}
                disabled={stopping}
                className="rounded-md border border-accent-red/40 px-3 py-1.5 text-xs font-semibold text-accent-red hover:bg-accent-red/10 disabled:opacity-50"
              >
                {stopping ? 'Stopping…' : 'Stop capture'}
              </button>
            )}
            {actionError && <span className="text-sm text-accent-red">{actionError}</span>}
          </div>
        )}
      </Card>

      {isRunning && (
        <Card className="!p-0" delay={0.05}>
          {liveFlows.length === 0 ? (
            <p className="p-4 text-text-muted">Waiting for the first flow to complete…</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-border text-xs uppercase tracking-wide text-text-muted">
                    <th className="px-3 py-2 font-medium">Source</th>
                    <th className="px-3 py-2 font-medium">Destination</th>
                    <th className="px-3 py-2 font-medium">Protocol</th>
                    <th className="px-3 py-2 font-medium">Packets</th>
                    <th className="px-3 py-2 font-medium">Bytes</th>
                    <th className="px-3 py-2 font-medium">Score</th>
                    <th className="px-3 py-2 font-medium">Severity</th>
                    <th className="px-3 py-2 font-medium">Closed</th>
                  </tr>
                </thead>
                <tbody>
                  {liveFlows.map((flow) => {
                    const sev = severityBand(flow.anomaly_score, flow.is_anomalous)
                    return (
                      <tr key={flow.id} className="border-b border-border/60">
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-text-primary">
                          {flow.src_ip}:{flow.src_port ?? '-'}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-text-primary">
                          {flow.dst_ip}:{flow.dst_port ?? '-'}
                        </td>
                        <td className="px-3 py-2 font-mono text-text-muted">{flow.protocol}</td>
                        <td className="px-3 py-2 font-mono text-text-muted">{flow.packet_count}</td>
                        <td className="px-3 py-2 font-mono text-text-muted">{flow.byte_count}</td>
                        <td className="px-3 py-2 font-mono text-text-primary">
                          {flow.anomaly_score != null ? flow.anomaly_score.toFixed(0) : '-'}
                        </td>
                        <td className="px-3 py-2">
                          <Badge tone={sev.tone} critical={sev.critical}>
                            {sev.label}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 font-mono text-xs text-text-muted">{flow.close_reason}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  )
}
