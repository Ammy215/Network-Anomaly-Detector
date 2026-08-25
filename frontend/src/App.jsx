import { Fragment, useEffect, useState } from 'react'
import FlowDetailPanel from './components/FlowDetailPanel'
import VerdictSummary from './components/VerdictSummary'
import { severityBand } from './severity'

const API_BASE_URL = 'http://localhost:8000'

const VERDICT_LABELS = {
  true_positive: 'TP',
  false_positive: 'FP',
  benign: 'Benign',
  unknown: 'Unknown',
}

function verdictBadge(flow) {
  if (!flow.verdict) {
    return <span className="text-slate-600">—</span>
  }
  const missed = flow.verdict.value === 'true_positive' && flow.is_anomalous === false
  return (
    <span className={missed ? 'text-amber-400' : 'text-slate-300'}>
      {VERDICT_LABELS[flow.verdict.value] ?? flow.verdict.value}
      {missed ? ' · missed' : ''}
    </span>
  )
}

function App() {
  const [health, setHealth] = useState('loading')
  const [healthError, setHealthError] = useState(null)

  const [flows, setFlows] = useState([])
  const [flowsError, setFlowsError] = useState(null)
  const [scoredBy, setScoredBy] = useState(null)

  const [file, setFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState(null)
  const [uploadMessage, setUploadMessage] = useState(null)

  const [expandedFlowId, setExpandedFlowId] = useState(null)
  const [verdictSummary, setVerdictSummary] = useState(null)

  const [sourceFiles, setSourceFiles] = useState([])
  const [sourceFileFilter, setSourceFileFilter] = useState('')
  const [scoreSort, setScoreSort] = useState('started_desc')

  function loadFlows() {
    setFlowsError(null)
    const params = new URLSearchParams()
    if (sourceFileFilter) params.set('source_file', sourceFileFilter)
    if (scoreSort !== 'started_desc') params.set('sort', scoreSort)
    fetch(`${API_BASE_URL}/api/flows?${params.toString()}`)
      .then((res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`)
        return res.json()
      })
      .then((data) => {
        setFlows(data.flows)
        setScoredBy(data.scored_by)
      })
      .catch((err) => setFlowsError(err.message))
  }

  function loadSourceFiles() {
    fetch(`${API_BASE_URL}/api/flows/source-files`)
      .then((res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`)
        return res.json()
      })
      .then((data) => setSourceFiles(data.source_files))
      .catch(() => setSourceFiles([]))
  }

  function loadVerdictSummary() {
    fetch(`${API_BASE_URL}/api/verdicts/summary`)
      .then((res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`)
        return res.json()
      })
      .then(setVerdictSummary)
      .catch(() => setVerdictSummary(null))
  }

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/health`)
      .then((res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`)
        return res.json()
      })
      .then((data) => setHealth(data.status))
      .catch((err) => setHealthError(err.message))

    loadSourceFiles()
    loadVerdictSummary()
  }, [])

  useEffect(() => {
    loadFlows()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceFileFilter, scoreSort])

  function handleUpload(e) {
    e.preventDefault()
    if (!file) return

    setUploading(true)
    setUploadError(null)
    setUploadMessage(null)

    const formData = new FormData()
    formData.append('file', file)

    fetch(`${API_BASE_URL}/api/pcap/upload`, { method: 'POST', body: formData })
      .then(async (res) => {
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || `Request failed: ${res.status}`)
        return data
      })
      .then((data) => {
        setUploadMessage(`Parsed ${data.flow_count} flow(s) from ${file.name}.`)
        loadFlows()
      })
      .catch((err) => setUploadError(err.message))
      .finally(() => setUploading(false))
  }

  function handleVerdictSaved(flowId, verdictRow) {
    setFlows((prev) =>
      prev.map((flow) =>
        flow.id === flowId
          ? {
              ...flow,
              verdict: {
                value: verdictRow.verdict,
                note: verdictRow.note,
                created_by: verdictRow.created_by,
                created_at: verdictRow.created_at,
                updated_at: verdictRow.updated_at,
              },
            }
          : flow
      )
    )
    loadVerdictSummary()
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">NetSentinel</h1>
        <p className="text-sm text-slate-400">
          Phase 4 — score transparency & verdict feedback
        </p>
      </div>

      <div className="rounded-md border border-slate-800 bg-slate-900 px-4 py-3 font-mono text-sm w-fit">
        {healthError ? (
          <span className="text-red-400">backend error: {healthError}</span>
        ) : health === 'loading' ? (
          <span className="text-slate-400">checking backend health...</span>
        ) : (
          <span className="text-green-400">backend status: {health}</span>
        )}
      </div>

      <form onSubmit={handleUpload} className="flex items-center gap-3">
        <input
          type="file"
          accept=".pcap,.pcapng"
          onChange={(e) => setFile(e.target.files[0] ?? null)}
          className="text-sm"
        />
        <button
          type="submit"
          disabled={!file || uploading}
          className="rounded-md bg-cyan-600 px-3 py-1.5 text-sm font-medium disabled:opacity-50"
        >
          {uploading ? 'Uploading...' : 'Upload PCAP'}
        </button>
      </form>

      {uploadError && <p className="text-sm text-red-400">{uploadError}</p>}
      {uploadMessage && <p className="text-sm text-green-400">{uploadMessage}</p>}

      <VerdictSummary summary={verdictSummary} />

      <div>
        <h2 className="text-lg font-medium mb-2">Flows</h2>
        <div className="flex flex-wrap items-center gap-3 mb-2 text-sm font-mono">
          <label className="flex items-center gap-2 text-slate-400">
            Source file
            <select
              value={sourceFileFilter}
              onChange={(e) => setSourceFileFilter(e.target.value)}
              className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
            >
              <option value="">All</option>
              {sourceFiles.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 text-slate-400">
            Sort by score
            <select
              value={scoreSort}
              onChange={(e) => setScoreSort(e.target.value)}
              className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200"
            >
              <option value="started_desc">Newest first (default)</option>
              <option value="score_desc">Score: high to low</option>
              <option value="score_asc">Score: low to high</option>
            </select>
          </label>
          {(sourceFileFilter || scoreSort !== 'started_desc') && (
            <span className="text-slate-600">{flows.length} flows shown</span>
          )}
        </div>
        {scoredBy && (
          <p className="text-xs text-slate-500 mb-2 font-mono">
            scores from {scoredBy.algorithm} ({scoredBy.variant}), threshold{' '}
            {scoredBy.threshold.toFixed(4)} — other trained models score these
            same flows differently; see /api/models. Severity is a derived label
            over the score, not a separate measurement.
          </p>
        )}
        {flowsError && <p className="text-sm text-red-400">{flowsError}</p>}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm font-mono border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-1 pr-4">#</th>
                <th className="py-1 pr-4">Source</th>
                <th className="py-1 pr-4">Destination</th>
                <th className="py-1 pr-4">Dst Port</th>
                <th className="py-1 pr-4">Protocol</th>
                <th className="py-1 pr-4">Packets</th>
                <th className="py-1 pr-4">Bytes</th>
                <th className="py-1 pr-4">PPS</th>
                <th className="py-1 pr-4">Avg Size</th>
                <th className="py-1 pr-4">Close</th>
                <th className="py-1 pr-4">
                  Score{scoredBy ? ` (${scoredBy.algorithm})` : ''}
                </th>
                <th className="py-1 pr-4">Severity</th>
                <th className="py-1 pr-4">Top Contributing Features</th>
                <th className="py-1 pr-4">Started</th>
                <th className="py-1 pr-4">Verdict</th>
              </tr>
            </thead>
            <tbody>
              {flows.length === 0 ? (
                <tr>
                  <td colSpan={15} className="py-3 text-slate-500">
                    No flows yet — upload a .pcap to see results.
                  </td>
                </tr>
              ) : (
                flows.map((flow) => {
                  const sev = severityBand(flow.anomaly_score, flow.is_anomalous)
                  const isExpanded = expandedFlowId === flow.id
                  return (
                    <Fragment key={flow.id}>
                      <tr className="border-b border-slate-900">
                        <td className="py-1 pr-4 text-slate-500">
                          <button
                            type="button"
                            onClick={() => setExpandedFlowId(isExpanded ? null : flow.id)}
                            className="hover:text-cyan-400"
                          >
                            {isExpanded ? '▾' : '▸'} {flow.seq}
                          </button>
                        </td>
                        <td className="py-1 pr-4">
                          {flow.src_ip}:{flow.src_port ?? '-'}
                        </td>
                        <td className="py-1 pr-4">
                          {flow.dst_ip}:{flow.dst_port ?? '-'}
                        </td>
                        <td className="py-1 pr-4">{flow.dst_port ?? '-'}</td>
                        <td className="py-1 pr-4">{flow.protocol}</td>
                        <td className="py-1 pr-4">{flow.packet_count}</td>
                        <td className="py-1 pr-4">{flow.byte_count}</td>
                        <td className="py-1 pr-4">{flow.packets_per_second?.toFixed(1) ?? '-'}</td>
                        <td className="py-1 pr-4">{flow.avg_packet_size?.toFixed(0) ?? '-'}</td>
                        <td className="py-1 pr-4">{flow.close_type ?? '-'}</td>
                        <td className={`py-1 pr-4 ${flow.is_anomalous ? 'text-amber-400' : ''}`}>
                          {flow.anomaly_score != null ? flow.anomaly_score.toFixed(0) : '-'}
                        </td>
                        <td className={`py-1 pr-4 ${sev.color}`} title={sev.detail}>
                          {sev.label}
                        </td>
                        <td className="py-1 pr-4 text-slate-400">
                          {flow.top_features?.length
                            ? flow.top_features
                                .filter((f) => f.contribution > 0)
                                .slice(0, 3)
                                .map((f) => f.feature)
                                .join(', ') || '-'
                            : '-'}
                        </td>
                        <td className="py-1 pr-4">{new Date(flow.started_at).toLocaleString()}</td>
                        <td className="py-1 pr-4">{verdictBadge(flow)}</td>
                      </tr>
                      {isExpanded && (
                        <tr className="border-b border-slate-900">
                          <td colSpan={15} className="py-3">
                            <FlowDetailPanel
                              flow={flow}
                              scoredBy={scoredBy}
                              apiBaseUrl={API_BASE_URL}
                              onVerdictSaved={handleVerdictSaved}
                            />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  )
}

export default App
