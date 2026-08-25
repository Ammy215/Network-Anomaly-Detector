import { useEffect, useState } from 'react'

const API_BASE_URL = 'http://localhost:8000'

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

  function loadFlows() {
    setFlowsError(null)
    fetch(`${API_BASE_URL}/api/flows`)
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

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/health`)
      .then((res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`)
        return res.json()
      })
      .then((data) => setHealth(data.status))
      .catch((err) => setHealthError(err.message))

    loadFlows()
  }, [])

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

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">NetSentinel</h1>
        <p className="text-sm text-slate-400">Phase 3 — flows → features → anomaly scores</p>
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

      <div>
        <h2 className="text-lg font-medium mb-2">Flows</h2>
        {scoredBy && (
          <p className="text-xs text-slate-500 mb-2 font-mono">
            scores from {scoredBy.algorithm} ({scoredBy.variant}), threshold{' '}
            {scoredBy.threshold.toFixed(4)} — other trained models score these
            same flows differently; see /api/models
          </p>
        )}
        {flowsError && <p className="text-sm text-red-400">{flowsError}</p>}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm font-mono border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-1 pr-4">Source</th>
                <th className="py-1 pr-4">Destination</th>
                <th className="py-1 pr-4">Protocol</th>
                <th className="py-1 pr-4">Packets</th>
                <th className="py-1 pr-4">Bytes</th>
                <th className="py-1 pr-4">PPS</th>
                <th className="py-1 pr-4">Avg Size</th>
                <th className="py-1 pr-4">Close</th>
                <th className="py-1 pr-4">
                  Score{scoredBy ? ` (${scoredBy.algorithm})` : ''}
                </th>
                <th className="py-1 pr-4">Top Contributing Features</th>
                <th className="py-1 pr-4">Started</th>
              </tr>
            </thead>
            <tbody>
              {flows.length === 0 ? (
                <tr>
                  <td colSpan={11} className="py-3 text-slate-500">
                    No flows yet — upload a .pcap to see results.
                  </td>
                </tr>
              ) : (
                flows.map((flow) => (
                  <tr key={flow.id} className="border-b border-slate-900">
                    <td className="py-1 pr-4">
                      {flow.src_ip}:{flow.src_port ?? '-'}
                    </td>
                    <td className="py-1 pr-4">
                      {flow.dst_ip}:{flow.dst_port ?? '-'}
                    </td>
                    <td className="py-1 pr-4">{flow.protocol}</td>
                    <td className="py-1 pr-4">{flow.packet_count}</td>
                    <td className="py-1 pr-4">{flow.byte_count}</td>
                    <td className="py-1 pr-4">{flow.packets_per_second?.toFixed(1) ?? '-'}</td>
                    <td className="py-1 pr-4">{flow.avg_packet_size?.toFixed(0) ?? '-'}</td>
                    <td className="py-1 pr-4">{flow.close_type ?? '-'}</td>
                    <td className={`py-1 pr-4 ${flow.is_anomalous ? 'text-amber-400' : ''}`}>
                      {flow.anomaly_score != null ? flow.anomaly_score.toFixed(0) : '-'}
                    </td>
                    <td className="py-1 pr-4 text-slate-400">
                      {flow.top_features?.length
                        ? flow.top_features.map((f) => f.feature).join(', ')
                        : '-'}
                    </td>
                    <td className="py-1 pr-4">{new Date(flow.started_at).toLocaleString()}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  )
}

export default App
