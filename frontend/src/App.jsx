import { useEffect, useState } from 'react'
import { apiGet } from './api'
import Sidebar from './components/layout/Sidebar'
import OverviewPage from './pages/OverviewPage'
import FlowsPage from './pages/FlowsPage'
import InvestigationsPage from './pages/InvestigationsPage'
import ModelDashboardPage from './pages/ModelDashboardPage'

async function fetchAllFlows(sourceFiles, signal) {
  const results = await Promise.all(
    sourceFiles.map((name) => apiGet(`/api/flows?source_file=${encodeURIComponent(name)}`, { signal }))
  )
  return results.flatMap((r) => r.flows)
}

function App() {
  const [activePage, setActivePage] = useState('overview')

  const [health, setHealth] = useState('loading')
  const [healthError, setHealthError] = useState(null)

  const [verdictSummary, setVerdictSummary] = useState(null)
  const [models, setModels] = useState(null)

  const [allFlows, setAllFlows] = useState([])
  const [allFlowsLoading, setAllFlowsLoading] = useState(true)

  const [file, setFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState(null)
  const [uploadMessage, setUploadMessage] = useState(null)
  const [dataVersion, setDataVersion] = useState(0)

  function loadSharedData(signal) {
    apiGet('/api/verdicts/summary', { signal })
      .then(setVerdictSummary)
      .catch((err) => {
        if (err.name === 'AbortError') return
        setVerdictSummary(null)
      })
    apiGet('/api/models', { signal })
      .then((data) => setModels(data.models))
      .catch((err) => {
        if (err.name === 'AbortError') return
        setModels([])
      })

    setAllFlowsLoading(true)
    apiGet('/api/flows/source-files', { signal })
      .then((data) => fetchAllFlows(data.source_files, signal))
      .then(setAllFlows)
      .catch((err) => {
        if (err.name === 'AbortError') return
        setAllFlows([])
      })
      .finally(() => {
        if (!signal.aborted) setAllFlowsLoading(false)
      })
  }

  useEffect(() => {
    apiGet('/api/health')
      .then((data) => setHealth(data.status))
      .catch((err) => setHealthError(err.message))
  }, [])

  useEffect(() => {
    // In dev, React StrictMode mounts every effect twice (mount ->
    // cleanup -> mount) to surface non-idempotent effects. This effect
    // fires 8 real network requests (7 of them concurrent), so without
    // this abort-on-cleanup, StrictMode's canary run and the real run
    // would both fire, doubling backend load and visibly slowing the
    // Overview/Investigations pages' first load. Aborting the canary
    // run's in-flight requests on cleanup fixes that -- and is correct,
    // standard practice for fetch-in-effect regardless of StrictMode
    // (e.g. also cancels in-flight requests on a genuine unmount).
    const controller = new AbortController()
    loadSharedData(controller.signal)
    return () => controller.abort()
  }, [dataVersion])

  function handleUpload(e) {
    e.preventDefault()
    if (!file) return

    setUploading(true)
    setUploadError(null)
    setUploadMessage(null)

    const formData = new FormData()
    formData.append('file', file)

    fetch('http://localhost:8000/api/pcap/upload', { method: 'POST', body: formData })
      .then(async (res) => {
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || `Request failed: ${res.status}`)
        return data
      })
      .then((data) => {
        setUploadMessage(`Parsed ${data.flow_count} flow(s) from ${file.name}.`)
        setDataVersion((v) => v + 1)
      })
      .catch((err) => setUploadError(err.message))
      .finally(() => setUploading(false))
  }

  const activeModel = models?.find((m) => m.is_active) ?? null

  return (
    <div className="flex min-h-screen bg-bg-page text-text-primary">
      <Sidebar active={activePage} onNavigate={setActivePage} health={health} healthError={healthError} />

      <main className="flex-1 overflow-x-auto">
        <div className="flex flex-wrap items-center gap-3 border-b border-border bg-bg-card px-6 py-3">
          <form onSubmit={handleUpload} className="flex items-center gap-3">
            <input
              type="file"
              accept=".pcap,.pcapng"
              onChange={(e) => setFile(e.target.files[0] ?? null)}
              className="text-xs text-text-muted"
            />
            <button
              type="submit"
              disabled={!file || uploading}
              className="rounded-md bg-accent-cyan px-3 py-1.5 text-xs font-semibold text-bg-page disabled:opacity-50"
            >
              {uploading ? 'Uploading...' : 'Upload PCAP'}
            </button>
          </form>
          {uploadError && <span className="text-xs text-accent-red">{uploadError}</span>}
          {uploadMessage && <span className="text-xs text-accent-green">{uploadMessage}</span>}
        </div>

        <div className="p-6">
          {activePage === 'overview' && (
            <OverviewPage
              allFlows={allFlows}
              allFlowsLoading={allFlowsLoading}
              verdictSummary={verdictSummary}
              activeModel={activeModel}
            />
          )}
          {activePage === 'flows' && <FlowsPage key={dataVersion} />}
          {activePage === 'investigations' && (
            <InvestigationsPage allFlows={allFlows} allFlowsLoading={allFlowsLoading} />
          )}
          {activePage === 'models' && <ModelDashboardPage models={models} />}
        </div>
      </main>
    </div>
  )
}

export default App
