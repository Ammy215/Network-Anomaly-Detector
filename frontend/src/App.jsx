import { useEffect, useState } from 'react'

const API_BASE_URL = 'http://localhost:8000'

function App() {
  const [status, setStatus] = useState('loading')
  const [error, setError] = useState(null)

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/health`)
      .then((res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`)
        return res.json()
      })
      .then((data) => setStatus(data.status))
      .catch((err) => setError(err.message))
  }, [])

  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 bg-slate-950 text-slate-100">
      <h1 className="text-2xl font-semibold">NetSentinel</h1>
      <p className="text-sm text-slate-400">Phase 0 — foundation</p>

      <div className="rounded-md border border-slate-800 bg-slate-900 px-4 py-3 font-mono text-sm">
        {error ? (
          <span className="text-red-400">backend error: {error}</span>
        ) : status === 'loading' ? (
          <span className="text-slate-400">checking backend health...</span>
        ) : (
          <span className="text-green-400">backend status: {status}</span>
        )}
      </div>
    </main>
  )
}

export default App
