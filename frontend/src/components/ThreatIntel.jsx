import { useEffect, useState } from 'react'

const PROVIDER_LABELS = {
  abuseipdb: 'AbuseIPDB',
  otx: 'AlienVault OTX',
  ipinfo: 'IPInfo',
  virustotal: 'VirusTotal',
}

function ProviderCard({ name, result }) {
  return (
    <div className="rounded border border-slate-800 bg-slate-900 px-3 py-2">
      <div className="text-slate-400 mb-1">{PROVIDER_LABELS[name]}</div>
      {!result || !result.available ? (
        <div className="text-slate-600">
          Unavailable{result?.error ? ` (${result.error})` : ''}
        </div>
      ) : (
        <ProviderFacts name={name} data={result.data} />
      )}
    </div>
  )
}

function ProviderFacts({ name, data }) {
  if (name === 'abuseipdb') {
    return (
      <>
        <div>
          {data.abuse_confidence_score}/100 confidence · {data.total_reports} reports
        </div>
        <div className="text-slate-500">
          {data.isp ?? '—'} · {data.country_code ?? '—'}
          {data.domain ? ` · ${data.domain}` : ''}
        </div>
      </>
    )
  }
  if (name === 'otx') {
    return (
      <div>
        {data.pulse_count ?? 0} threat pulses · reputation {data.reputation ?? 0}
      </div>
    )
  }
  if (name === 'ipinfo') {
    return (
      <>
        <div>
          {data.city ?? '—'}, {data.region ?? '—'}, {data.country ?? '—'}
        </div>
        <div className="text-slate-500">{data.org ?? '—'}</div>
      </>
    )
  }
  if (name === 'virustotal') {
    const stats = data.last_analysis_stats ?? {}
    return (
      <>
        <div>
          {stats.malicious ?? 0} malicious · {stats.suspicious ?? 0} suspicious ·{' '}
          {stats.harmless ?? 0} harmless · {stats.undetected ?? 0} undetected
        </div>
        <div className="text-slate-500">
          reputation {data.reputation ?? 0} · {data.country ?? '—'}
        </div>
      </>
    )
  }
  return null
}

export default function ThreatIntel({ flow, apiBaseUrl }) {
  const [state, setState] = useState(null)
  const [error, setError] = useState(null)
  const [fetching, setFetching] = useState(false)

  function check(fetchNow) {
    if (fetchNow) setFetching(true)
    setError(null)
    fetch(`${apiBaseUrl}/api/flows/${flow.id}/enrichment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fetch: fetchNow }),
    })
      .then(async (res) => {
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || `Request failed: ${res.status}`)
        return data
      })
      .then(setState)
      .catch((err) => setError(err.message))
      .finally(() => setFetching(false))
  }

  useEffect(() => {
    setState(null)
    check(false)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flow.id])

  return (
    <div className="border-t border-slate-800 pt-3">
      <h3 className="text-sm font-semibold text-slate-200 mb-2">Threat Intelligence</h3>

      {error && <p className="text-red-400">{error}</p>}
      {!state && !error && <p className="text-slate-500">Checking...</p>}

      {state && !state.applicable && <p className="text-slate-500">{state.reason}</p>}

      {state && state.applicable && !state.providers && (
        <div>
          <p className="text-slate-500 mb-2">
            External IP: <span className="text-slate-300">{state.ip}</span> — not yet checked.
            Checking spends real API quota against free-tier daily limits, so it only happens
            on request.
          </p>
          <button
            type="button"
            onClick={() => check(true)}
            disabled={fetching}
            className="rounded-md bg-cyan-600 px-3 py-1.5 text-xs font-medium disabled:opacity-50"
          >
            {fetching ? 'Enriching...' : 'Enrich'}
          </button>
        </div>
      )}

      {state && state.applicable && state.providers && (
        <div>
          <p className="text-slate-600 mb-2">
            {state.ip} — {state.cached ? 'cached' : 'just fetched'}, as of{' '}
            {new Date(state.fetched_at).toLocaleString()}
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {Object.entries(state.providers).map(([name, result]) => (
              <ProviderCard key={name} name={name} result={result} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
