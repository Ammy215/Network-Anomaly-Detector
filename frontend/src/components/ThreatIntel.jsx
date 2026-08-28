import { useEffect, useState } from 'react'
import { apiPost } from '../api'
import Skeleton from './ui/Skeleton'

const PROVIDER_LABELS = {
  abuseipdb: 'AbuseIPDB',
  otx: 'AlienVault OTX',
  ipinfo: 'IPInfo',
  virustotal: 'VirusTotal',
}

function ProviderCard({ name, result }) {
  return (
    <div className="rounded border border-border bg-bg-card px-3 py-2">
      <div className="mb-1 text-text-muted">{PROVIDER_LABELS[name]}</div>
      {!result || !result.available ? (
        <div className="text-text-muted/70">
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
        <div className="text-text-primary">
          {data.abuse_confidence_score}/100 confidence · {data.total_reports} reports
        </div>
        <div className="font-mono text-text-muted">
          {data.isp ?? '—'} · {data.country_code ?? '—'}
          {data.domain ? ` · ${data.domain}` : ''}
        </div>
      </>
    )
  }
  if (name === 'otx') {
    return (
      <div className="text-text-primary">
        {data.pulse_count ?? 0} threat pulses · reputation {data.reputation ?? 0}
      </div>
    )
  }
  if (name === 'ipinfo') {
    return (
      <>
        <div className="text-text-primary">
          {data.city ?? '—'}, {data.region ?? '—'}, {data.country ?? '—'}
        </div>
        <div className="text-text-muted">{data.org ?? '—'}</div>
      </>
    )
  }
  if (name === 'virustotal') {
    const stats = data.last_analysis_stats ?? {}
    return (
      <>
        <div className="text-text-primary">
          {stats.malicious ?? 0} malicious · {stats.suspicious ?? 0} suspicious ·{' '}
          {stats.harmless ?? 0} harmless · {stats.undetected ?? 0} undetected
        </div>
        <div className="text-text-muted">
          reputation {data.reputation ?? 0} · {data.country ?? '—'}
        </div>
      </>
    )
  }
  return null
}

export default function ThreatIntel({ flow }) {
  const [state, setState] = useState(null)
  const [error, setError] = useState(null)
  const [fetching, setFetching] = useState(false)

  function check(fetchNow) {
    if (fetchNow) setFetching(true)
    setError(null)
    apiPost(`/api/flows/${flow.id}/enrichment`, { fetch: fetchNow })
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
    <div className="border-t border-border pt-4">
      <h3 className="mb-2 font-sans text-sm font-semibold text-text-primary">Threat Intelligence</h3>

      {error && <p className="text-accent-red">{error}</p>}
      {!state && !error && <Skeleton className="h-5 w-64" />}

      {state && !state.applicable && <p className="text-text-muted">{state.reason}</p>}

      {state && state.applicable && !state.providers && (
        <div>
          <p className="mb-2 text-text-muted">
            External IP: <span className="font-mono text-text-primary">{state.ip}</span> — not yet
            checked. Checking spends real API quota against free-tier daily limits, so it only
            happens on request.
          </p>
          <button
            type="button"
            onClick={() => check(true)}
            disabled={fetching}
            className="rounded-md bg-accent-cyan px-3 py-1.5 text-xs font-semibold text-bg-page disabled:opacity-50"
          >
            {fetching ? 'Enriching...' : 'Enrich'}
          </button>
        </div>
      )}

      {state && state.applicable && state.providers && (
        <div>
          <p className="mb-2 text-text-muted">
            <span className="font-mono text-text-primary">{state.ip}</span> —{' '}
            {state.cached ? 'cached' : 'just fetched'}, as of{' '}
            {new Date(state.fetched_at).toLocaleString()}
          </p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {Object.entries(state.providers).map(([name, result]) => (
              <ProviderCard key={name} name={name} result={result} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
