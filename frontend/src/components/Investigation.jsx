import { useEffect, useState } from 'react'

function chunkText(retrievedChunks, chunkId) {
  return retrievedChunks.find((c) => c.id === chunkId)?.text ?? null
}

function SelfCheckBanner({ selfCheck }) {
  const hasIssues =
    !selfCheck.citations_valid ||
    selfCheck.invalid_citations.length > 0 ||
    selfCheck.unsupported_claims.length > 0

  if (!hasIssues) {
    return (
      <p className="text-green-400 mb-2">
        Self-check passed — every citation and named technique is backed by a retrieved chunk.
      </p>
    )
  }

  return (
    <div className="rounded border border-red-700 bg-red-950/40 px-3 py-2 mb-2 text-red-300">
      <p className="font-semibold mb-1">Self-check flagged issues in this investigation:</p>
      {selfCheck.invalid_citations.length > 0 && (
        <p>Unsupported citations: {selfCheck.invalid_citations.join(', ')}</p>
      )}
      {selfCheck.unsupported_claims.length > 0 && (
        <ul className="list-disc list-inside">
          {selfCheck.unsupported_claims.map((claim, i) => (
            <li key={i}>{claim}</li>
          ))}
        </ul>
      )}
      {selfCheck.notes && <p className="text-red-400 mt-1">{selfCheck.notes}</p>}
    </div>
  )
}

export default function Investigation({ flow, apiBaseUrl }) {
  const [state, setState] = useState(null)
  const [error, setError] = useState(null)
  const [fetching, setFetching] = useState(false)

  function check(fetchNow) {
    if (fetchNow) setFetching(true)
    setError(null)
    fetch(`${apiBaseUrl}/api/flows/${flow.id}/investigate`, {
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
      <h3 className="text-sm font-semibold text-slate-200 mb-2">AI Investigation</h3>

      {error && <p className="text-red-400">{error}</p>}
      {!state && !error && <p className="text-slate-500">Checking...</p>}

      {state && !state.cached && (
        <div>
          <p className="text-slate-500 mb-2">
            Not yet investigated. Running this calls a free-tier LLM (Groq) three times
            (classify, explain, self-check), so it only happens on request.
          </p>
          <button
            type="button"
            onClick={() => check(true)}
            disabled={fetching}
            className="rounded-md bg-cyan-600 px-3 py-1.5 text-xs font-medium disabled:opacity-50"
          >
            {fetching ? 'Investigating...' : 'Investigate'}
          </button>
        </div>
      )}

      {state && state.cached && (
        <div className="space-y-2">
          <p className="text-slate-600">
            Classified as{' '}
            <span className="text-slate-300">{state.classification.anomaly_type}</span>{' '}
            (confidence {state.classification.confidence.toFixed(2)}) — {state.classification.reasoning}
          </p>

          <SelfCheckBanner selfCheck={state.self_check} />

          <div className="rounded border border-slate-800 bg-slate-900 px-3 py-2">
            <p className="text-slate-200 font-semibold mb-1">{state.investigation.summary}</p>
            <p className="text-slate-400 mb-2">{state.investigation.detailed_narrative}</p>
            <p className="text-slate-500">
              Confidence: <span className="text-slate-300">{state.investigation.confidence.toFixed(2)}</span>
            </p>
            <p className="text-slate-500">
              Recommended action:{' '}
              <span className="text-slate-300">{state.investigation.recommended_action}</span>
            </p>
          </div>

          <div>
            <p className="text-slate-400 mb-1">
              MITRE techniques:{' '}
              {state.investigation.mitre_techniques.length === 0 ? (
                <span className="text-slate-600">none — no retrieved evidence supported one</span>
              ) : (
                state.investigation.mitre_techniques.map((t) => (
                  <span
                    key={t}
                    className="inline-block rounded bg-slate-800 border border-slate-700 px-1.5 py-0.5 mr-1 text-slate-300"
                  >
                    {t}
                  </span>
                ))
              )}
            </p>
          </div>

          {state.investigation.citations.length > 0 && (
            <div>
              <p className="text-slate-400 mb-1">Citations:</p>
              <ul className="space-y-1">
                {state.investigation.citations.map((c, i) => (
                  <li key={i} className="rounded border border-slate-800 bg-slate-900 px-2 py-1">
                    <div className="text-slate-500">{c.source}</div>
                    <div className="text-slate-300">"{c.excerpt}"</div>
                    {chunkText(state.retrieved_chunks, c.source) && (
                      <div className="text-slate-600 mt-1">
                        Chunk text: {chunkText(state.retrieved_chunks, c.source)}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <p className="text-slate-700">
            {state.models.classify} / {state.models.explain} / {state.models.self_check} —{' '}
            {new Date(state.fetched_at).toLocaleString()}
          </p>
        </div>
      )}
    </div>
  )
}
