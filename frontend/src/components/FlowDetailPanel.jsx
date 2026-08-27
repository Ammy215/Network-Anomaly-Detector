import { useEffect, useState } from 'react'
import { featureName, featureValue } from '../featureLabels'
import { severityBand } from '../severity'
import Investigation from './Investigation'
import ThreatIntel from './ThreatIntel'

const VERDICT_OPTIONS = [
  { value: 'true_positive', label: 'True Positive' },
  { value: 'false_positive', label: 'False Positive' },
  { value: 'benign', label: 'Benign' },
  { value: 'unknown', label: 'Unknown' },
]

export default function FlowDetailPanel({ flow, scoredBy, apiBaseUrl, onVerdictSaved }) {
  const [breakdown, setBreakdown] = useState(null)
  const [breakdownError, setBreakdownError] = useState(null)

  const [verdict, setVerdict] = useState(flow.verdict?.value ?? 'unknown')
  const [note, setNote] = useState(flow.verdict?.note ?? '')
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState(null)
  const [saveMessage, setSaveMessage] = useState(null)

  useEffect(() => {
    setBreakdown(null)
    setBreakdownError(null)
    fetch(`${apiBaseUrl}/api/flows/${flow.id}/score`)
      .then((res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`)
        return res.json()
      })
      .then((data) => {
        const entry = (data.scores ?? []).find(
          (s) => s.model_version_id === scoredBy?.model_version_id
        )
        if (!entry) {
          setBreakdownError('No stored explanation for this flow under the active model.')
          return
        }
        const sorted = [...(entry.top_features ?? [])].sort(
          (a, b) => b.contribution - a.contribution
        )
        setBreakdown(sorted)
      })
      .catch((err) => setBreakdownError(err.message))
  }, [flow.id, scoredBy?.model_version_id, apiBaseUrl])

  function saveVerdict() {
    setSaving(true)
    setSaveError(null)
    setSaveMessage(null)
    fetch(`${apiBaseUrl}/api/flows/${flow.id}/verdict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verdict, note: note || null }),
    })
      .then(async (res) => {
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || `Request failed: ${res.status}`)
        return data
      })
      .then((data) => {
        setSaveMessage('Saved.')
        onVerdictSaved(flow.id, data)
      })
      .catch((err) => setSaveError(err.message))
      .finally(() => setSaving(false))
  }

  const missedByModel = verdict === 'true_positive' && flow.is_anomalous === false
  const sev = severityBand(flow.anomaly_score, flow.is_anomalous)

  return (
    <div className="border border-slate-800 bg-slate-950 rounded-md p-4 space-y-4 font-mono text-xs">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-1 rounded border border-slate-800 bg-slate-900 px-3 py-2">
        <span>
          Score:{' '}
          <span className="text-slate-100 text-sm">
            {flow.anomaly_score != null ? flow.anomaly_score.toFixed(0) : '-'}
          </span>
        </span>
        <span>
          Status:{' '}
          <span className={flow.is_anomalous ? 'text-red-400' : 'text-slate-300'}>
            {flow.is_anomalous ? 'Flagged' : 'Not flagged'}
          </span>
        </span>
        <span>
          Severity: <span className={sev.color}>{sev.label}</span>
          <span className="text-slate-600"> ({sev.detail})</span>
        </span>
      </div>

      <div>
        <h3 className="text-sm font-semibold text-slate-200 mb-2">
          Score breakdown — {scoredBy?.algorithm} ({scoredBy?.variant})
        </h3>
        {breakdownError && <p className="text-red-400">{breakdownError}</p>}
        {!breakdown && !breakdownError && <p className="text-slate-500">Loading...</p>}
        {breakdown && (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500">
                  <th className="py-1 pr-4">Feature</th>
                  <th className="py-1 pr-4">This flow</th>
                  <th className="py-1 pr-4">Typical baseline</th>
                  <th className="py-1 pr-4">Contribution</th>
                  <th className="py-1 pr-4">Direction</th>
                </tr>
              </thead>
              <tbody>
                {breakdown.map((entry) => (
                  <tr key={entry.feature} className="border-b border-slate-900">
                    <td className="py-1 pr-4 text-slate-300">{featureName(entry.feature)}</td>
                    <td className="py-1 pr-4">{featureValue(entry.feature, entry.flow_value)}</td>
                    <td className="py-1 pr-4 text-slate-500">
                      {featureValue(entry.feature, entry.baseline_value)}
                    </td>
                    <td
                      className={`py-1 pr-4 ${
                        entry.contribution > 0
                          ? 'text-amber-400'
                          : entry.contribution < 0
                            ? 'text-green-400'
                            : 'text-slate-500'
                      }`}
                    >
                      {entry.contribution > 0 ? '+' : ''}
                      {entry.contribution.toFixed(4)}
                    </td>
                    <td className="py-1 pr-4 text-slate-500">
                      {entry.contribution > 0
                        ? 'toward anomalous'
                        : entry.contribution < 0
                          ? 'toward normal'
                          : 'neutral'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="text-slate-600 mt-2">
              Occlusion-based attribution: each contribution is how much the score would improve
              if this feature were swapped for its typical training value. Indicative, not a
              rigorous Shapley decomposition — correlated features can understate each other.
            </p>
          </div>
        )}
      </div>

      <div className="border-t border-slate-800 pt-3">
        <h3 className="text-sm font-semibold text-slate-200 mb-2">Verdict</h3>
        <div className="flex flex-wrap gap-2 mb-2">
          {VERDICT_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              onClick={() => setVerdict(opt.value)}
              className={`px-2 py-1 rounded border text-xs ${
                verdict === opt.value
                  ? 'bg-cyan-900 border-cyan-600 text-cyan-200'
                  : 'border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
        {missedByModel && (
          <p className="text-amber-400 mb-2">
            This flow was not flagged by the active model (is_anomalous=false) — marking it True
            Positive records it as a missed detection.
          </p>
        )}
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Optional note"
          rows={2}
          className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200 text-xs mb-2"
        />
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={saveVerdict}
            disabled={saving}
            className="rounded-md bg-cyan-600 px-3 py-1.5 text-xs font-medium disabled:opacity-50"
          >
            {saving ? 'Saving...' : 'Save verdict'}
          </button>
          {saveError && <span className="text-red-400">{saveError}</span>}
          {saveMessage && <span className="text-green-400">{saveMessage}</span>}
          {flow.verdict && (
            <span className="text-slate-600">
              last set by {flow.verdict.created_by} at{' '}
              {new Date(flow.verdict.updated_at).toLocaleString()}
            </span>
          )}
        </div>
      </div>

      {flow.is_anomalous && <ThreatIntel flow={flow} apiBaseUrl={apiBaseUrl} />}
      {flow.is_anomalous && <Investigation flow={flow} apiBaseUrl={apiBaseUrl} />}
    </div>
  )
}
