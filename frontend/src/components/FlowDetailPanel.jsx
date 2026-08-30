import { useEffect, useState } from 'react'
import { apiGet, apiPost } from '../api'
import { useAuth } from '../auth/AuthContext'
import { featureName, featureValue } from '../featureLabels'
import { severityBand, verdictLabel, verdictTone } from '../severity'
import Badge from './ui/Badge'
import Skeleton from './ui/Skeleton'
import Investigation from './Investigation'
import ThreatIntel from './ThreatIntel'

const VERDICT_OPTIONS = [
  { value: 'true_positive', label: 'True Positive' },
  { value: 'false_positive', label: 'False Positive' },
  { value: 'benign', label: 'Benign' },
  { value: 'unknown', label: 'Unknown' },
]

export default function FlowDetailPanel({ flow, scoredBy, onVerdictSaved }) {
  const { role } = useAuth()
  const canSetVerdict = role === 'analyst' || role === 'admin'
  const [breakdown, setBreakdown] = useState(null)
  const [breakdownError, setBreakdownError] = useState(null)

  const [verdict, setVerdict] = useState(flow.verdict?.value ?? 'unknown')
  const [note, setNote] = useState(flow.verdict?.note ?? '')
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState(null)
  const [savedVerdict, setSavedVerdict] = useState(flow.verdict ?? null)

  useEffect(() => {
    setBreakdown(null)
    setBreakdownError(null)
    apiGet(`/api/flows/${flow.id}/score`)
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
  }, [flow.id, scoredBy?.model_version_id])

  function saveVerdict() {
    setSaving(true)
    setSaveError(null)
    apiPost(`/api/flows/${flow.id}/verdict`, { verdict, note: note || null })
      .then((data) => {
        setSavedVerdict(data)
        onVerdictSaved(flow.id, data)
      })
      .catch((err) => setSaveError(err.message))
      .finally(() => setSaving(false))
  }

  const missedByModel = verdict === 'true_positive' && flow.is_anomalous === false
  const sev = severityBand(flow.anomaly_score, flow.is_anomalous)

  return (
    <div className="space-y-5 rounded-lg border border-border bg-bg-elevated p-4 text-sm">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-md border border-border bg-bg-card px-4 py-3">
        <span className="text-text-muted">
          Score:{' '}
          <span className="font-mono text-base font-semibold text-text-primary">
            {flow.anomaly_score != null ? flow.anomaly_score.toFixed(0) : '-'}
          </span>
        </span>
        <span className="text-text-muted">
          Status:{' '}
          <Badge tone={flow.is_anomalous ? 'red' : 'gray'} critical={sev.critical} dot={false}>
            {flow.is_anomalous ? 'Flagged' : 'Not flagged'}
          </Badge>
        </span>
        <span className="text-text-muted">
          Severity: <Badge tone={sev.tone} critical={sev.critical}>{sev.label}</Badge>
          <span className="ml-2 text-xs text-text-muted">({sev.detail})</span>
        </span>
      </div>

      <div>
        <h3 className="mb-2 font-sans text-sm font-semibold text-text-primary">
          Score breakdown — {scoredBy?.algorithm} ({scoredBy?.variant})
        </h3>
        {breakdownError && <p className="text-accent-red">{breakdownError}</p>}
        {!breakdown && !breakdownError && (
          <div className="space-y-1.5">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-5 w-full" />
            ))}
          </div>
        )}
        {breakdown && (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="border-b border-border text-xs uppercase tracking-wide text-text-muted">
                  <th className="py-1.5 pr-4 font-medium">Feature</th>
                  <th className="py-1.5 pr-4 font-medium">This flow</th>
                  <th className="py-1.5 pr-4 font-medium">Typical baseline</th>
                  <th className="py-1.5 pr-4 font-medium">Contribution</th>
                  <th className="py-1.5 pr-4 font-medium">Direction</th>
                </tr>
              </thead>
              <tbody>
                {breakdown.map((entry) => (
                  <tr key={entry.feature} className="border-b border-border/50">
                    <td className="py-1.5 pr-4 text-text-primary">{featureName(entry.feature)}</td>
                    <td className="py-1.5 pr-4 font-mono text-text-primary">
                      {featureValue(entry.feature, entry.flow_value)}
                    </td>
                    <td className="py-1.5 pr-4 font-mono text-text-muted">
                      {featureValue(entry.feature, entry.baseline_value)}
                    </td>
                    <td
                      className={`py-1.5 pr-4 font-mono ${
                        entry.contribution > 0
                          ? 'text-accent-amber'
                          : entry.contribution < 0
                            ? 'text-accent-green'
                            : 'text-text-muted'
                      }`}
                    >
                      {entry.contribution > 0 ? '+' : ''}
                      {entry.contribution.toFixed(4)}
                    </td>
                    <td className="py-1.5 pr-4 text-text-muted">
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
            <p className="mt-2 text-xs text-text-muted">
              Occlusion-based attribution: each contribution is how much the score would improve
              if this feature were swapped for its typical training value. Indicative, not a
              rigorous Shapley decomposition — correlated features can understate each other.
            </p>
          </div>
        )}
      </div>

      <div className="border-t border-border pt-4">
        <h3 className="mb-2 font-sans text-sm font-semibold text-text-primary">Verdict</h3>
        {canSetVerdict ? (
          <>
            <div className="mb-3 flex flex-wrap gap-2">
              {VERDICT_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setVerdict(opt.value)}
                  className={`rounded border px-2.5 py-1 text-xs font-medium transition-colors ${
                    verdict === opt.value
                      ? 'border-accent-cyan/40 bg-accent-cyan/10 text-accent-cyan'
                      : 'border-border text-text-muted hover:border-accent-cyan/30 hover:text-text-primary'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
            {missedByModel && (
              <p className="mb-3 text-accent-amber">
                This flow was not flagged by the active model (is_anomalous=false) — marking it
                True Positive records it as a missed detection.
              </p>
            )}
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Optional note"
              rows={2}
              className="mb-3 w-full rounded border border-border bg-bg-card px-3 py-2 text-sm text-text-primary placeholder:text-text-muted/60"
            />
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={saveVerdict}
                disabled={saving}
                className="rounded-md bg-accent-cyan px-3 py-1.5 text-xs font-semibold text-bg-page disabled:opacity-50"
              >
                {saving ? 'Saving...' : 'Save verdict'}
              </button>
              {saveError && <span className="text-accent-red">{saveError}</span>}
              {savedVerdict && (
                <Badge key={savedVerdict.updated_at} tone={verdictTone(savedVerdict.verdict)}>
                  {verdictLabel(savedVerdict.verdict)} saved
                </Badge>
              )}
              {savedVerdict && (
                <span className="text-xs text-text-muted">
                  last set by {savedVerdict.created_by} at{' '}
                  {new Date(savedVerdict.updated_at).toLocaleString()}
                </span>
              )}
            </div>
          </>
        ) : savedVerdict ? (
          <div className="flex flex-wrap items-center gap-3">
            <Badge tone={verdictTone(savedVerdict.verdict)}>{verdictLabel(savedVerdict.verdict)}</Badge>
            <span className="text-xs text-text-muted">
              set by {savedVerdict.created_by} at {new Date(savedVerdict.updated_at).toLocaleString()}
            </span>
            {savedVerdict.note && <span className="text-xs text-text-muted">— {savedVerdict.note}</span>}
          </div>
        ) : (
          <p className="text-text-muted">No verdict recorded yet.</p>
        )}
      </div>

      {flow.is_anomalous && <ThreatIntel flow={flow} />}
      {flow.is_anomalous && <Investigation flow={flow} />}
    </div>
  )
}
