import { useEffect, useState } from 'react'
import { apiGet } from '../api'
import Badge from '../components/ui/Badge'
import Card from '../components/ui/Card'
import Skeleton from '../components/ui/Skeleton'
import StatCard from '../components/ui/StatCard'
import { verdictLabel, verdictTone } from '../severity'

const VERDICT_KEYS = ['true_positive', 'false_positive', 'benign', 'unknown']

const INTEGRATION_LABELS = {
  mini_siem: 'Mini SIEM',
  threathunter: 'ThreatHunter',
}

function IntegrationsCard() {
  const [status, setStatus] = useState(null)

  useEffect(() => {
    apiGet('/api/integrations/status')
      .then(setStatus)
      .catch(() => setStatus(null))
  }, [])

  return (
    <Card delay={0.25}>
      <h3 className="mb-3 font-sans text-sm font-semibold text-text-primary">Integrations</h3>
      {!status ? (
        <Skeleton className="h-8 w-full" />
      ) : (
        <div className="flex flex-wrap items-center gap-3">
          {Object.entries(INTEGRATION_LABELS).map(([key, label]) => {
            const enabled = Boolean(status[key]?.enabled)
            return (
              <div key={key} className="flex items-center gap-2">
                <Badge
                  tone={enabled ? 'green' : 'gray'}
                  title={
                    enabled
                      ? 'Configured — delivery on flag/verdict is best-effort, not a confirmed live connection.'
                      : 'Not configured — set the corresponding URL in backend/.env to enable.'
                  }
                >
                  {enabled ? 'Configured' : 'Not configured'}
                </Badge>
                <span className="text-text-primary">{label}</span>
              </div>
            )
          })}
        </div>
      )}
      <p className="mt-3 text-xs text-text-muted">
        Optional, loosely coupled — NetSentinel works the same whether either is configured. See
        docs/INTEGRATIONS.md for the event/request schemas.
      </p>
    </Card>
  )
}

export default function OverviewPage({ allFlows, allFlowsLoading, verdictSummary, activeModel }) {
  const flaggedCount = allFlowsLoading ? null : allFlows.filter((f) => f.is_anomalous).length

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="font-sans text-xl font-bold text-text-primary">Overview</h2>
        <p className="mt-1 text-sm text-text-muted">
          Real-time summary across every captured flow and the currently active detection model.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Total flows"
          value={verdictSummary ? verdictSummary.total_flows.toLocaleString() : <Skeleton className="h-9 w-20" />}
          tone="cyan"
        />
        <StatCard
          label="Flagged by active model"
          value={flaggedCount != null ? flaggedCount.toLocaleString() : <Skeleton className="h-9 w-20" />}
          sublabel={
            flaggedCount != null && verdictSummary
              ? `${((flaggedCount / Math.max(verdictSummary.total_flows, 1)) * 100).toFixed(1)}% of all flows`
              : undefined
          }
          tone="red"
          delay={0.05}
        />
        <StatCard
          label="Not yet verdicted"
          value={verdictSummary ? verdictSummary.not_verdicted.toLocaleString() : <Skeleton className="h-9 w-20" />}
          tone="amber"
          delay={0.1}
        />
        <StatCard
          label="Active model"
          value={
            activeModel ? (
              <span className="font-mono text-2xl">{activeModel.algorithm}</span>
            ) : (
              <Skeleton className="h-9 w-32" />
            )
          }
          sublabel={activeModel ? `variant: ${activeModel.variant}` : undefined}
          tone="purple"
          delay={0.15}
        />
      </div>

      <Card delay={0.2}>
        <h3 className="mb-3 font-sans text-sm font-semibold text-text-primary">Verdict breakdown</h3>
        {!verdictSummary ? (
          <Skeleton className="h-8 w-full" />
        ) : (
          <div className="flex flex-wrap items-center gap-3">
            {VERDICT_KEYS.map((key) => (
              <div key={key} className="flex items-center gap-2">
                <Badge tone={verdictTone(key)}>{verdictLabel(key)}</Badge>
                <span className="font-mono text-text-primary">{verdictSummary[key]}</span>
              </div>
            ))}
            {verdictSummary.missed_by_model > 0 && (
              <span className="ml-2 text-accent-amber">
                {verdictSummary.missed_by_model} confirmed anomalous but not flagged by the active
                model
              </span>
            )}
          </div>
        )}
        <p className="mt-3 text-xs text-text-muted">
          Recorded for review only. Never used to automatically retrain the model or adjust its
          threshold.
        </p>
      </Card>

      <IntegrationsCard />
    </div>
  )
}
