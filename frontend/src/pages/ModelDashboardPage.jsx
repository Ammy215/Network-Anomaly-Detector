import Badge from '../components/ui/Badge'
import Card from '../components/ui/Card'
import Skeleton from '../components/ui/Skeleton'

// Human labels for the model_versions.metrics jsonb -- presentation
// only, values are rendered exactly as stored (see docs/ML-MODEL-NOTES.md
// for what each number means and its known limitations).
const METRIC_LABELS = {
  f1: 'F1 score',
  recall: 'Recall',
  precision: 'Precision',
  roc_auc: 'ROC-AUC',
  average_precision: 'Average precision',
  false_positive_rate: 'False positive rate',
  fpr_on_heldout_normals: 'FPR (held-out normals)',
  fpr_on_training_normals_CIRCULAR: 'FPR (training normals — circular, not a holdout metric)',
  precision_at_1pct_base_rate: 'Precision @ 1% base rate',
  inference_ms_per_1000_flows: 'Inference (ms / 1000 flows)',
  train_flows: 'Training flows (this metric)',
  validation_flows: 'Validation flows',
  scan_flows_evaluated: 'Scan flows evaluated',
  scan_flows_labelled_positive: 'Scan flows labelled positive',
  true_positives: 'True positives',
  true_negatives: 'True negatives',
  false_positives: 'False positives',
  false_negatives: 'False negatives',
}

function formatMetric(value) {
  if (typeof value === 'number') {
    return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(4)
  }
  return String(value)
}

// The 5 headline "higher is better" quality scores (all genuinely 0-1)
// get a small bar under the number so they're scannable at a glance
// instead of requiring you to read and compare five separate 4-decimal
// numbers. Deliberately NOT applied to the FPR/count metrics below --
// those are either "lower is better" (a long bar would visually read
// as good when it isn't) or not a 0-1 ratio at all.
const RATIO_METRIC_KEYS = new Set(['f1', 'recall', 'precision', 'roc_auc', 'average_precision'])

function MetricCell({ metricKey, value }) {
  const isRatio = RATIO_METRIC_KEYS.has(metricKey) && typeof value === 'number'
  return (
    <div>
      <div className="text-xs text-text-muted">{METRIC_LABELS[metricKey] ?? metricKey}</div>
      <div className="font-mono text-sm text-text-primary">{formatMetric(value)}</div>
      {isRatio && (
        <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-bg-elevated">
          <div
            className="h-full rounded-full bg-accent-cyan"
            style={{ width: `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%` }}
          />
        </div>
      )}
    </div>
  )
}

function ModelCard({ model, active }) {
  return (
    <Card className={active ? 'border-accent-cyan/40' : undefined}>
      <div className="mb-2 flex items-center gap-2">
        <span className="font-mono text-base font-semibold text-text-primary">
          {model.algorithm}
        </span>
        <span className="font-mono text-sm text-text-muted">({model.variant})</span>
        {active && <Badge tone="cyan">active</Badge>}
      </div>
      {/* Label-above-value, same convention as the metrics grid below and
          StatCard elsewhere in the app -- the previous side-by-side dt/dd
          columns read as an unstyled form and didn't match how every other
          label+value pair in this app is presented. */}
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
        <div>
          <dt className="text-xs text-text-muted">Threshold</dt>
          <dd className="font-mono text-sm text-text-primary">{model.threshold.toFixed(4)}</dd>
        </div>
        <div className="col-span-2 sm:col-span-2">
          <dt className="text-xs text-text-muted">Threshold strategy</dt>
          <dd className="text-sm text-text-primary">{model.threshold_strategy}</dd>
        </div>
        <div>
          <dt className="text-xs text-text-muted">Training set size</dt>
          <dd className="font-mono text-sm text-text-primary">{model.training_set_size}</dd>
        </div>
        <div>
          <dt className="text-xs text-text-muted">Trained</dt>
          <dd className="text-sm text-text-primary">{new Date(model.created_at).toLocaleString()}</dd>
        </div>
      </dl>
    </Card>
  )
}

export default function ModelDashboardPage({ models }) {
  if (!models) {
    return (
      <div className="flex flex-col gap-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-40 w-full" />
      </div>
    )
  }

  const active = models.find((m) => m.is_active) ?? null
  const scalarMetrics = active
    ? Object.entries(active.metrics).filter(([, v]) => typeof v === 'number' || typeof v === 'string')
    : []

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="font-sans text-xl font-bold text-text-primary">Model dashboard</h2>
        <p className="mt-1 text-sm text-text-muted">
          The model actually shipped to score flows, its measured performance, and every other
          trained version for comparison — all read directly from the model registry.
        </p>
      </div>

      {active ? (
        <ModelCard model={active} active />
      ) : (
        <Card>
          <p className="text-accent-amber">No model is currently marked active.</p>
        </Card>
      )}

      {active && (
        <Card delay={0.05}>
          <h3 className="mb-3 font-sans text-sm font-semibold text-text-primary">
            Measured performance — {active.algorithm} ({active.variant})
          </h3>
          <div className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3 lg:grid-cols-4">
            {scalarMetrics.map(([key, value]) => (
              <MetricCell key={key} metricKey={key} value={value} />
            ))}
          </div>
          <p className="mt-3 text-xs text-text-muted">
            Nested breakdowns (per-capture generalisation, threshold sweep) live in
            docs/ML-MODEL-NOTES.md, not duplicated here.
          </p>
        </Card>
      )}

      <Card delay={0.1} className="overflow-x-auto !p-0">
        <table className="w-full border-collapse text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wide text-text-muted">
              <th className="px-3 py-2 font-medium">Algorithm</th>
              <th className="px-3 py-2 font-medium">Variant</th>
              <th className="px-3 py-2 font-medium">Threshold</th>
              <th className="px-3 py-2 font-medium">Trained</th>
              <th className="px-3 py-2 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {models.map((m) => (
              <tr key={m.id} className="border-b border-border/50">
                <td className="px-3 py-2 font-mono text-text-primary">{m.algorithm}</td>
                <td className="px-3 py-2 font-mono text-text-muted">{m.variant}</td>
                <td className="px-3 py-2 font-mono text-text-muted">{m.threshold.toFixed(4)}</td>
                <td className="px-3 py-2 text-text-muted">
                  {new Date(m.created_at).toLocaleDateString()}
                </td>
                <td className="px-3 py-2">
                  {m.is_active ? <Badge tone="cyan">active</Badge> : <span className="text-text-muted">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  )
}
