// Severity is a DERIVED convenience label over the model's anomaly_score
// (0-100) -- it is not a separate measurement. `is_anomalous` (the
// model's actual flagged/not-flagged call) is always authoritative;
// these cutoffs only bucket the score for a quicker read and are
// deliberately arbitrary, named here in one place, and easy to change.
//
// Copy stays to "unusual" / "elevated" / "flagged" -- never "malicious"
// or "attack" -- per docs/PROJECT.md's language-discipline rule.

const ELEVATED_CUTOFF = 85
const MEDIUM_CUTOFF = 50

export function severityBand(anomalyScore, isAnomalous) {
  if (isAnomalous) {
    return {
      label: 'High',
      detail: 'flagged by the active model',
      color: 'text-red-400',
      badgeClass: 'bg-red-950 text-red-400 border-red-800',
    }
  }
  if (anomalyScore != null && anomalyScore >= ELEVATED_CUTOFF) {
    return {
      label: 'Elevated',
      detail: 'not flagged — near the model\'s threshold',
      color: 'text-amber-400',
      badgeClass: 'bg-amber-950 text-amber-400 border-amber-800',
    }
  }
  if (anomalyScore != null && anomalyScore >= MEDIUM_CUTOFF) {
    return {
      label: 'Medium',
      detail: 'somewhat unusual',
      color: 'text-amber-500',
      badgeClass: 'bg-amber-950/60 text-amber-500 border-amber-900',
    }
  }
  if (anomalyScore == null) {
    return {
      label: 'Unscored',
      detail: 'no model has scored this flow yet',
      color: 'text-slate-500',
      badgeClass: 'bg-slate-900 text-slate-500 border-slate-800',
    }
  }
  return {
    label: 'Low',
    detail: 'within the ordinary range',
    color: 'text-green-400',
    badgeClass: 'bg-green-950 text-green-400 border-green-800',
  }
}
