// Severity is a DERIVED convenience label over the model's anomaly_score
// (0-100) -- it is not a separate measurement. `is_anomalous` (the
// model's actual flagged/not-flagged call) is always authoritative;
// these cutoffs only bucket the score for a quicker read and are
// deliberately arbitrary, named here in one place, and easy to change.
//
// Copy stays to "unusual" / "elevated" / "flagged" -- never "malicious"
// or "attack" -- per docs/PROJECT.md's language-discipline rule.
//
// `tone` maps to Badge.jsx's color tokens (docs/PROJECT.md §20's locked
// accent scale) -- this file no longer hardcodes Tailwind color classes
// itself, so there is exactly one place (Badge.jsx) that turns a tone
// into actual styling.

const ELEVATED_CUTOFF = 85
const MEDIUM_CUTOFF = 50
// "Critical" (the pulsing red state, §20) = flagged AND near-certain,
// not a new label -- an extra treatment layered on the existing High
// badge. Chosen as a judgment call, flagged in the Phase 8 plan.
const CRITICAL_CUTOFF = 95

export function severityBand(anomalyScore, isAnomalous) {
  if (isAnomalous) {
    return {
      label: 'High',
      detail: 'flagged by the active model',
      tone: 'red',
      critical: anomalyScore != null && anomalyScore >= CRITICAL_CUTOFF,
    }
  }
  if (anomalyScore != null && anomalyScore >= ELEVATED_CUTOFF) {
    return {
      label: 'Elevated',
      detail: "not flagged — near the model's threshold",
      tone: 'amber',
      critical: false,
    }
  }
  if (anomalyScore != null && anomalyScore >= MEDIUM_CUTOFF) {
    return {
      label: 'Medium',
      detail: 'somewhat unusual',
      tone: 'amber',
      critical: false,
    }
  }
  if (anomalyScore == null) {
    return {
      label: 'Unscored',
      detail: 'no model has scored this flow yet',
      tone: 'gray',
      critical: false,
    }
  }
  return {
    label: 'Low',
    detail: 'within the ordinary range',
    tone: 'green',
    critical: false,
  }
}

// Verdict badges: TP = a confirmed real anomaly (red, matches High
// severity); FP = the model was wrong, this traffic is fine but the
// mismatch is worth an analyst's attention (amber); benign = confirmed
// fine (green); unknown = not yet judged (gray, §20's locked UNKNOWN
// color).
const VERDICT_TONE = {
  true_positive: 'red',
  false_positive: 'amber',
  benign: 'green',
  unknown: 'gray',
}

const VERDICT_LABEL = {
  true_positive: 'TP',
  false_positive: 'FP',
  benign: 'Benign',
  unknown: 'Unknown',
}

export function verdictTone(value) {
  return VERDICT_TONE[value] ?? 'gray'
}

export function verdictLabel(value) {
  return VERDICT_LABEL[value] ?? value
}
