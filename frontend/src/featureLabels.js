// Maps the model's internal one-hot feature names to human-readable
// labels/values for the explanation panel, e.g. "Handshake state:
// failed" instead of "handshake_false". Presentation only -- the
// underlying data and math are untouched; this never changes what a
// value IS, only how it's printed.

export const FEATURE_LABELS = {
  duration_seconds: 'Duration',
  packets_per_second: 'Packets/sec',
  bytes_per_second: 'Bytes/sec',
  avg_packet_size: 'Avg packet size',
  packet_count: 'Packet count',
  is_bidirectional: 'Bidirectional',
  handshake_true: 'Handshake state: completed',
  handshake_false: 'Handshake state: failed',
  handshake_not_applicable: 'Handshake state: N/A (non-TCP)',
  close_fin_fin: 'Closed via: FIN/FIN',
  close_rst: 'Closed via: RST',
  close_timeout: 'Closed via: timeout',
  close_eof: 'Closed via: EOF',
}

const BOOLEAN_FEATURES = new Set([
  'is_bidirectional',
  'handshake_true',
  'handshake_false',
  'handshake_not_applicable',
  'close_fin_fin',
  'close_rst',
  'close_timeout',
  'close_eof',
])

const UNITS = {
  duration_seconds: 's',
  packets_per_second: '/s',
  bytes_per_second: 'B/s',
  avg_packet_size: 'B',
  packet_count: '',
}

export function featureName(feature) {
  return FEATURE_LABELS[feature] ?? feature
}

export function featureValue(feature, value) {
  if (value == null) return '—'
  if (BOOLEAN_FEATURES.has(feature)) return value >= 0.5 ? 'True' : 'False'
  const unit = UNITS[feature] ?? ''
  return `${Number(value).toFixed(2)}${unit}`
}
