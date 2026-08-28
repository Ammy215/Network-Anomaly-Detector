import { Fragment, useEffect, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { apiGet } from '../api'
import Badge from '../components/ui/Badge'
import Card from '../components/ui/Card'
import Skeleton from '../components/ui/Skeleton'
import FlowDetailPanel from '../components/FlowDetailPanel'
import { severityBand, verdictLabel, verdictTone } from '../severity'

function VerdictBadge({ flow }) {
  if (!flow.verdict) {
    return <span className="text-text-muted">—</span>
  }
  const missed = flow.verdict.value === 'true_positive' && flow.is_anomalous === false
  return (
    <div className="flex items-center gap-1.5">
      <Badge key={flow.verdict.updated_at ?? flow.verdict.value} tone={verdictTone(flow.verdict.value)}>
        {verdictLabel(flow.verdict.value)}
      </Badge>
      {missed && <span className="text-xs text-accent-amber">missed</span>}
    </div>
  )
}

const COLUMNS = [
  '#', 'Source', 'Destination', 'Dst Port', 'Protocol', 'Packets', 'Bytes',
  'PPS', 'Avg Size', 'Close', 'Score', 'Severity', 'Top Contributing Features',
  'Started', 'Verdict',
]

export default function FlowsPage() {
  const [flows, setFlows] = useState([])
  const [loading, setLoading] = useState(true)
  const [flowsError, setFlowsError] = useState(null)
  const [scoredBy, setScoredBy] = useState(null)

  const [expandedFlowId, setExpandedFlowId] = useState(null)
  const [sourceFiles, setSourceFiles] = useState([])
  const [sourceFileFilter, setSourceFileFilter] = useState('')
  const [scoreSort, setScoreSort] = useState('started_desc')

  function loadFlows() {
    setFlowsError(null)
    const params = new URLSearchParams()
    if (sourceFileFilter) params.set('source_file', sourceFileFilter)
    if (scoreSort !== 'started_desc') params.set('sort', scoreSort)
    apiGet(`/api/flows?${params.toString()}`)
      .then((data) => {
        setFlows(data.flows)
        setScoredBy(data.scored_by)
      })
      .catch((err) => setFlowsError(err.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    apiGet('/api/flows/source-files')
      .then((data) => setSourceFiles(data.source_files))
      .catch(() => setSourceFiles([]))
  }, [])

  useEffect(() => {
    setLoading(true)
    loadFlows()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceFileFilter, scoreSort])

  function handleVerdictSaved(flowId, verdictRow) {
    setFlows((prev) =>
      prev.map((flow) =>
        flow.id === flowId
          ? {
              ...flow,
              verdict: {
                value: verdictRow.verdict,
                note: verdictRow.note,
                created_by: verdictRow.created_by,
                created_at: verdictRow.created_at,
                updated_at: verdictRow.updated_at,
              },
            }
          : flow
      )
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="font-sans text-xl font-bold text-text-primary">Flows</h2>
        <p className="mt-1 text-sm text-text-muted">
          Every captured flow, scored by the active model. Filter or sort by score to search
          beyond the default most-recent view.
        </p>
      </div>

      <Card className="flex flex-wrap items-center gap-4 !py-3">
        <label className="flex items-center gap-2 text-sm text-text-muted">
          Source file
          <select
            value={sourceFileFilter}
            onChange={(e) => setSourceFileFilter(e.target.value)}
            className="rounded border border-border bg-bg-elevated px-2 py-1 font-mono text-sm text-text-primary"
          >
            <option value="">All</option>
            {sourceFiles.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-text-muted">
          Sort by score
          <select
            value={scoreSort}
            onChange={(e) => setScoreSort(e.target.value)}
            className="rounded border border-border bg-bg-elevated px-2 py-1 font-mono text-sm text-text-primary"
          >
            <option value="started_desc">Newest first (default)</option>
            <option value="score_desc">Score: high to low</option>
            <option value="score_asc">Score: low to high</option>
          </select>
        </label>
        {(sourceFileFilter || scoreSort !== 'started_desc') && (
          <span className="text-sm text-text-muted">{flows.length} flows shown</span>
        )}
        {scoredBy && (
          <span className="font-mono text-xs text-text-muted">
            scores from {scoredBy.algorithm} ({scoredBy.variant}), threshold{' '}
            {scoredBy.threshold.toFixed(4)}
          </span>
        )}
      </Card>

      {flowsError && <p className="text-sm text-accent-red">{flowsError}</p>}

      {/* [container-type:inline-size] + the expanded row's `w-[100cqw]` below
          is the fix for a real bug: this table's 15 columns are wider than
          the viewport, so this Card scrolls horizontally. Without this, the
          expanded FlowDetailPanel -- which doesn't need that width -- was
          silently inheriting the table's full scrolled-content width and
          getting clipped at the viewport edge (e.g. the score breakdown's
          "Direction" column was invisible without scrolling right). Pinning
          it to the container's actual visible inline size fixes that. */}
      <Card className="overflow-x-auto !p-0 [container-type:inline-size]" delay={0.05}>
        <table className="w-full border-collapse text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wide text-text-muted">
              {COLUMNS.map((col) => (
                <th key={col} className="whitespace-nowrap px-3 py-2 font-medium">
                  {col === 'Score' && scoredBy ? `${col} (${scoredBy.algorithm})` : col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 8 }).map((_, i) => (
                <tr key={i} className="border-b border-border/60">
                  {COLUMNS.map((col) => (
                    <td key={col} className="px-3 py-2">
                      <Skeleton className="h-4 w-16" />
                    </td>
                  ))}
                </tr>
              ))
            ) : flows.length === 0 ? (
              <tr>
                <td colSpan={COLUMNS.length} className="px-3 py-6 text-center text-text-muted">
                  No flows yet — upload a .pcap to see results.
                </td>
              </tr>
            ) : (
              flows.map((flow) => {
                const sev = severityBand(flow.anomaly_score, flow.is_anomalous)
                const isExpanded = expandedFlowId === flow.id
                return (
                  <Fragment key={flow.id}>
                    <tr className="border-b border-border/60 hover:bg-bg-elevated/40">
                      <td className="px-3 py-2 text-text-muted">
                        <button
                          type="button"
                          onClick={() => setExpandedFlowId(isExpanded ? null : flow.id)}
                          className="font-mono hover:text-accent-cyan"
                        >
                          {isExpanded ? '▾' : '▸'} {flow.seq}
                        </button>
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-text-primary">
                        {flow.src_ip}:{flow.src_port ?? '-'}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-text-primary">
                        {flow.dst_ip}:{flow.dst_port ?? '-'}
                      </td>
                      <td className="px-3 py-2 font-mono text-text-primary">{flow.dst_port ?? '-'}</td>
                      <td className="px-3 py-2 font-mono text-text-muted">{flow.protocol}</td>
                      <td className="px-3 py-2 font-mono text-text-muted">{flow.packet_count}</td>
                      <td className="px-3 py-2 font-mono text-text-muted">{flow.byte_count}</td>
                      <td className="px-3 py-2 font-mono text-text-muted">
                        {flow.packets_per_second?.toFixed(1) ?? '-'}
                      </td>
                      <td className="px-3 py-2 font-mono text-text-muted">
                        {flow.avg_packet_size?.toFixed(0) ?? '-'}
                      </td>
                      <td className="px-3 py-2 font-mono text-text-muted">{flow.close_type ?? '-'}</td>
                      <td className="px-3 py-2 font-mono font-medium text-text-primary">
                        {flow.anomaly_score != null ? flow.anomaly_score.toFixed(0) : '-'}
                      </td>
                      <td className="px-3 py-2">
                        <Badge tone={sev.tone} critical={sev.critical} title={sev.detail}>
                          {sev.label}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-text-muted">
                        {flow.top_features?.length
                          ? flow.top_features
                              .filter((f) => f.contribution > 0)
                              .slice(0, 3)
                              .map((f) => f.feature)
                              .join(', ') || '-'
                          : '-'}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-text-muted">
                        {new Date(flow.started_at).toLocaleString()}
                      </td>
                      <td className="px-3 py-2">
                        <VerdictBadge flow={flow} />
                      </td>
                    </tr>
                    <AnimatePresence initial={false}>
                      {isExpanded && (
                        <tr key="detail" className="border-b border-border/60">
                          <td colSpan={COLUMNS.length} className="bg-bg-page/40 p-0">
                            {/* The sticky/cqw wrapper stays OUTSIDE the
                                height-animated motion.div deliberately --
                                overflow:hidden (needed to clip the height
                                animation) creates a new sticky containing
                                block for anything nested inside it, which
                                would silently break the horizontal-scroll
                                clipping fix from the last review round.
                                Keeping `sticky` as the direct child of `td`
                                means its nearest scrolling ancestor stays the
                                Card below, unaffected by the animation
                                wrapper nested inside it. */}
                            <div className="sticky left-0 w-[100cqw]">
                              <motion.div
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: 'auto', opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                transition={{ duration: 0.22, ease: 'easeInOut' }}
                                className="overflow-hidden"
                              >
                                <div className="px-3 py-4">
                                  <FlowDetailPanel
                                    flow={flow}
                                    scoredBy={scoredBy}
                                    onVerdictSaved={handleVerdictSaved}
                                  />
                                </div>
                              </motion.div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </AnimatePresence>
                  </Fragment>
                )
              })
            )}
          </tbody>
        </table>
      </Card>
    </div>
  )
}
