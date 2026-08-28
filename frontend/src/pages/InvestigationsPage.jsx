import { useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import Badge from '../components/ui/Badge'
import Card from '../components/ui/Card'
import Skeleton from '../components/ui/Skeleton'
import Investigation from '../components/Investigation'
import { verdictLabel, verdictTone } from '../severity'

// This list can legitimately be 1000+ rows (the two nmap captures alone
// flag ~2000 flows). Deliberately NOT using the `Card`/motion wrapper
// per row here -- that's fine for a handful of Overview stat cards, but
// mounting a live Framer Motion instance per row at this scale is real,
// measured jank (confirmed: an unpaginated version rendered a
// >118,000px-tall page). Capped to the top-scoring 200, same "most
// interesting slice by default" precedent as the Flows page's own
// default cap -- the full set is still browsable via the Flows page's
// filter/sort.
const DISPLAY_LIMIT = 200

export default function InvestigationsPage({ allFlows, allFlowsLoading }) {
  const [expandedFlowId, setExpandedFlowId] = useState(null)

  const flagged = allFlowsLoading
    ? []
    : [...allFlows].filter((f) => f.is_anomalous).sort((a, b) => (b.anomaly_score ?? 0) - (a.anomaly_score ?? 0))
  const visible = flagged.slice(0, DISPLAY_LIMIT)

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="font-sans text-xl font-bold text-text-primary">Investigations</h2>
        <p className="mt-1 text-sm text-text-muted">
          Flows flagged by the active model, sorted by anomaly score. Expand one to view or run
          its AI-generated investigation.
        </p>
      </div>

      {allFlowsLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : flagged.length === 0 ? (
        <Card>
          <p className="text-text-muted">No flows are currently flagged by the active model.</p>
        </Card>
      ) : (
        <div className="flex flex-col gap-2">
          <p className="text-xs text-text-muted">
            {flagged.length > DISPLAY_LIMIT
              ? `Showing the top ${DISPLAY_LIMIT} of ${flagged.length} flagged flows by score — use the Flows page to filter/browse the rest.`
              : `${flagged.length} flagged flows`}
          </p>
          {visible.map((flow) => {
            const isExpanded = expandedFlowId === flow.id
            return (
              <div key={flow.id} className="rounded-lg border border-border bg-bg-card">
                <button
                  type="button"
                  onClick={() => setExpandedFlowId(isExpanded ? null : flow.id)}
                  className="flex w-full flex-wrap items-center gap-4 px-4 py-3 text-left"
                >
                  <span className="font-mono text-text-muted">{isExpanded ? '▾' : '▸'}</span>
                  <span className="font-mono text-text-primary">
                    {flow.src_ip}:{flow.src_port ?? '-'}
                  </span>
                  <span className="text-text-muted">→</span>
                  <span className="font-mono text-text-primary">
                    {flow.dst_ip}:{flow.dst_port ?? '-'}
                  </span>
                  <span className="font-mono text-xs text-text-muted">{flow.protocol}</span>
                  <span className="font-mono text-sm font-medium text-text-primary">
                    {flow.anomaly_score?.toFixed(0)}
                  </span>
                  {/* Every row on this page is already "High" severity by
                      definition (that's the page's own filter) -- repeating
                      that badge 200 times added visual noise, not signal,
                      and most of them would pulse simultaneously as
                      "critical". The verdict, where one exists, is the
                      genuinely differentiating thing to show here. */}
                  {flow.verdict && (
                    <Badge tone={verdictTone(flow.verdict.value)}>{verdictLabel(flow.verdict.value)}</Badge>
                  )}
                  <span className="ml-auto font-mono text-xs text-text-muted">{flow.source_file}</span>
                </button>
                <AnimatePresence initial={false}>
                  {isExpanded && (
                    <motion.div
                      key="detail"
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.22, ease: 'easeInOut' }}
                      className="overflow-hidden"
                    >
                      <div className="border-t border-border px-4 pb-4 pt-1">
                        <Investigation flow={flow} />
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
