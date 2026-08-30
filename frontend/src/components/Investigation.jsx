import { useEffect, useState } from 'react'
import { apiPost } from '../api'
import { useAuth } from '../auth/AuthContext'
import Badge from './ui/Badge'
import ConfidenceBar from './ui/ConfidenceBar'
import Skeleton from './ui/Skeleton'

function chunkText(retrievedChunks, chunkId) {
  return retrievedChunks.find((c) => c.id === chunkId)?.text ?? null
}

// The LLM's own prose and the RAG corpus's source markdown both use
// `code` spans and **bold** -- rendered as plain text, the literal
// backticks/asterisks were showing up on screen (e.g. "**this
// generalises**"), which read as broken/unfinished. This renders just
// those two inline markdown forms as real elements, nothing more (no
// full markdown parser, no new dependency).
//
// Code spans are extracted FIRST, as their own pass -- the source
// corpus sometimes combines the two markers as **`code`**, and a
// single combined regex mismatches on that (the `**` alternative wins
// and swallows the backticks as literal characters, since backticks
// aren't excluded from its character class). Splitting on backticks
// first is unambiguous; whatever bold-marker asterisks are left
// stranded around an extracted code span (no longer able to find their
// pair) are cleaned up as harmless leftovers, not left visible.
function renderInline(text) {
  if (!text) return text
  const codeSplit = text.split(/(`[^`]+`)/g)
  return codeSplit.flatMap((segment, i) => {
    if (segment.length > 1 && segment.startsWith('`') && segment.endsWith('`')) {
      return [
        <code
          key={`code-${i}`}
          className="rounded bg-bg-elevated px-1 py-0.5 font-mono text-[0.85em] text-accent-cyan"
        >
          {segment.slice(1, -1)}
        </code>,
      ]
    }
    return segment.split(/(\*\*[^*]+\*\*)/g).map((part, j) => {
      if (part.length > 4 && part.startsWith('**') && part.endsWith('**')) {
        return (
          <strong key={`bold-${i}-${j}`} className="font-semibold text-text-primary">
            {part.slice(2, -2)}
          </strong>
        )
      }
      return part.replace(/\*\*/g, '')
    })
  })
}

function SelfCheckBanner({ selfCheck }) {
  const hasIssues =
    !selfCheck.citations_valid ||
    selfCheck.invalid_citations.length > 0 ||
    selfCheck.unsupported_claims.length > 0

  if (!hasIssues) {
    return (
      <div className="rounded-md border border-accent-green/40 bg-accent-green/10 px-3 py-2 text-accent-green">
        Self-check passed — every citation and named technique is backed by a retrieved chunk.
      </div>
    )
  }

  return (
    <div className="rounded-md border border-accent-red/40 bg-accent-red/10 px-3 py-2 text-accent-red">
      <p className="font-semibold">Self-check flagged issues in this investigation:</p>
      {selfCheck.invalid_citations.length > 0 && (
        <p className="mt-1 font-mono text-xs">
          Unsupported citations: {selfCheck.invalid_citations.join(', ')}
        </p>
      )}
      {selfCheck.unsupported_claims.length > 0 && (
        <ul className="mt-1 list-inside list-disc text-xs">
          {selfCheck.unsupported_claims.map((claim, i) => (
            <li key={i}>{claim}</li>
          ))}
        </ul>
      )}
      {selfCheck.notes && <p className="mt-1 text-xs">{selfCheck.notes}</p>}
    </div>
  )
}

export default function Investigation({ flow }) {
  const { role } = useAuth()
  const canRun = role === 'analyst' || role === 'admin'
  const [state, setState] = useState(null)
  const [error, setError] = useState(null)
  const [fetching, setFetching] = useState(false)

  function check(fetchNow) {
    if (fetchNow) setFetching(true)
    setError(null)
    apiPost(`/api/flows/${flow.id}/investigate`, { fetch: fetchNow })
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
    <div className="border-t border-border pt-4">
      <h3 className="mb-2 flex items-center gap-2 font-sans text-sm font-semibold text-text-primary">
        <span className="h-1.5 w-1.5 rounded-full bg-accent-purple" />
        AI Investigation
      </h3>

      {error && <p className="text-accent-red">{error}</p>}
      {!state && !error && (
        <div className="space-y-2">
          <Skeleton className="h-4 w-80" />
          <Skeleton className="h-20 w-full" />
        </div>
      )}

      {state && !state.cached && (
        <div>
          <p className="mb-2 text-text-muted">
            Not yet investigated.
            {canRun
              ? ' Running this calls a free-tier LLM (Groq) three times (classify, explain, self-check), so it only happens on request.'
              : ' Viewing is read-only — running a new investigation requires an analyst or admin.'}
          </p>
          {canRun && (
            <button
              type="button"
              onClick={() => check(true)}
              disabled={fetching}
              className="rounded-md bg-accent-purple px-3 py-1.5 text-xs font-semibold text-bg-page disabled:opacity-50"
            >
              {fetching ? 'Investigating...' : 'Investigate'}
            </button>
          )}
        </div>
      )}

      {state && state.cached && (
        <div className="space-y-3">
          <p className="text-text-muted">
            Classified as{' '}
            <span className="font-mono text-text-primary">{state.classification.anomaly_type}</span>{' '}
            (confidence {state.classification.confidence.toFixed(2)}) —{' '}
            {renderInline(state.classification.reasoning)}
          </p>

          <SelfCheckBanner selfCheck={state.self_check} />

          <div className="rounded-md border border-border bg-bg-card p-3">
            <p className="mb-1.5 font-sans font-semibold text-text-primary">
              {renderInline(state.investigation.summary)}
            </p>
            <p className="mb-3 text-text-muted">{renderInline(state.investigation.detailed_narrative)}</p>
            <ConfidenceBar value={state.investigation.confidence} />
            <p className="mt-2 text-text-muted">
              <span className="font-medium text-text-primary">Recommended action: </span>
              {renderInline(state.investigation.recommended_action)}
            </p>
          </div>

          <div>
            <p className="mb-1.5 text-text-muted">MITRE techniques:</p>
            {state.investigation.mitre_techniques.length === 0 ? (
              <p className="text-text-muted/70">none — no retrieved evidence supported one</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {state.investigation.mitre_techniques.map((t) => (
                  <Badge key={t} tone="purple" dot={false}>
                    <span className="font-mono">{t}</span>
                  </Badge>
                ))}
              </div>
            )}
          </div>

          {state.investigation.citations.length > 0 && (
            <div>
              <p className="mb-1.5 flex items-center gap-1.5 text-text-muted">
                <span className="h-1.5 w-1.5 rounded-full bg-accent-purple" />
                Citations
              </p>
              {/* A purple background tint (not just the left border) is
                  deliberate -- these are quoted evidence, not generated
                  prose, and should read as a visually distinct "evidence"
                  zone against the plain narrative above, not just another
                  card in the same tone. */}
              <ul className="space-y-2">
                {state.investigation.citations.map((c, i) => (
                  <li
                    key={i}
                    className="rounded-md border border-accent-purple/30 border-l-2 border-l-accent-purple bg-accent-purple/[0.06] px-3 py-2"
                  >
                    <div className="font-mono text-xs text-accent-purple-text">{c.source}</div>
                    <div className="mt-0.5 italic text-text-primary">
                      &ldquo;{renderInline(c.excerpt)}&rdquo;
                    </div>
                    {chunkText(state.retrieved_chunks, c.source) && (
                      <div className="mt-1.5 border-t border-border pt-1.5 text-xs text-text-muted">
                        Chunk text: {renderInline(chunkText(state.retrieved_chunks, c.source))}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <p className="font-mono text-xs text-text-muted/70">
            {state.models.classify} / {state.models.explain} / {state.models.self_check} —{' '}
            {new Date(state.fetched_at).toLocaleString()}
          </p>
        </div>
      )}
    </div>
  )
}
