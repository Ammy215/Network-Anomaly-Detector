export default function VerdictSummary({ summary }) {
  if (!summary) return null

  return (
    <div className="rounded-md border border-slate-800 bg-slate-900 px-4 py-3 text-sm font-mono flex flex-wrap items-center gap-x-6 gap-y-2">
      <span className="text-slate-400">Verdicts:</span>
      <span>
        TP <span className="text-slate-100">{summary.true_positive}</span>
      </span>
      <span>
        FP <span className="text-slate-100">{summary.false_positive}</span>
      </span>
      <span>
        Benign <span className="text-slate-100">{summary.benign}</span>
      </span>
      <span>
        Unknown <span className="text-slate-100">{summary.unknown}</span>
      </span>
      <span className="text-slate-500">
        Not yet verdicted <span className="text-slate-300">{summary.not_verdicted}</span>
      </span>
      {summary.missed_by_model > 0 && (
        <span className="text-amber-400">
          {summary.missed_by_model} confirmed anomalous but not flagged by the active model
        </span>
      )}
      <span className="w-full text-xs text-slate-600">
        Recorded for review only. Never used to automatically retrain the model or adjust its
        threshold.
      </span>
    </div>
  )
}
