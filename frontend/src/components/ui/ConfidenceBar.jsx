import { motion } from 'motion/react'

// The purple AI-feature accent, animating its width in once on mount --
// the one motion moment the Investigation panel gets, per the Phase 8
// spec ("the confidence indicator animating in").
export default function ConfidenceBar({ value, label = 'Confidence' }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100)
  return (
    <div className="flex items-center gap-2">
      <span className="whitespace-nowrap text-xs text-text-muted">{label}</span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-bg-elevated">
        <motion.div
          className="h-full rounded-full bg-accent-purple"
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.5, ease: 'easeOut' }}
        />
      </div>
      <span className="w-10 text-right font-mono text-xs text-accent-purple-text">{pct}%</span>
    </div>
  )
}
