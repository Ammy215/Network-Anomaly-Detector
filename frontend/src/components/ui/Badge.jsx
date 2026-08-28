import { motion } from 'motion/react'

// Single source of truth for tone -> color mapping. Text colors use the
// lighter purple/gray tints (see index.css) where the raw locked accent
// hex doesn't clear 4.5:1 on card/elevated backgrounds -- backgrounds,
// borders, and dots keep the real accent hex.
const TONE_STYLES = {
  cyan: { bg: 'bg-accent-cyan/10', border: 'border-accent-cyan/40', text: 'text-accent-cyan', dot: 'bg-accent-cyan' },
  green: { bg: 'bg-accent-green/10', border: 'border-accent-green/40', text: 'text-accent-green', dot: 'bg-accent-green' },
  amber: { bg: 'bg-accent-amber/10', border: 'border-accent-amber/40', text: 'text-accent-amber', dot: 'bg-accent-amber' },
  red: { bg: 'bg-accent-red/10', border: 'border-accent-red/40', text: 'text-accent-red', dot: 'bg-accent-red' },
  purple: { bg: 'bg-accent-purple/10', border: 'border-accent-purple/40', text: 'text-accent-purple-text', dot: 'bg-accent-purple' },
  gray: { bg: 'bg-accent-gray/10', border: 'border-accent-gray/40', text: 'text-accent-gray-text', dot: 'bg-accent-gray' },
}

// `critical` adds the pulse loop (docs/PROJECT.md §20: red + pulse on
// critical). Give the badge a `key` that changes when its underlying
// value changes (e.g. a verdict save) to replay the mount-in animation
// as a "confirmed" moment -- that's a caller decision, not this
// component's, so it stays reusable.
export default function Badge({ tone = 'gray', critical = false, dot = true, title, children }) {
  const s = TONE_STYLES[tone] ?? TONE_STYLES.gray
  return (
    <motion.span
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.2 }}
      title={title}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded border px-2 py-0.5 text-xs font-medium ${s.bg} ${s.border} ${s.text} ${critical ? 'animate-critical-pulse' : ''}`}
    >
      {dot && <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${s.dot}`} />}
      {children}
    </motion.span>
  )
}
