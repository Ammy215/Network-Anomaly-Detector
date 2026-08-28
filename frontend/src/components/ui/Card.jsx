import { motion } from 'motion/react'

// The one entrance animation used across the dashboard -- a card fades
// and lifts in on mount. `delay` lets a grid of cards (Overview's
// StatCards) stagger slightly instead of popping in simultaneously.
export default function Card({ children, className = '', delay = 0, ...props }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, delay, ease: 'easeOut' }}
      className={`rounded-lg border border-border bg-bg-card p-4 ${className}`}
      {...props}
    >
      {children}
    </motion.div>
  )
}
