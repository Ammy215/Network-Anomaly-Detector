import Card from './Card'

const TONE_TEXT = {
  cyan: 'text-accent-cyan',
  red: 'text-accent-red',
  amber: 'text-accent-amber',
  green: 'text-accent-green',
  purple: 'text-accent-purple-text',
  primary: 'text-text-primary',
}

export default function StatCard({ label, value, sublabel, delay = 0, tone = 'primary' }) {
  return (
    <Card delay={delay} className="flex flex-col gap-1">
      <span className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</span>
      <span className={`font-sans text-3xl font-bold ${TONE_TEXT[tone] ?? TONE_TEXT.primary}`}>
        {value}
      </span>
      {sublabel && <span className="text-xs text-text-muted">{sublabel}</span>}
    </Card>
  )
}
