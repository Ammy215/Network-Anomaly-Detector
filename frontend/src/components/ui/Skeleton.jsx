// A pulsing block standing in for real content while it loads --
// per the Phase 8 spec: skeleton loaders, not spinners.
export default function Skeleton({ className = '' }) {
  return <div className={`animate-pulse rounded bg-bg-elevated ${className}`} />
}
