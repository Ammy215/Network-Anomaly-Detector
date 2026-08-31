import { useState } from 'react'
import { useAuth } from '../auth/AuthContext'

export default function AuthScreen() {
  const { signIn, signUp } = useAuth()
  const [mode, setMode] = useState('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [info, setInfo] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError(null)
    setInfo(null)
    setSubmitting(true)
    try {
      if (mode === 'login') {
        const { error: err } = await signIn(email, password)
        if (err) throw err
      } else {
        const { error: err, data } = await signUp(email, password)
        if (err) throw err
        if (!data.session) {
          setInfo('Account created — check your email to confirm it, then sign in.')
          setMode('login')
        }
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-page px-4">
      <div className="w-full max-w-sm rounded-lg border border-border bg-bg-card p-6">
        <h1 className="mb-1 font-sans text-xl font-bold text-text-primary">NetSentinel</h1>
        <p className="mb-6 text-sm text-text-muted">
          {mode === 'login' ? 'Sign in to continue.' : 'Create an account (new accounts start as viewer).'}
        </p>

        <form onSubmit={handleSubmit} className="flex flex-col gap-3">
          <label className="flex flex-col gap-1 text-sm text-text-muted">
            Email
            <input
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="rounded border border-border bg-bg-elevated px-3 py-2 text-sm text-text-primary"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm text-text-muted">
            Password
            <input
              type="password"
              required
              minLength={6}
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="rounded border border-border bg-bg-elevated px-3 py-2 text-sm text-text-primary"
            />
          </label>

          {error && <p className="text-sm text-accent-red">{error}</p>}
          {info && <p className="text-sm text-accent-green">{info}</p>}

          <button
            type="submit"
            disabled={submitting}
            className="mt-2 rounded-md bg-accent-cyan px-3 py-2 text-sm font-semibold text-bg-page disabled:opacity-50"
          >
            {submitting ? 'Please wait...' : mode === 'login' ? 'Sign in' : 'Sign up'}
          </button>
        </form>

        <button
          type="button"
          onClick={() => {
            setMode(mode === 'login' ? 'signup' : 'login')
            setError(null)
            setInfo(null)
          }}
          className="mt-4 text-sm text-text-muted hover:text-accent-cyan"
        >
          {mode === 'login' ? "Don't have an account? Sign up" : 'Already have an account? Sign in'}
        </button>
      </div>
    </div>
  )
}
