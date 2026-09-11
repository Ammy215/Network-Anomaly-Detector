import { createContext, useContext, useEffect, useState } from 'react'
import { apiGet, apiPost } from '../api'
import { supabase } from '../supabaseClient'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [session, setSession] = useState(null)
  const [role, setRole] = useState(null)
  const [loading, setLoading] = useState(true)
  const [sessionChecked, setSessionChecked] = useState(false)

  useEffect(() => {
    // 'SIGNED_IN' does NOT mean a real sign-in happened: supabase-js also
    // fires it when a stored session is recovered on every tab refocus,
    // and re-broadcasts it to every other open tab. So the login-event
    // call below may run many times per sign-in -- the backend records
    // only the first per Supabase session (see log_login, docs/MONITORING.md).
    const { data: subscription } = supabase.auth.onAuthStateChange((event, newSession) => {
      setSession(newSession)
      setSessionChecked(true)
      if (event === 'SIGNED_IN') {
        apiPost('/api/auth/login-event', {}).catch(() => {})
      }
      if (event === 'SIGNED_OUT') {
        setRole(null)
      }
    })
    return () => subscription.subscription.unsubscribe()
  }, [])

  useEffect(() => {
    if (!sessionChecked) return
    if (!session?.user) {
      setLoading(false)
      return
    }
    setLoading(true)
    apiGet('/api/auth/me')
      .then((me) => setRole(me.role))
      .catch(() => setRole(null))
      .finally(() => setLoading(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionChecked, session?.user?.id])

  const value = {
    session,
    user: session?.user ?? null,
    role,
    loading,
    signUp: (email, password) => supabase.auth.signUp({ email, password }),
    signIn: (email, password) => supabase.auth.signInWithPassword({ email, password }),
    signOut: () => supabase.auth.signOut(),
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider')
  return ctx
}
