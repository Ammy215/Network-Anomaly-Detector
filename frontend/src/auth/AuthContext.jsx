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
    // onAuthStateChange fires 'SIGNED_IN' for an actual sign-in in this
    // tab (not for a session merely restored from storage on page load,
    // which fires 'INITIAL_SESSION' instead) -- that distinction is what
    // lets the login-event audit call fire only on real logins.
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
