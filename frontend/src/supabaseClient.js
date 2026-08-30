import { createClient } from '@supabase/supabase-js'

export const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY
)

// `getSession()` reads the current session from local storage/memory (a
// fast local check, not a network round trip) and transparently refreshes
// it first if it's expired -- safe to call before every API request.
export async function getAccessToken() {
  const { data } = await supabase.auth.getSession()
  return data.session?.access_token ?? null
}
