import { getAccessToken } from './supabaseClient'

export const API_BASE_URL = 'http://localhost:8000'

async function authHeaders() {
  const token = await getAccessToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

export async function apiGet(path, options = {}) {
  const { headers, ...rest } = options
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...rest,
    headers: { ...(await authHeaders()), ...headers },
  })
  if (!res.ok) throw new Error(`Request failed: ${res.status}`)
  return res.json()
}

export async function apiPost(path, body) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(await authHeaders()) },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.detail || `Request failed: ${res.status}`)
  return data
}

export async function apiPatch(path, body) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', ...(await authHeaders()) },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.detail || `Request failed: ${res.status}`)
  return data
}

// FormData sets its own multipart Content-Type header (with boundary) --
// setting one manually here would break it, so this only adds auth.
export async function apiPostForm(path, formData) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: await authHeaders(),
    body: formData,
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.detail || `Request failed: ${res.status}`)
  return data
}
