export const API_BASE_URL = 'http://localhost:8000'

export async function apiGet(path, options = {}) {
  const res = await fetch(`${API_BASE_URL}${path}`, options)
  if (!res.ok) throw new Error(`Request failed: ${res.status}`)
  return res.json()
}

export async function apiPost(path, body) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.detail || `Request failed: ${res.status}`)
  return data
}
