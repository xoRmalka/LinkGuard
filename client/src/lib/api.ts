import type { ScanPayload } from './types'

const base = () => (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, '') ?? ''

async function parseJson(res: Response): Promise<unknown> {
  try {
    return await res.json()
  } catch {
    return null
  }
}

/** Calls `GET /api/v1/me` so the server runs lazy default `public_metadata.role` in Clerk. */
export async function getMe(getToken: () => Promise<string | null>): Promise<{
  user_id: string
  role: string
}> {
  const token = await getToken()
  if (!token) throw new Error('no token')
  const res = await fetch(`${base()}/api/v1/me`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) {
    const body = (await parseJson(res)) as { message?: string } | null
    throw new Error(body?.message || 'me fetch failed')
  }
  return (await res.json()) as { user_id: string; role: string }
}

export async function postScan(
  url: string,
  getToken?: () => Promise<string | null>
): Promise<{ ok: true; data: ScanPayload } | { ok: false; status: number; message: string }> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (getToken) {
    const token = await getToken()
    if (token) headers.Authorization = `Bearer ${token}`
  }
  const res = await fetch(`${base()}/api/v1/scans`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ url }),
  })
  const body = (await parseJson(res)) as Record<string, unknown> | null
  if (!res.ok) {
    const msg =
      typeof body?.message === 'string'
        ? body.message
        : typeof body?.error === 'string'
          ? body.error
          : 'Request failed'
    return { ok: false, status: res.status, message: msg }
  }
  return { ok: true, data: body as unknown as ScanPayload }
}

export async function listMyScans(
  getToken: () => Promise<string | null>,
  page = 1
): Promise<{ items: unknown[]; total: number }> {
  const token = await getToken()
  if (!token) throw new Error('no token')
  const res = await fetch(`${base()}/api/v1/me/scans?page=${page}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) throw new Error('failed to load scans')
  return (await res.json()) as { items: unknown[]; total: number }
}

export async function listAdminUsers(
  getToken: () => Promise<string | null>
): Promise<{
  items: { id: string; email: string; role: string; created_at: string | null }[]
  total?: number
}> {
  const token = await getToken()
  if (!token) throw new Error('no token')
  const res = await fetch(`${base()}/api/v1/admin/users`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error((err as { message?: string }).message || 'admin fetch failed')
  }
  return res.json() as Promise<{
    items: { id: string; email: string; role: string; created_at: string | null }[]
    total?: number
  }>
}

export async function postAdminInvite(
  getToken: () => Promise<string | null>,
  payload: { email: string; role?: 'user' | 'admin'; redirect_url?: string }
): Promise<void> {
  const token = await getToken()
  if (!token) throw new Error('no token')
  const res = await fetch(`${base()}/api/v1/admin/invites`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email: payload.email,
      role: payload.role ?? 'user',
      redirect_url: payload.redirect_url,
    }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error((err as { message?: string }).message || 'invite failed')
  }
}

export async function patchAdminUserRole(
  getToken: () => Promise<string | null>,
  userId: string,
  role: 'user' | 'admin'
): Promise<void> {
  const token = await getToken()
  if (!token) throw new Error('no token')
  const res = await fetch(`${base()}/api/v1/admin/users/${encodeURIComponent(userId)}`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ role }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error((err as { message?: string }).message || 'update failed')
  }
}

export async function deleteAdminUser(
  getToken: () => Promise<string | null>,
  userId: string
): Promise<void> {
  const token = await getToken()
  if (!token) throw new Error('no token')
  const res = await fetch(`${base()}/api/v1/admin/users/${encodeURIComponent(userId)}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error((err as { message?: string }).message || 'delete failed')
  }
}

export async function postFavorite(
  scanId: string,
  getToken: () => Promise<string | null>
): Promise<{ favorited: boolean }> {
  const token = await getToken()
  if (!token) throw new Error('no token')
  const res = await fetch(`${base()}/api/v1/scans/${scanId}/favorite`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) throw new Error('favorite failed')
  return res.json() as Promise<{ favorited: boolean }>
}

export async function postReport(
  payload: { url: string; scan_id?: string; note?: string },
  getToken: () => Promise<string | null>
): Promise<void> {
  const token = await getToken()
  if (!token) throw new Error('no token')
  const res = await fetch(`${base()}/api/v1/reports`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      url: payload.url,
      scan_id: payload.scan_id,
      note: payload.note,
    }),
  })
  if (!res.ok) throw new Error('report failed')
}
