import type { ScanPayload } from './types'

const base = () => (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, '') ?? ''

async function parseJson(res: Response): Promise<unknown> {
  try {
    return await res.json()
  } catch {
    return null
  }
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
): Promise<{ items: { id: string; email: string; role: string; created_at: string | null }[] }> {
  const token = await getToken()
  if (!token) throw new Error('no token')
  const res = await fetch(`${base()}/api/v1/admin/users`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error((err as { message?: string }).message || 'admin fetch failed')
  }
  return res.json() as Promise<{ items: { id: string; email: string; role: string; created_at: string | null }[] }>
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
