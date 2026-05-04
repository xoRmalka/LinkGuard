import { useEffect, useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { useAuth } from '@clerk/clerk-react'

import { useI18n } from '../i18n/I18nProvider'
import { listMyScans } from '../lib/api'

const clerkKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined

type Row = {
  id: string
  normalized_url: string
  score: number
  verdict: string
  risk_band: string
  created_at: string | null
}

function DashboardInner() {
  const { t } = useI18n()
  const { getToken, isSignedIn } = useAuth()
  const [rows, setRows] = useState<Row[]>([])
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    if (!isSignedIn) return
    let cancelled = false
    ;(async () => {
      try {
        const data = await listMyScans(() => getToken())
        if (!cancelled) setRows(data.items as Row[])
      } catch (e) {
        if (!cancelled) setErr((e as Error).message)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [getToken, isSignedIn])

  if (!isSignedIn) {
    return (
      <div className="page panel narrow">
        <p className="muted">{t('result.signInToSave')}</p>
        <Link className="btn" to="/sign-in">
          {t('nav.signIn')}
        </Link>
      </div>
    )
  }

  return (
    <div className="page">
      <h1>{t('dashboard.title')}</h1>
      {err ? <p className="error">{err}</p> : null}
      {rows.length === 0 && !err ? (
        <p className="muted">{t('dashboard.empty')}</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('dashboard.col.url')}</th>
                <th>{t('dashboard.col.score')}</th>
                <th>{t('dashboard.col.verdict')}</th>
                <th>{t('dashboard.col.date')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="mono truncate">{r.normalized_url}</td>
                  <td>{r.score}</td>
                  <td>{r.verdict}</td>
                  <td>{r.created_at ? new Date(r.created_at).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export function DashboardPage() {
  if (!clerkKey) return <Navigate to="/" replace />
  return <DashboardInner />
}
