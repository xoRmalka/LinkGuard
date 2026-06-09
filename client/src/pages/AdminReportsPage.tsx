import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '@clerk/react'

import { useI18n } from '../i18n/I18nProvider'
import { getAdminReports, deleteAdminReport } from '../lib/api'

type ReportRow = {
  id: string
  user_id?: string
  url: string
  scan_id?: string | null
  note?: string | null
  status?: string
  created_at?: string | null
  score?: number | null
  normalized_url?: string | null
}

export default function AdminReportsPage() {
  const { t } = useI18n()
  const { getToken, isSignedIn } = useAuth()

  const [items, setItems] = useState<ReportRow[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)

  useEffect(() => {
    if (!isSignedIn) return
    let cancelled = false
    ;(async () => {
      try {
        setErr(null)
        const token = await getToken()
        if (!token) throw new Error('no token')
        const data = await getAdminReports(token)
        const next = Array.isArray(data) ? data : (data?.items ?? data)
        if (!cancelled) setItems(next)
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
      <h1>{t('admin.reports') || 'Reports'}</h1>
      <section className="panel">
        {err ? <p className="error">{err}</p> : null}
        {items.length === 0 && !err ? <p className="muted">{t('admin.empty') || 'No reports'}</p> : null}

        {items.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>{t('dashboard.col.url') || 'URL'}</th>
                  <th>{t('dashboard.col.score') || 'Score'}</th>
                  <th>{t('admin.actions') || 'Actions'}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((r) => (
                  <tr key={r.id}>
                    <td>{r.normalized_url ?? r.url}</td>
                    <td>{typeof r.score === 'number' ? r.score : '—'}</td>
                    <td>
                      <button type="button" className="btn btn--ghost" onClick={() => {}}>
                        {t('admin.approve') || 'Approve'}
                      </button>
                      <button
                        type="button"
                        className="btn btn--ghost"
                        disabled={busyId === r.id}
                        onClick={async () => {
                          if (busyId) return
                          setBusyId(r.id)
                          setErr(null)
                          try {
                            const token = await getToken()
                            if (!token) throw new Error('no token')
                            await deleteAdminReport(token, r.id)
                            setItems((prev) => prev.filter((x) => x.id !== r.id))
                          } catch (e) {
                            setErr((e as Error).message)
                          } finally {
                            setBusyId(null)
                          }
                        }}
                      >
                        {t('admin.reject') || 'Reject'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </div>
  )
}
