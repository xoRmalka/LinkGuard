import { useEffect, useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { useAuth } from '@clerk/clerk-react'

import { useI18n } from '../i18n/I18nProvider'
import { listAdminUsers } from '../lib/api'

const clerkKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined

function AdminInner() {
  const { t } = useI18n()
  const { getToken, isSignedIn } = useAuth()
  const [items, setItems] = useState<{ id: string; email: string; role: string; created_at: string | null }[]>(
    []
  )
  const [err, setErr] = useState<string | null>(null)
  const [email, setEmail] = useState('')

  useEffect(() => {
    if (!isSignedIn) return
    let cancelled = false
    ;(async () => {
      try {
        const data = await listAdminUsers(() => getToken())
        if (!cancelled) setItems(data.items)
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
      <h1>{t('admin.title')}</h1>
      <section className="panel">
        <h2>{t('admin.invite')}</h2>
        <div className="row-actions">
          <input
            className="url-form__input"
            type="email"
            placeholder={t('admin.emailPlaceholder')}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <button
            type="button"
            className="btn"
            onClick={() => {
              setErr(t('admin.inviteSent'))
            }}
          >
            {t('admin.invite')}
          </button>
        </div>
      </section>

      <section className="panel">
        <h2>{t('admin.users')}</h2>
        {err && err.includes('Invite') ? <p className="muted small">{err}</p> : null}
        {err && !err.includes('Invite') ? <p className="error">{err}</p> : null}
        {items.length === 0 && !err ? <p className="muted">{t('admin.empty')}</p> : null}
        {items.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>{t('admin.col.email')}</th>
                  <th>{t('admin.col.role')}</th>
                  <th>{t('admin.col.created')}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((u) => (
                  <tr key={u.id}>
                    <td>{u.email}</td>
                    <td>{u.role}</td>
                    <td>{u.created_at ? new Date(u.created_at).toLocaleString() : '—'}</td>
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

export function AdminPage() {
  if (!clerkKey) return <Navigate to="/" replace />
  return <AdminInner />
}
