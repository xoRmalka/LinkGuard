import { useCallback, useEffect, useState } from 'react'
import { useAuth, useUser } from '@clerk/react'

import { AdminGate } from '../components/admin/AdminGate'
import { withClerkAdminPage } from '../components/admin/withClerkAdminPage'
import { useAdminAccess } from '../hooks/useAdminAccess'
import { useI18n } from '../i18n/I18nProvider'
import {
  deleteAdminUser,
  listAdminUsers,
  patchAdminUserRole,
  postAdminInvite,
} from '../lib/api'

type Row = { id: string; email: string; role: string; created_at: string | null }

function AdminInner() {
  const { t } = useI18n()
  const { getToken } = useAuth()
  const { user } = useUser()
  const { isSignedIn, isAdmin } = useAdminAccess()
  const [items, setItems] = useState<Row[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)
  const [email, setEmail] = useState('')
  const [inviteRole, setInviteRole] = useState<'user' | 'admin'>('user')
  const [rowRoles, setRowRoles] = useState<Record<string, 'user' | 'admin'>>({})
  const [busyId, setBusyId] = useState<string | null>(null)

  const reload = useCallback(async () => {
    const data = await listAdminUsers(() => getToken())
    setItems(data.items)
    const next: Record<string, 'user' | 'admin'> = {}
    for (const u of data.items) {
      next[u.id] = u.role === 'admin' ? 'admin' : 'user'
    }
    setRowRoles(next)
  }, [getToken])

  useEffect(() => {
    if (!isSignedIn || !isAdmin) return
    let cancelled = false
    ;(async () => {
      try {
        setErr(null)
        await reload()
      } catch (e) {
        if (!cancelled) setErr((e as Error).message)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [getToken, isSignedIn, isAdmin, reload])

  return (
    <AdminGate titleKey="admin.title">
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
            <select
              className="url-form__input"
              aria-label={t('admin.col.role')}
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value as 'user' | 'admin')}
            >
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
            <button
              type="button"
              className="btn"
              disabled={!email.trim()}
              onClick={async () => {
                setErr(null)
                setInfo(null)
                try {
                  await postAdminInvite(() => getToken(), {
                    email: email.trim(),
                    role: inviteRole,
                    redirect_url: `${window.location.origin}/`,
                  })
                  setInfo(t('admin.inviteSent'))
                  setEmail('')
                } catch (e) {
                  setErr((e as Error).message)
                }
              }}
            >
              {t('admin.invite')}
            </button>
          </div>
          {info ? <p className="muted small">{info}</p> : null}
        </section>

        <section className="panel">
          <h2>{t('admin.users')}</h2>
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
                    <th>{t('admin.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((u) => (
                    <tr key={u.id}>
                      <td>{u.email}</td>
                      <td>
                        <select
                          value={rowRoles[u.id] ?? 'user'}
                          disabled={busyId === u.id}
                          onChange={(e) =>
                            setRowRoles((prev) => ({
                              ...prev,
                              [u.id]: e.target.value as 'user' | 'admin',
                            }))
                          }
                        >
                          <option value="user">user</option>
                          <option value="admin">admin</option>
                        </select>
                      </td>
                      <td>{u.created_at ? new Date(u.created_at).toLocaleString() : '—'}</td>
                      <td>
                        <button
                          type="button"
                          className="btn btn--ghost"
                          disabled={busyId === u.id || (rowRoles[u.id] ?? 'user') === u.role}
                          onClick={async () => {
                            setBusyId(u.id)
                            setErr(null)
                            try {
                              await patchAdminUserRole(() => getToken(), u.id, rowRoles[u.id] ?? 'user')
                              await user?.reload?.()
                              await reload()
                            } catch (e) {
                              setErr((e as Error).message)
                            } finally {
                              setBusyId(null)
                            }
                          }}
                        >
                          {t('admin.save')}
                        </button>
                        <button
                          type="button"
                          className="btn btn--ghost"
                          disabled={busyId === u.id || u.id === user?.id}
                          onClick={async () => {
                            if (!window.confirm(t('admin.deleteConfirm'))) return
                            setBusyId(u.id)
                            setErr(null)
                            try {
                              await deleteAdminUser(() => getToken(), u.id)
                              await reload()
                            } catch (e) {
                              setErr((e as Error).message)
                            } finally {
                              setBusyId(null)
                            }
                          }}
                        >
                          {t('admin.delete')}
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
    </AdminGate>
  )
}

export const AdminPage = withClerkAdminPage(AdminInner)
