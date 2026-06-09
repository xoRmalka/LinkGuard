import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

import { useAdminAccess } from '../../hooks/useAdminAccess'
import { useI18n } from '../../i18n/I18nProvider'

type AdminGateProps = {
  titleKey: string
  children: ReactNode
}

export function AdminGate({ titleKey, children }: AdminGateProps) {
  const { t } = useI18n()
  const { isSignedIn, isAdmin, userLoaded } = useAdminAccess()

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

  if (userLoaded && !isAdmin) {
    return (
      <div className="page panel narrow">
        <h1>{t(titleKey)}</h1>
        <p className="error">{t('admin.forbidden')}</p>
        <Link className="btn" to="/dashboard">
          {t('nav.dashboard')}
        </Link>
      </div>
    )
  }

  return children
}
