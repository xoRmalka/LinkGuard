import { useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import { useAuth } from '@clerk/react'

import { Header } from '../components/Header'
import { useI18n } from '../i18n/I18nProvider'
import { getMe } from '../lib/api'
import { hasClerkPublishableKey } from '../lib/env'

export function RootLayout() {
  const { t } = useI18n()
  const { isSignedIn, getToken } = useAuth()

  useEffect(() => {
    if (!hasClerkPublishableKey || !isSignedIn) return
    let cancelled = false
    ;(async () => {
      try {
        await getMe(() => getToken())
      } catch {
        // Token may not be ready on first frame; retry on next navigation/sign-in.
      }
      if (cancelled) return
    })()
    return () => {
      cancelled = true
    }
  }, [isSignedIn, getToken])

  return (
    <div className="shell">
      <Header />
      <main className="main">
        <Outlet />
      </main>
      <footer className="footer">
        <p className="muted small">{t('footer.note')}</p>
      </footer>
    </div>
  )
}
