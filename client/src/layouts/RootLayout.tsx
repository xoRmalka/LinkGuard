import { Outlet } from 'react-router-dom'

import { Header } from '../components/Header'
import { useI18n } from '../i18n/I18nProvider'

export function RootLayout() {
  const { t } = useI18n()

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
