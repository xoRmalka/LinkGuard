import { Link, NavLink } from 'react-router-dom'
import {
  SignedIn,
  SignedOut,
  UserButton,
  useAuth,
} from '@clerk/clerk-react'

import { useI18n } from '../i18n/I18nProvider'

const clerkKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined

function HeaderGuest() {
  const { t, locale, setLocale } = useI18n()
  return (
    <header className="site-header">
      <div className="site-header__inner">
        <Link to="/" className="brand">
          <span className="brand__mark" aria-hidden />
          <span className="brand__text">{t('brand')}</span>
        </Link>
        <nav className="site-nav" aria-label="Main">
          <NavLink to="/" className="nav-link" end>
            {t('nav.home')}
          </NavLink>
        </nav>
        <div className="site-header__actions">
          <div className="lang-switch" role="group" aria-label="Language">
            <button
              type="button"
              className={locale === 'en' ? 'is-active' : ''}
              onClick={() => setLocale('en')}
            >
              {t('lang.en')}
            </button>
            <button
              type="button"
              className={locale === 'he' ? 'is-active' : ''}
              onClick={() => setLocale('he')}
            >
              {t('lang.he')}
            </button>
          </div>
          <span className="muted small">{t('auth.clerkMissing')}</span>
        </div>
      </div>
    </header>
  )
}

function HeaderAuthed() {
  const { t, locale, setLocale } = useI18n()
  const { isSignedIn } = useAuth()

  return (
    <header className="site-header">
      <div className="site-header__inner">
        <Link to="/" className="brand">
          <span className="brand__mark" aria-hidden />
          <span className="brand__text">{t('brand')}</span>
        </Link>

        <nav className="site-nav" aria-label="Main">
          <NavLink to="/" className="nav-link" end>
            {t('nav.home')}
          </NavLink>
          {isSignedIn && (
            <NavLink to="/dashboard" className="nav-link">
              {t('nav.dashboard')}
            </NavLink>
          )}
          {isSignedIn && (
            <NavLink to="/admin" className="nav-link">
              {t('nav.admin')}
            </NavLink>
          )}
        </nav>

        <div className="site-header__actions">
          <div className="lang-switch" role="group" aria-label="Language">
            <button
              type="button"
              className={locale === 'en' ? 'is-active' : ''}
              onClick={() => setLocale('en')}
            >
              {t('lang.en')}
            </button>
            <button
              type="button"
              className={locale === 'he' ? 'is-active' : ''}
              onClick={() => setLocale('he')}
            >
              {t('lang.he')}
            </button>
          </div>

          <SignedOut>
            <Link className="btn btn--ghost" to="/sign-in">
              {t('nav.signIn')}
            </Link>
            <Link className="btn" to="/sign-up">
              {t('nav.signUp')}
            </Link>
          </SignedOut>
          <SignedIn>
            <UserButton afterSignOutUrl="/" />
          </SignedIn>
        </div>
      </div>
    </header>
  )
}

export function Header() {
  if (!clerkKey) return <HeaderGuest />
  return <HeaderAuthed />
}
