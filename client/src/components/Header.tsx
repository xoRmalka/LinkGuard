import { Link, NavLink } from 'react-router-dom'
import {
  Show,
  SignInButton,
  SignUpButton,
  UserButton,
  useAuth,
  useUser,
} from '@clerk/react'

import { useI18n } from '../i18n/I18nProvider'
import { isAppAdmin } from '../lib/clerkAdmin'
import { hasClerkPublishableKey } from '../lib/env'

export function Header() {
  const { t, locale, setLocale } = useI18n()
  const { sessionClaims } = useAuth()
  const { user, isLoaded: userLoaded } = useUser()
  const showAdmin =
    userLoaded && isAppAdmin(sessionClaims as Record<string, unknown> | null, user?.publicMetadata)

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
          {hasClerkPublishableKey ? (
            <Show when="signed-in">
              <NavLink to="/dashboard" className="nav-link">
                {t('nav.dashboard')}
              </NavLink>
              {showAdmin ? (
                <NavLink to="/admin" className="nav-link">
                  {t('nav.admin')}
                </NavLink>
              ) : null}
            </Show>
          ) : null}
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

          {!hasClerkPublishableKey ? (
            <span className="muted small">{t('auth.clerkMissing')}</span>
          ) : (
            <>
              <Show when="signed-out">
                <SignInButton mode="redirect">
                  <button type="button" className="btn btn--ghost">
                    {t('nav.signIn')}
                  </button>
                </SignInButton>
                <SignUpButton mode="redirect">
                  <button type="button" className="btn">
                    {t('nav.signUp')}
                  </button>
                </SignUpButton>
              </Show>
              <Show when="signed-in">
                <UserButton />
              </Show>
            </>
          )}
        </div>
      </div>
    </header>
  )
}
