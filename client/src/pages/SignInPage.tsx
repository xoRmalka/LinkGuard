import { SignIn } from '@clerk/react'
import { Link } from 'react-router-dom'

import { useI18n } from '../i18n/I18nProvider'
import { hasClerkPublishableKey } from '../lib/env'

export function SignInPage() {
  const { t } = useI18n()

  if (!hasClerkPublishableKey) {
    return (
      <div className="page panel narrow">
        <h1>{t('auth.titleIn')}</h1>
        <p className="muted">{t('auth.clerkMissing')}</p>
        <Link className="btn" to="/">
          {t('nav.home')}
        </Link>
      </div>
    )
  }

  return (
    <div className="page auth">
      <h1 className="sr-only">{t('auth.titleIn')}</h1>
      <SignIn routing="path" path="/sign-in" signUpUrl="/sign-up" />
    </div>
  )
}
