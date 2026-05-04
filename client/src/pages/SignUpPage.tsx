import { SignUp } from '@clerk/clerk-react'
import { Link } from 'react-router-dom'

import { useI18n } from '../i18n/I18nProvider'

const clerkKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined

export function SignUpPage() {
  const { t } = useI18n()

  if (!clerkKey) {
    return (
      <div className="page panel narrow">
        <h1>{t('auth.titleUp')}</h1>
        <p className="muted">{t('auth.clerkMissing')}</p>
        <Link className="btn" to="/">
          {t('nav.home')}
        </Link>
      </div>
    )
  }

  return (
    <div className="page auth">
      <h1 className="sr-only">{t('auth.titleUp')}</h1>
      <SignUp routing="path" path="/sign-up" signInUrl="/sign-in" />
    </div>
  )
}
