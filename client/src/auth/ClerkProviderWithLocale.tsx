import { ClerkProvider } from '@clerk/react'
import { enUS, heIL } from '@clerk/localizations'
import type { ReactNode } from 'react'

import { useI18n } from '../i18n/I18nProvider'
import { hasClerkPublishableKey } from '../lib/env'

type Props = {
  children: ReactNode
}

export function ClerkProviderWithLocale({ children }: Props) {
  const { locale } = useI18n()
  const localization = locale === 'he' ? heIL : enUS

  return (
    <ClerkProvider
      afterSignOutUrl="/"
      localization={localization}
      publishableKey={(import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined) ?? ''}
      {...(!hasClerkPublishableKey ? { __internal_bypassMissingPublishableKey: true } : {})}
    >
      {children}
    </ClerkProvider>
  )
}
