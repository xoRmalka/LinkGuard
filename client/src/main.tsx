import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { ClerkProvider } from '@clerk/react'

import { AppRoutes } from './app/AppRoutes.tsx'
import { hasClerkPublishableKey } from './lib/env'
import { I18nProvider } from './i18n/I18nProvider.tsx'
import './index.css'

function AppTree() {
  return (
    <I18nProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </I18nProvider>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ClerkProvider
      afterSignOutUrl="/"
      publishableKey={(import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined) ?? ''}
      {...(!hasClerkPublishableKey ? { __internal_bypassMissingPublishableKey: true } : {})}
    >
      <AppTree />
    </ClerkProvider>
  </StrictMode>
)
