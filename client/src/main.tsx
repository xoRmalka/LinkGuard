import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

import { ClerkProviderWithLocale } from './auth/ClerkProviderWithLocale.tsx'
import { AppRoutes } from './app/AppRoutes.tsx'
import { I18nProvider } from './i18n/I18nProvider.tsx'
import './index.css'

function AppTree() {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <I18nProvider>
      <ClerkProviderWithLocale>
        <AppTree />
      </ClerkProviderWithLocale>
    </I18nProvider>
  </StrictMode>
)
