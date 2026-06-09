import type { ComponentType } from 'react'
import { Navigate } from 'react-router-dom'

import { hasClerkPublishableKey } from '../../lib/env'

export function withClerkAdminPage(Inner: ComponentType) {
  return function ClerkAdminPage() {
    if (!hasClerkPublishableKey) return <Navigate to="/" replace />
    return <Inner />
  }
}
