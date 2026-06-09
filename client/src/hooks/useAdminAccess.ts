import { useAuth, useUser } from '@clerk/react'

import { isAppAdmin } from '../lib/clerkAdmin'

export function useAdminAccess() {
  const { getToken, isSignedIn, sessionClaims } = useAuth()
  const { user, isLoaded: userLoaded } = useUser()
  const isAdmin =
    userLoaded && isAppAdmin(sessionClaims as Record<string, unknown> | null, user?.publicMetadata)

  return { getToken, isSignedIn, isAdmin, userLoaded, user }
}
