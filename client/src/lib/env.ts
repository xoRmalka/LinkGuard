/** True when Clerk is configured (real publishable key). Guest mode uses bypass in `main.tsx`. */
export const hasClerkPublishableKey = Boolean(
  (import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined)?.trim()
)
