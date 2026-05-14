/** MVP: admin when Clerk `public_metadata.role` is `admin` (JWT claim or loaded user). */
export function isAppAdmin(
  sessionClaims: Record<string, unknown> | null | undefined,
  publicMetadata: unknown
): boolean {
  const fromUser =
    typeof publicMetadata === 'object' &&
    publicMetadata !== null &&
    (publicMetadata as { role?: string }).role === 'admin'
  const claims = sessionClaims as { role?: string; public_metadata?: { role?: string } } | null | undefined
  const fromClaimsRoot = claims?.role === 'admin'
  const fromClaimsNested = claims?.public_metadata?.role === 'admin'
  return Boolean(fromUser || fromClaimsRoot || fromClaimsNested)
}
