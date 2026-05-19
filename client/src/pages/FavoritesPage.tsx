import { useEffect, useState } from 'react'
import { SignInButton, useAuth } from '@clerk/react'

import { useI18n } from '../i18n/I18nProvider'
import { getFavorites } from '../lib/api'
import { hasClerkPublishableKey } from '../lib/env'
import { normalizeVerdict } from '../lib/riskDisplay'

interface FavoriteItem {
  id: string
  scan_id: string
  normalized_url: string
  verdict: string
  score: number
  created_at: string
}

export function FavoritesPage() {
  const { t } = useI18n()
  const { isSignedIn, getToken } = useAuth()
  const [favorites, setFavorites] = useState<FavoriteItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchFavorites() {
      if (!isSignedIn) {
        setLoading(false)
        return
      }

      try {
        const data = await getFavorites(getToken)
        setFavorites(data.favorites || data)
        setError(null)
      } catch {
        setError(t('favorites.errorLoad'))
      } finally {
        setLoading(false)
      }
    }

    fetchFavorites()
  }, [isSignedIn, getToken, t])

  if (!isSignedIn) {
    return (
      <div className="page panel narrow">
        <h1>{t('nav.favorites')}</h1>
        <p className="muted">{t('favorites.signInPrompt')}</p>
        {hasClerkPublishableKey ? (
          <SignInButton mode="redirect" forceRedirectUrl="/favorites">
            <button type="button" className="btn">
              {t('nav.signIn')}
            </button>
          </SignInButton>
        ) : (
          <p className="muted small">{t('auth.clerkMissing')}</p>
        )}
      </div>
    )
  }

  if (loading) {
    return (
      <div className="page">
        <h1>{t('nav.favorites')}</h1>
        <p className="muted">{t('favorites.loading')}</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="page">
        <h1>{t('nav.favorites')}</h1>
        <p className="error">{error}</p>
      </div>
    )
  }

  return (
    <div className="page">
      <h1>{t('nav.favorites')}</h1>

      {favorites.length === 0 ? (
        <p className="muted">{t('favorites.empty')}</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('dashboard.col.url')}</th>
                <th>{t('dashboard.col.score')}</th>
                <th>{t('dashboard.col.verdict')}</th>
              </tr>
            </thead>
            <tbody>
              {favorites.map((fav) => (
                <tr key={fav.id}>
                  <td className="mono">{fav.normalized_url}</td>
                  <td>{fav.score}%</td>
                  <td>
                    {t(`result.verdict.${normalizeVerdict(fav.verdict)}` as Parameters<typeof t>[0])}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
