import { useEffect, useState } from 'react'
import { useAuth } from '@clerk/react'

import { useI18n } from '../i18n/I18nProvider'
import { getFavorites } from '../lib/api'
import { normalizeVerdict } from '../lib/riskDisplay'

interface FavoriteItem {
  id: string
  scan_id: string;
  normalized_url: string;
  verdict: string;
  score: number;
  created_at: string;
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
      } catch (err) {
        setError('Failed to load favorites.')
      } finally {
        setLoading(false)
      }
    }

    fetchFavorites()
  }, [isSignedIn, getToken])

  if (!isSignedIn) {
    return (
      <div className="page">
        <h2>My Favorites</h2>
        <p>Please sign in to view your saved URLs.</p>
      </div>
    )
  }

  if (loading) return <div className="page"><p>Loading favorites...</p></div>
  if (error) return <div className="page"><p className="danger">{error}</p></div>

  return (
    <div className="page">
      <h1>{t('nav.favorites') || 'My Favorites'}</h1>
      
      {favorites.length === 0 ? (
        <p className="muted">You haven't saved any URLs yet.</p>
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