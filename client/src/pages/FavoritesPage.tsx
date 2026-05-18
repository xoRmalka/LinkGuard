import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '@clerk/react'

import { useI18n } from '../i18n/I18nProvider'
import { getFavorites } from '../lib/api'

interface FavoriteItem {
  id: number;
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
                <th>URL</th>
                <th>Score</th>
                <th>Verdict</th>
              </tr>
            </thead>
            <tbody>
              {favorites.map((fav) => (
                <tr key={fav.id}>
                  <td className="mono">{fav.normalized_url}</td>
                  <td>{fav.score}%</td>
                  <td>{fav.verdict}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}