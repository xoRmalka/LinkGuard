import { useMemo, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '@clerk/react'

import { ScoreCard } from '../components/ScoreCard'
import { VerdictBanner } from '../components/VerdictBanner'
import { useI18n } from '../i18n/I18nProvider'
import { postFavorite, postReport } from '../lib/api'
import type { ScanPayload, Verdict } from '../lib/types'

const hasPublishableKey = Boolean(
  (import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined)?.trim()
)

function ResultBody({
  scan,
  getToken,
}: {
  scan: ScanPayload
  getToken?: () => Promise<string | null>
}) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [note, setNote] = useState<string | null>(null)
  const [reporting, setReporting] = useState(false)

  const verdict: Verdict = useMemo(() => scan.verdict, [scan.verdict])

  async function onFavorite() {
    if (!scan.scan_id || !getToken) return
    setNote(null)
    try {
      const r = await postFavorite(scan.scan_id, getToken)
      setNote(r.favorited ? t('result.favoriteDone') : t('result.favoriteRemoved'))
    } catch {
      setNote(t('error.generic'))
    }
  }

  async function onReport() {
    if (!getToken) return
    setReporting(true)
    setNote(null)
    try {
      await postReport(
        { url: scan.normalized_url, scan_id: scan.scan_id ?? undefined },
        getToken
      )
      setNote(t('admin.inviteSent'))
    } catch {
      setNote(t('error.generic'))
    } finally {
      setReporting(false)
    }
  }

  const authed = Boolean(getToken)

  return (
    <div className="page result">
      <VerdictBanner verdict={verdict} />
      <ScoreCard score={scan.score} band={scan.risk_band} />

      <section className="panel">
        <h2>{t('result.why')}</h2>
        <ul className="prose-list">
          {(scan.explanation || []).map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
        {(scan.insufficient_reasons || []).length > 0 && (
          <ul className="prose-list muted">
            {scan.insufficient_reasons!.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        )}
      </section>

      <section className="panel">
        <h2>{t('result.actions')}</h2>
        <ul className="prose-list">
          {(scan.recommended_actions || []).map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </section>

      <section className="panel">
        <h2>{t('result.signals')}</h2>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('result.col.signal')}</th>
                <th>{t('result.col.status')}</th>
                <th>{t('result.col.points')}</th>
                <th>{t('result.col.summary')}</th>
              </tr>
            </thead>
            <tbody>
              {(scan.breakdown || []).map((row) => (
                <tr key={row.id}>
                  <td>{row.id}</td>
                  <td>{row.status}</td>
                  <td>{row.points ?? '—'}</td>
                  <td>{row.summary ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h2>{t('result.normalized')}</h2>
        <p className="mono">{scan.normalized_url}</p>
        <p className="muted small">
          Host: {scan.host}
          {scan.is_ip_host ? ' · IP host' : ''}
          {scan.punycode_applied ? ' · IDN/punycode' : ''}
        </p>
      </section>

      <div className="row-actions">
        <button type="button" className="btn" onClick={() => navigate('/')}>
          {t('result.back')}
        </button>
        {authed ? (
          <>
            <button
              type="button"
              className="btn btn--ghost"
              onClick={onReport}
              disabled={reporting}
            >
              {t('result.report')}
            </button>
            {scan.scan_id ? (
              <button type="button" className="btn btn--primary" onClick={onFavorite}>
                {t('result.favorite')}
              </button>
            ) : null}
          </>
        ) : (
          <p className="muted small">{t('result.signInToSave')}</p>
        )}
      </div>
      {note ? <p className="muted small">{note}</p> : null}
    </div>
  )
}

function ResultWithClerk({ scan }: { scan: ScanPayload }) {
  const { isSignedIn, getToken } = useAuth()
  const get = isSignedIn ? () => getToken() : undefined
  return <ResultBody scan={scan} getToken={get} />
}

export function ResultPage() {
  const { t } = useI18n()
  const location = useLocation()
  const scan = location.state?.scan as ScanPayload | undefined

  if (!scan) {
    return (
      <div className="page">
        <p>{t('result.missing')}</p>
        <Link className="btn" to="/">
          {t('nav.home')}
        </Link>
      </div>
    )
  }

  if (!hasPublishableKey) return <ResultBody scan={scan} />
  return <ResultWithClerk scan={scan} />
}
