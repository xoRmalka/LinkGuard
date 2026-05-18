import { useMemo, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '@clerk/react'

import { ScoreCard } from '../components/ScoreCard'
import { VerdictBanner } from '../components/VerdictBanner'
import { useI18n } from '../i18n/I18nProvider'
import { postFavorite, postReport } from '../lib/api'
import { hasClerkPublishableKey } from '../lib/env'
import type { ScanPayload, Verdict } from '../lib/types'

function SignalIcon({ status, concern, tooltip }: { status: string; concern?: boolean; tooltip: string }) {
  let svg: React.ReactNode

  if (status === 'skipped') {
    svg = (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <circle cx="8" cy="8" r="7" stroke="#9ca3af" strokeWidth="1.5" />
        <line x1="5" y1="8" x2="11" y2="8" stroke="#9ca3af" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    )
  } else if (status === 'unknown' || status === 'error') {
    svg = (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <circle cx="8" cy="8" r="7" stroke="#9ca3af" strokeWidth="1.5" />
        <text x="8" y="12" textAnchor="middle" fontSize="10" fill="#9ca3af">?</text>
      </svg>
    )
  } else if (concern) {
    svg = (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <path d="M8 2L14.5 13.5H1.5L8 2Z" stroke="#f59e0b" strokeWidth="1.5" strokeLinejoin="round" />
        <line x1="8" y1="7" x2="8" y2="10" stroke="#f59e0b" strokeWidth="1.5" strokeLinecap="round" />
        <circle cx="8" cy="12" r="0.75" fill="#f59e0b" />
      </svg>
    )
  } else {
    svg = (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <circle cx="8" cy="8" r="7" stroke="#22c55e" strokeWidth="1.5" />
        <polyline points="5,8.5 7,10.5 11,6" stroke="#22c55e" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    )
  }

  return (
    <span className="signal-icon-wrap" data-tooltip={tooltip}>
      {svg}
    </span>
  )
}

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
  const [showSignals, setShowSignals] = useState(false)

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
        <button
          type="button"
          className="btn btn--ghost signals-toggle"
          onClick={() => setShowSignals((v) => !v)}
          aria-expanded={showSignals}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 14 14"
            fill="none"
            aria-hidden="true"
            style={{ transform: showSignals ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}
          >
            <polyline points="2,4 7,10 12,4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          {showSignals ? t('result.signals.hide') : t('result.signals.show')}
        </button>
        {showSignals && (
          <div className="table-wrap" style={{ marginTop: '0.75rem' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th></th>
                  <th>{t('result.col.signal')}</th>
                </tr>
              </thead>
              <tbody>
                {(scan.breakdown || []).map((row) => {
                  const iconTooltip = row.status === 'skipped'
                    ? t('signal.status.skipped')
                    : row.status === 'unknown' || row.status === 'error'
                    ? t('signal.status.unknown')
                    : row.concern
                    ? t('signal.status.concern')
                    : t('signal.status.ok')
                  return (
                    <tr key={row.id}>
                      <td><SignalIcon status={row.status} concern={row.concern} tooltip={iconTooltip} /></td>
                      <td>
                        <span className="signal-name">{t(`signal.${row.id}` as Parameters<typeof t>[0]) || row.id}</span>
                        <span className="signal-desc">{t(`signal.${row.id}.desc` as Parameters<typeof t>[0])}</span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
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

  if (!hasClerkPublishableKey) return <ResultBody scan={scan} />
  return <ResultWithClerk scan={scan} />
}
