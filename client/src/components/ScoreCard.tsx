import type { RiskBand } from '../lib/types'
import { normalizeBand } from '../lib/riskDisplay'
import { useI18n } from '../i18n/I18nProvider'

export function ScoreCard({
  score,
  band,
}: {
  score: number
  band: RiskBand | string
}) {
  const { t } = useI18n()
  const normalized = normalizeBand(band)
  const bandLabel = t(`result.band.${normalized}`)

  return (
    <div className="score-card">
      <div>
        <p className="eyebrow">{t('result.score')}</p>
        <p className="score-card__value" aria-live="polite">
          {score}
          <span className="score-card__suffix">/100</span>
        </p>
      </div>
      <div>
        <p className="eyebrow">{t('result.band')}</p>
        <p className={`pill pill--${normalized}`}>{bandLabel}</p>
      </div>
    </div>
  )
}
