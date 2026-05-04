import type { RiskBand } from '../lib/types'
import { useI18n } from '../i18n/I18nProvider'

export function ScoreCard({
  score,
  band,
}: {
  score: number
  band: RiskBand
}) {
  const { t } = useI18n()
  const bandLabel = t(`result.band.${band}`)

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
        <p className={`pill pill--${band}`}>{bandLabel}</p>
      </div>
    </div>
  )
}
