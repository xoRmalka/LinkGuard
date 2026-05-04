import type { Verdict } from '../lib/types'
import { useI18n } from '../i18n/I18nProvider'

export function VerdictBanner({ verdict }: { verdict: Verdict }) {
  const { t } = useI18n()
  const tone =
    verdict === 'dangerous'
      ? 'danger'
      : verdict === 'suspicious'
        ? 'warn'
        : verdict === 'insufficient_data'
          ? 'muted'
          : 'ok'

  const labelKey = `result.verdict.${verdict}` as const

  return (
    <div className={`verdict verdict--${tone}`} role="status">
      <p className="verdict__eyebrow">{t('result.verdictEyebrow')}</p>
      <h2 className="verdict__title">{t(labelKey)}</h2>
    </div>
  )
}
