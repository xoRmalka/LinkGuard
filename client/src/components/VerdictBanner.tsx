import type { Verdict } from '../lib/types'
import { normalizeVerdict, verdictTone } from '../lib/riskDisplay'
import { useI18n } from '../i18n/I18nProvider'

export function VerdictBanner({ verdict }: { verdict: Verdict | string }) {
  const { t } = useI18n()
  const normalized = normalizeVerdict(verdict)
  const tone = verdictTone(verdict)
  const labelKey = `result.verdict.${normalized}` as const

  return (
    <div className={`verdict verdict--${tone}`} role="status">
      <p className="verdict__eyebrow">{t('result.verdictEyebrow')}</p>
      <h2 className="verdict__title">{t(labelKey)}</h2>
    </div>
  )
}
