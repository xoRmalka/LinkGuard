import type { RiskBand, Verdict } from './types'

/** Map legacy API/DB values to current verdict keys for i18n and styling. */
export function normalizeVerdict(verdict: string): Verdict {
  switch (verdict) {
    case 'safe_low':
      return 'safe'
    case 'suspicious':
      return 'moderate_risk'
    default:
      return verdict as Verdict
  }
}

/** Map legacy risk bands to current band keys for i18n and styling. */
export function normalizeBand(band: string): RiskBand {
  switch (band) {
    case 'low':
      return 'safe'
    case 'medium':
      return 'moderate_risk'
    case 'high':
    case 'critical':
      return 'high_risk'
    default:
      return band as RiskBand
  }
}

export type VerdictTone = 'ok' | 'warn' | 'danger' | 'muted'

export function verdictTone(verdict: string): VerdictTone {
  const v = normalizeVerdict(verdict)
  if (v === 'dangerous' || v === 'high_risk') return 'danger'
  if (v === 'moderate_risk') return 'warn'
  if (v === 'insufficient_data') return 'muted'
  return 'ok'
}
