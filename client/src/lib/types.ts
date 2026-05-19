export type Verdict =
  | 'safe'
  | 'low_risk'
  | 'moderate_risk'
  | 'high_risk'
  | 'dangerous'
  | 'insufficient_data'

export type RiskBand = 'safe' | 'low_risk' | 'moderate_risk' | 'high_risk'

export type SignalBreakdown = {
  id: string
  status: string
  concern?: boolean
  summary?: string
  points?: number
  [k: string]: unknown
}

export type ScanPayload = {
  ok?: boolean
  scan_id: string | null
  input_url: string
  normalized_url: string
  host?: string
  host_display?: string
  scheme?: string
  is_ip_host?: boolean
  punycode_applied?: boolean
  score: number
  risk_band: RiskBand
  verdict: Verdict
  breakdown: SignalBreakdown[]
  weights_version: string
  explanation: string[]
  recommended_actions: string[]
  explanation_keys?: string[]
  action_keys?: string[]
  insufficient?: boolean
  insufficient_reasons?: string[]
}
