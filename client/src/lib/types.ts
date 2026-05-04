export type Verdict =
  | 'safe_low'
  | 'suspicious'
  | 'dangerous'
  | 'insufficient_data'

export type RiskBand = 'low' | 'medium' | 'high' | 'critical'

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
  insufficient?: boolean
  insufficient_reasons?: string[]
}
