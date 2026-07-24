import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@clerk/react'

import { useI18n } from '../i18n/I18nProvider'
import { hasClerkPublishableKey } from '../lib/env'
import { postScan } from '../lib/api'
import type { ScanPayload } from '../lib/types'

const EXAMPLES = [
  {
    labelKey: 'home.example1' as const,
    descriptionKey: 'home.example1.desc' as const,
    url: 'https://www.wikipedia.org/wiki/Phishing',
  },
  {
    labelKey: 'home.example2' as const,
    descriptionKey: 'home.example2.desc' as const,
    url: 'https://bit.ly/example-demo',
  },
  {
    labelKey: 'home.example3' as const,
    descriptionKey: 'home.example3.desc' as const,
    url: 'https://192.0.2.1/login',
  },
]

function HomeContent({
  getToken,
}: {
  getToken?: () => Promise<string | null>
}) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function selectExample(exampleUrl: string) {
    setUrl(exampleUrl)
    setError(null)
    requestAnimationFrame(() => document.getElementById('url-input')?.focus())
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const res = await postScan(url, getToken)
      if (!res.ok) {
        if (res.status === 429) {
          setError(t('result.rateLimited'))
        } else {
          setError(res.message || t('error.generic'))
        }
        setBusy(false)
        return
      }
      navigate('/result', { state: { scan: res.data as ScanPayload } })
    } catch {
      setError(t('error.generic'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="page home">
      <section className="hero panel">
        <p className="eyebrow hero__eyebrow">{t('home.heroEyebrow')}</p>
        <h1>{t('home.heroTitle')}</h1>
        <p className="lede">{t('home.heroSubtitle')}</p>

        <form className="url-form" onSubmit={onSubmit}>
          <label className="url-form__label" htmlFor="url-input">
            {t('home.urlLabel')}
          </label>
          <div className="url-form__control">
            <input
              id="url-input"
              className="url-form__input"
              type="text"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              placeholder={t('home.urlPlaceholder')}
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              aria-invalid={Boolean(error)}
              aria-describedby={error ? 'url-error' : undefined}
            />
            <button className="btn btn--primary url-form__submit" type="submit" disabled={busy || !url.trim()}>
              {busy ? t('home.analyzing') : t('home.analyze')}
            </button>
          </div>
          {error ? (
            <p id="url-error" className="error" role="alert">
              {error}
            </p>
          ) : null}
        </form>
        <p className="muted small">{t('home.rateHint')}</p>
      </section>

      <section className="panel">
        <h2>{t('home.howTitle')}</h2>
        <ol className="steps">
          <li>{t('home.step1')}</li>
          <li>{t('home.step2')}</li>
          <li>{t('home.step3')}</li>
          <li>{t('home.step4')}</li>
        </ol>
      </section>

      <section className="panel">
        <h2>{t('home.examplesTitle')}</h2>
        <p className="muted examples-intro">{t('home.examplesIntro')}</p>
        <div className="examples">
          {EXAMPLES.map((ex) => (
            <article className="example-card" key={ex.url}>
              <div>
                <h3>{t(ex.labelKey)}</h3>
                <p>{t(ex.descriptionKey)}</p>
              </div>
              <code className="example-card__url">{ex.url}</code>
              <button
                type="button"
                className="btn btn--ghost example-card__action"
                onClick={() => selectExample(ex.url)}
              >
                {t('home.example.use')}
              </button>
            </article>
          ))}
        </div>
      </section>
    </div>
  )
}

function HomeWithToken() {
  const { getToken } = useAuth()
  return <HomeContent getToken={() => getToken()} />
}

export function HomePage() {
  if (!hasClerkPublishableKey) return <HomeContent />
  return <HomeWithToken />
}
