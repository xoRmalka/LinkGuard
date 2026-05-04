import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

import en from './locales/en.json'
import he from './locales/he.json'

export type Locale = 'en' | 'he'

const STORAGE_KEY = 'linkguard.locale'

const catalogs: Record<Locale, Record<string, string>> = { en, he }

function getByPath(obj: Record<string, string>, path: string): string | undefined {
  return obj[path]
}

type I18nContextValue = {
  locale: Locale
  setLocale: (l: Locale) => void
  t: (key: string) => string
}

const I18nContext = createContext<I18nContextValue | null>(null)

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() => {
    const saved = localStorage.getItem(STORAGE_KEY) as Locale | null
    return saved === 'he' ? 'he' : 'en'
  })

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l)
    localStorage.setItem(STORAGE_KEY, l)
  }, [])

  useEffect(() => {
    document.documentElement.lang = locale === 'he' ? 'he' : 'en'
    document.documentElement.dir = locale === 'he' ? 'rtl' : 'ltr'
  }, [locale])

  const t = useCallback(
    (key: string) => {
      const fromCatalog = getByPath(catalogs[locale], key)
      if (fromCatalog) return fromCatalog
      return getByPath(catalogs.en, key) ?? key
    },
    [locale]
  )

  const value = useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t])

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n() {
  const ctx = useContext(I18nContext)
  if (!ctx) throw new Error('useI18n must be used within I18nProvider')
  return ctx
}
