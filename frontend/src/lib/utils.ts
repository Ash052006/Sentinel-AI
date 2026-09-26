import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}

const TOKEN_KEY = 'sentinel.soc.token'

export const tokenStore = {
  get: (): string | null => {
    try {
      return window.localStorage.getItem(TOKEN_KEY)
    } catch {
      return null
    }
  },
  set: (value: string): void => {
    try {
      window.localStorage.setItem(TOKEN_KEY, value)
    } catch {
      /* storage unavailable — session proceeds without persistence */
    }
  },
  clear: (): void => {
    try {
      window.localStorage.removeItem(TOKEN_KEY)
    } catch {
      /* noop */
    }
  },
}