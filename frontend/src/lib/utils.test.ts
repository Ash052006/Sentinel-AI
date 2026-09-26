import { describe, expect, it, beforeEach } from 'vitest'
import { cn, tokenStore } from './utils'

describe('cn', () => {
  it('joins truthy class names and skips falsy values', () => {
    expect(cn('a', 'b', false, undefined, null, 'c')).toBe('a b c')
  })

  it('returns an empty string for no inputs', () => {
    expect(cn()).toBe('')
  })
})

describe('tokenStore', () => {
  const key = 'sentinel.soc.token'

  beforeEach(() => {
    localStorage.clear()
  })

  it('persists and reads the token', () => {
    tokenStore.set('abc.123')
    expect(localStorage.getItem(key)).toBe('abc.123')
    expect(tokenStore.get()).toBe('abc.123')
  })

  it('clears the token', () => {
    tokenStore.set('abc.123')
    tokenStore.clear()
    expect(localStorage.getItem(key)).toBeNull()
    expect(tokenStore.get()).toBeNull()
  })

  it('reads null when nothing was stored', () => {
    expect(tokenStore.get()).toBeNull()
  })
})