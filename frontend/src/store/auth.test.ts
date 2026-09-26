import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useAuthStore, useUiStore } from './auth'
import { tokenStore } from '../lib/utils'

beforeEach(() => {
  useAuthStore.setState({ token: null, user: null })
  localStorage.clear()
})

describe('useAuthStore', () => {
  it('initializes the token from persisted storage on module load', async () => {
    tokenStore.set('persisted-token')
    vi.resetModules()
    const fresh = await import('./auth')
    expect(fresh.useAuthStore.getState().token).toBe('persisted-token')
  })

  it('setToken persists to storage and updates state', () => {
    useAuthStore.getState().setToken('fresh-token')
    expect(tokenStore.get()).toBe('fresh-token')
    expect(useAuthStore.getState().token).toBe('fresh-token')
  })

  it('setUser stores the fetched profile', () => {
    const profile = {
      id: 'u-1',
      email: 'analyst@sentinel.ai',
      role: 'analyst',
      is_active: true,
    }
    useAuthStore.getState().setUser(profile)
    expect(useAuthStore.getState().user).toEqual(profile)
  })

  it('logout clears both state and persisted token', () => {
    useAuthStore.getState().setToken('t')
    useAuthStore.getState().setUser({
      id: 'u-1',
      email: 'a@b.c',
      role: 'analyst',
      is_active: true,
    })
    useAuthStore.getState().logout()
    expect(tokenStore.get()).toBeNull()
    expect(useAuthStore.getState().token).toBeNull()
    expect(useAuthStore.getState().user).toBeNull()
  })
})

describe('useUiStore', () => {
  it('toggles sidebar open state', () => {
    expect(useUiStore.getState().sidebarOpen).toBe(false)
    useUiStore.getState().toggleSidebar()
    expect(useUiStore.getState().sidebarOpen).toBe(true)
    useUiStore.getState().closeSidebar()
    expect(useUiStore.getState().sidebarOpen).toBe(false)
  })
})