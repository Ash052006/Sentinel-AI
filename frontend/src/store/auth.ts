import { create } from 'zustand'
import { tokenStore } from '../lib/utils'
import type { UserMe } from '../types/api'

interface AuthState {
  token: string | null
  user: UserMe | null
  setToken: (token: string) => void
  setUser: (user: UserMe | null) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  token: tokenStore.get(),
  user: null,
  setToken: (token) => {
    tokenStore.set(token)
    set({ token })
  },
  setUser: (user) => set({ user }),
  logout: () => {
    tokenStore.clear()
    set({ token: null, user: null })
  },
}))

interface UiState {
  sidebarOpen: boolean
  toggleSidebar: () => void
  closeSidebar: () => void
}

export const useUiStore = create<UiState>((set) => ({
  sidebarOpen: false,
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  closeSidebar: () => set({ sidebarOpen: false }),
}))