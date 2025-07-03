import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface User {
  id: string;
  email: string;
  name: string;
  picture?: string;
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  setUser: (user: User | null) => void;
  setLoading: (loading: boolean) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      isAuthenticated: false,
      isLoading: true,
      setUser: (user) => {
        console.log('🔄 AuthStore: Setting user:', user?.email || 'null');
        set({ user, isAuthenticated: !!user });
      },
      setLoading: (isLoading) => {
        console.log('🔄 AuthStore: Setting loading:', isLoading);
        set({ isLoading });
      },
      logout: () => {
        console.log('🔄 AuthStore: Logging out');
        set({ user: null, isAuthenticated: false });
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
      onRehydrateStorage: () => (state) => {
        console.log('🔄 AuthStore: Rehydrated from storage:', {
          user: state?.user?.email || 'null',
          isAuthenticated: state?.isAuthenticated || false
        });
      },
    }
  )
);