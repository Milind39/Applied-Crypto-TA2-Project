import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { User } from '../types';
import * as api from '../services/api';
import { clearKeysFromIndexedDB } from '../crypto/key-management';

interface AuthContextValue {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<User>;
  register: (
    username: string,
    email: string,
    password: string,
    confirmPassword: string
  ) => Promise<User>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const SESSION_TOKEN_KEY = 'pq_socket_token';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() =>
    sessionStorage.getItem(SESSION_TOKEN_KEY)
  );
  const [isLoading, setIsLoading] = useState(true);

  const refreshUser = useCallback(async () => {
    try {
      const { user: me } = await api.getMe();
      setUser(me);
    } catch {
      setUser(null);
      setToken(null);
      sessionStorage.removeItem(SESSION_TOKEN_KEY);
    }
  }, []);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const { user: me } = await api.getMe();
        if (mounted) setUser(me);
      } catch {
        if (mounted) {
          setUser(null);
          setToken(null);
          sessionStorage.removeItem(SESSION_TOKEN_KEY);
        }
      } finally {
        if (mounted) setIsLoading(false);
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  const login = useCallback(async (email: string, password: string): Promise<User> => {
    const res = await api.login(email, password);
    setUser(res.user);
    setToken(res.token);
    sessionStorage.setItem(SESSION_TOKEN_KEY, res.token);
    return res.user;
  }, []);

  const register = useCallback(
    async (
      username: string,
      email: string,
      password: string,
      confirmPassword: string
    ): Promise<User> => {
      const res = await api.register(username, email, password, confirmPassword);
      setUser(res.user);
      setToken(res.token);
      sessionStorage.setItem(SESSION_TOKEN_KEY, res.token);
      return res.user;
    },
    []
  );

  const logout = useCallback(async () => {
    const currentUserId = user?.id;
    try {
      await api.logout();
    } catch {
      // Ignore network errors during logout cleanup
    } finally {
      await clearKeysFromIndexedDB(currentUserId).catch(() => {});
      setUser(null);
      setToken(null);
      sessionStorage.removeItem(SESSION_TOKEN_KEY);
    }
  }, [user?.id]);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: Boolean(user),
        isLoading,
        login,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
