import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import {
  User, LoginResult, me, login as apiLogin, verifyLoginCode, logout as apiLogout, tokenStore,
} from "./api";

interface AuthState {
  user: User | null;
  loading: boolean;
  /** Resolves to "needs-code" when the account has a second factor configured. */
  login: (username: string, password: string) => Promise<LoginResult>;
  /** Completes a login that stopped for a second factor. */
  verifyCode: (challenge: string, code: string) => Promise<void>;
  logout: () => void;
  /** Re-reads the account, e.g. after two-factor is switched on or off. */
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthState>(null as any);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    if (!tokenStore.get()) { setUser(null); return; }
    try {
      setUser((await me()).user);
    } catch {
      tokenStore.clear();
      setUser(null);
    }
  };

  // Restore a session from a persisted token on first load.
  useEffect(() => {
    refresh().finally(() => setLoading(false));
  }, []);

  const login = async (username: string, password: string) => {
    const result = await apiLogin(username, password);
    if (result.kind === "signed-in") setUser(result.user);
    return result;
  };

  const verifyCode = async (challenge: string, code: string) => {
    setUser(await verifyLoginCode(challenge, code));
  };

  const logout = () => {
    apiLogout();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, verifyCode, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
