import { createContext, useContext, useEffect, type ReactNode } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { ApiError, endpoints, type Me } from "./api"
import { cached, forgetCached, remember } from "./cached"
import { signInWithPasskey } from "./webauthn"

interface Session {
  me: Me | undefined
  loading: boolean
  error: unknown
  /** Resolves to "mfa" when a one-time code is required. */
  login: (user: string, pass: string, otp?: string, recovery?: string) => Promise<"ok" | "mfa">
  /** A passkey is both factors: no one-time code follows. */
  loginWithPasskey: (user?: string) => Promise<void>
  logout: () => Promise<void>
  refresh: () => Promise<void>
}

const SessionContext = createContext<Session | null>(null)

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  // The last known session renders the page straight away; the real one replaces it moments later.
  const query = useQuery({ queryKey: ["me"], queryFn: endpoints.me, placeholderData: () => cached<Me>("me"), retry: false })
  useEffect(() => { if (query.data && !query.isPlaceholderData) remember("me", query.data) }, [query.data, query.isPlaceholderData])
  const refresh = async () => { await qc.invalidateQueries({ queryKey: ["me"] }); await query.refetch() }
  const login = async (user: string, pass: string, otp?: string, recovery?: string): Promise<"ok" | "mfa"> => {
    try {
      await endpoints.login(user, pass, otp, recovery)
    } catch (e) {
      if (e instanceof ApiError && e.status === 401 && (e.body as { mfa_required?: boolean })?.mfa_required) return "mfa"
      throw e
    }
    forgetCached()
    qc.clear()
    await refresh()
    return "ok"
  }
  const loginWithPasskey = async (user?: string) => {
    await signInWithPasskey(user)
    forgetCached()
    qc.clear()
    await refresh()
  }
  const logout = async () => { try { await endpoints.logout() } catch { /* ignore */ } forgetCached(); qc.clear(); await refresh() }
  return (
    <SessionContext.Provider value={{ me: query.data, loading: query.isLoading, error: query.error, login, loginWithPasskey, logout, refresh }}>
      {children}
    </SessionContext.Provider>
  )
}

export function useSession(): Session {
  const s = useContext(SessionContext)
  if (!s) throw new Error("useSession outside provider")
  return s
}
