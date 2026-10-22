import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react"
import { useQuery } from "@tanstack/react-query"
import { endpoints, type OrgSummary } from "./api"
import { cached, remember } from "./cached"
import { useSession } from "./session"

/** The workspace the UI is scoped to: the user's own namespace or one organization. */
export type Scope = { kind: "personal" } | { kind: "org"; name: string }

interface ScopeCtx {
  scope: Scope
  setScope: (s: Scope) => void
  /** Organizations the user is on a team of (admins can see others, but they aren't workspaces). */
  orgs: OrgSummary[]
  /** Repository prefix for the current scope, e.g. `zack/`. */
  prefix: string
  label: string
}

const Ctx = createContext<ScopeCtx | null>(null)
const KEY = "kontainer-scope"

export function ScopeProvider({ children }: { children: ReactNode }) {
  const { me, loading } = useSession()
  const orgsQuery = useQuery({ queryKey: ["orgs"], queryFn: endpoints.orgs, placeholderData: () => cached<OrgSummary[]>("orgs"), enabled: !!me?.username })
  useEffect(() => { if (orgsQuery.data && !orgsQuery.isPlaceholderData) remember("orgs", orgsQuery.data) }, [orgsQuery.data, orgsQuery.isPlaceholderData])
  // `is_joined` is missing from servers older than the UI: fall back to membership.
  const orgs = useMemo(() => (orgsQuery.data ?? []).filter((o) => o.is_joined ?? o.is_member), [orgsQuery.data])
  const [scope, setScopeState] = useState<Scope>(() => {
    try { const raw = localStorage.getItem(KEY); if (raw) return JSON.parse(raw) as Scope } catch { /* ignore */ }
    return { kind: "personal" }
  })
  // Drop a stale org scope once memberships are known, and reset when signed out. Not while the
  // session is still loading: that is every page load, and the saved workspace would be lost.
  useEffect(() => {
    if (loading) return
    if (!me?.username && scope.kind !== "personal") setScopeState({ kind: "personal" })
    if (scope.kind === "org" && orgsQuery.isSuccess && !orgsQuery.isPlaceholderData && !orgs.some((o) => o.name === scope.name)) setScopeState({ kind: "personal" })
  }, [loading, me?.username, orgs, orgsQuery.isSuccess, scope])
  const setScope = (s: Scope) => { setScopeState(s); try { localStorage.setItem(KEY, JSON.stringify(s)) } catch { /* ignore */ } }
  const prefix = scope.kind === "personal" ? `${me?.username ?? ""}/` : `${scope.name}/`
  const label = scope.kind === "personal" ? me?.display_name || me?.username || "Personal" : orgs.find((o) => o.name === scope.name)?.display_name || scope.name
  return <Ctx.Provider value={{ scope, setScope, orgs, prefix, label }}>{children}</Ctx.Provider>
}

export function useScope(): ScopeCtx {
  const c = useContext(Ctx)
  if (!c) throw new Error("useScope outside provider")
  return c
}
