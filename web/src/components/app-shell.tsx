import { useEffect, useRef, useState, type ReactNode } from "react"
import { Link, NavLink, useLocation } from "react-router"
import { ActivityIcon, BotIcon, BuildingIcon, ContainerIcon, DatabaseIcon, LogOutIcon, MenuIcon, SettingsIcon, ShieldIcon, StarIcon, UsersIcon, XIcon } from "lucide-react"
import { WorkspaceSwitcher } from "@/components/workspace-switcher"
import { TabNav, TabNavLink, tabBarClass } from "@/components/ui/tabs"
import { Skeleton } from "@/components/ui/skeleton"
import { GlobalSearch } from "@/components/global-search"
import { useScope } from "@/lib/scope"
import { useSession } from "@/lib/session"
import type { Global } from "@/lib/api"
import { cn } from "@/lib/utils"

type Tab = { label: string; to: string; exact?: boolean; match?: string; also?: string[]; icon: React.ComponentType<{ className?: string }> }

/** Workspace tabs under the navbar: they follow the workspace switcher. */
function useTabs(): Tab[] {
  const { me } = useSession()
  const { scope, orgs } = useScope()
  if (!me?.username) return []
  const has = (g: Global) => me.globals.includes(g) || me.globals.includes("system")
  const adminHome = has("users:read") ? "/admin" : has("roles:write") ? "/admin/roles" : has("gc") ? "/admin/gc" : null
  if (scope.kind === "org") {
    const org = orgs.find((o) => o.name === scope.name)
    const base = `/orgs/${scope.name}`
    return [
      { label: "Repositories", to: "/", exact: true, also: ["/r/"], icon: DatabaseIcon },
      { label: "Teams", to: `${base}/teams`, icon: UsersIcon },
      ...(org?.is_admin ? [{ label: "Robot accounts", to: `${base}/robots`, icon: BotIcon }] : []),
      { label: "Activity", to: "/activity", icon: ActivityIcon },
      ...(org?.is_admin ? [{ label: "Settings", to: `${base}/settings`, icon: SettingsIcon }] : []),
    ]
  }
  return [
    { label: "Repositories", to: "/", exact: true, also: ["/r/"], icon: DatabaseIcon },
    { label: "Starred", to: "/stars", icon: StarIcon },
    { label: "Organizations", to: "/orgs", exact: true, icon: BuildingIcon },
    { label: "Activity", to: "/activity", icon: ActivityIcon },
    { label: "Settings", to: "/settings/profile", match: "/settings", icon: SettingsIcon },
    ...(adminHome ? [{ label: "Admin", to: adminHome, match: "/admin", icon: ShieldIcon }] : []),
  ]
}


function Logo() {
  return <Link to="/explore" className="flex shrink-0 items-center gap-2 text-sm font-semibold"><ContainerIcon className="size-5" /><span className="hidden sm:inline">Kontainer</span></Link>
}

function UserMenu() {
  const { me, logout } = useSession()
  if (!me?.username) return null
  return (
    <button type="button" onClick={() => logout()} title={`Sign out (${me.username})`} aria-label="Sign out"
      className="rounded-lg p-2 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground">
      <LogOutIcon className="size-4" />
    </button>
  )
}

/** The header's workspace switcher and tabs, before anyone is known (first visit only: later
 *  visits render from the last session). */
function PendingChrome() {
  return (
    <div className="placeholder-in contents">
      <span className="text-lg font-light text-muted-foreground/40">/</span>
      <Skeleton className="h-5 w-32" />
    </div>
  )
}

const PENDING_TABS = ["w-24", "w-16", "w-28", "w-16", "w-16"]

/** The page frame. `pending`: the session is still loading. */
export function AppShell({ children, pending }: { children: ReactNode; pending?: boolean }) {
  const { me } = useSession()
  const signedIn = !!me?.username
  const tabs = useTabs()
  const [mobileOpen, setMobileOpen] = useState(false)
  const { pathname } = useLocation()
  useEffect(() => { setMobileOpen(false) }, [pathname])
  const menuRef = useRef<HTMLDivElement>(null)
  // Close the mobile popover on outside tap or Escape.
  useEffect(() => {
    if (!mobileOpen) return
    const onDown = (e: MouseEvent | TouchEvent) => { if (!menuRef.current?.contains(e.target as Node)) setMobileOpen(false) }
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setMobileOpen(false) }
    window.addEventListener("mousedown", onDown); window.addEventListener("touchstart", onDown); window.addEventListener("keydown", onKey)
    return () => { window.removeEventListener("mousedown", onDown); window.removeEventListener("touchstart", onDown); window.removeEventListener("keydown", onKey) }
  }, [mobileOpen])
  const signIn = !pending && !signedIn && me?.auth_mode !== "none" && (
    <Link to="/login" className="flex h-8 shrink-0 items-center rounded-lg bg-primary px-3 text-sm font-medium text-primary-foreground hover:bg-primary/90">Sign in</Link>
  )

  return (
    <div className="min-h-svh bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b bg-background/85 backdrop-blur-md">
        <div className="mx-auto flex h-14 max-w-[88rem] items-center gap-3 px-4 sm:px-6 lg:px-10">
          <Logo />
          {pending ? <PendingChrome /> : signedIn && <><span className="text-lg font-light text-muted-foreground/40">/</span><WorkspaceSwitcher /></>}
          <div className="ml-auto flex items-center gap-2">
            <GlobalSearch className="hidden w-64 md:block lg:w-80" />
            {signIn}
            <UserMenu />
            <div ref={menuRef} className="relative md:hidden">
              <button type="button" onClick={() => setMobileOpen((o) => !o)} aria-expanded={mobileOpen} aria-label={mobileOpen ? "Close menu" : "Open menu"}
                className={cn("rounded-lg p-2 text-muted-foreground hover:bg-accent hover:text-foreground", mobileOpen && "bg-accent text-foreground")}>
                {mobileOpen ? <XIcon className="size-4" /> : <MenuIcon className="size-4" />}
              </button>
              {mobileOpen && (
                <div className="absolute right-0 top-full z-50 mt-2 w-[calc(100vw-2rem)] max-w-sm space-y-3 rounded-lg border bg-popover p-3 shadow-xl animate-in fade-in-0 zoom-in-95 slide-in-from-top-1">
                  <GlobalSearch onNavigate={() => setMobileOpen(false)} />
                  <nav className="space-y-0.5">
                    {tabs.map((t) => (
                      <NavLink key={t.to} to={t.to} end={t.to === "/"} className={({ isActive }) => cn("flex items-center gap-2.5 rounded-md px-3 py-2 text-sm hover:bg-accent", isActive ? "bg-accent text-foreground" : "text-muted-foreground")}><t.icon className="size-4 shrink-0" />{t.label}</NavLink>
                    ))}
                  </nav>
                </div>
              )}
            </div>
          </div>
        </div>
        {pending && (
          <div className={cn(tabBarClass, "placeholder-in mx-auto -mb-px max-w-[88rem] gap-1 px-1 shadow-none sm:px-3 lg:px-7")}>
            {PENDING_TABS.map((w, i) => <div key={i} className="mb-2 flex h-8 items-center gap-2 px-3"><Skeleton className="size-4" /><Skeleton className={cn("h-3.5", w)} /></div>)}
          </div>
        )}
        {tabs.length > 0 && (
          <TabNav // Page gutter minus each tab's 12px padding: the first icon lines up with the logo and page content.
            className="mx-auto -mb-px max-w-[88rem] px-1 shadow-none sm:px-3 lg:px-7">
            {tabs.map((t) => <TabNavLink key={t.to} to={t.to} exact={t.exact} match={t.match} also={t.also}><t.icon />{t.label}</TabNavLink>)}
          </TabNav>
        )}
      </header>

      <main className="mx-auto flex w-full max-w-[88rem] flex-col gap-8 px-4 py-6 sm:px-6 sm:py-8 lg:px-10 lg:py-10">{children}</main>
    </div>
  )
}
