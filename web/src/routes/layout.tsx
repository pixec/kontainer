import { Navigate, Outlet, useLocation } from "react-router"
import { AppShell } from "@/components/app-shell"
import { useSession } from "@/lib/session"
import { Loading } from "@/components/ui-bits"
import { LoginPage } from "./login"

export function Layout() {
  const { me, loading } = useSession()
  const loc = useLocation()
  if (loading) return <AppShell pending><Loading /></AppShell>
  // Auth enabled and nobody signed in: only Explore and public repositories are browsable.
  const publicPath = loc.pathname === "/explore" || loc.pathname.startsWith("/r/")
  const anonymous = !!me && me.auth_mode !== "none" && !me.username
  if (anonymous && loc.pathname === "/") return <Navigate to="/explore" replace />
  if (anonymous && !publicPath) return <LoginPage />
  return (
    <AppShell>
      <Outlet />
    </AppShell>
  )
}
