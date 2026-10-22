import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { createBrowserRouter, Navigate, RouterProvider, useLocation } from "react-router"
import { MutationCache, QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { toast } from "sonner"
import { Toaster } from "@/components/ui/sonner"
import "./index.css"
import { SessionProvider } from "./lib/session"
import { ScopeProvider } from "./lib/scope"
import { Layout } from "./routes/layout"
import { RepositoriesPage } from "./routes/repositories"
import { RepositoryPage } from "./routes/repository"
import { ManifestPage } from "./routes/manifest"
import { ScanPage } from "./routes/scan"
import { ComparePage } from "./routes/compare"
import { LogsPage } from "./routes/logs"
import { AdminLayout, GcPage, RolesPage, StoragePage } from "./routes/admin"
import { UsersPage } from "./routes/admin-users"
import { SettingsPage } from "./routes/settings"
import { AdminRunnersPage } from "./components/runners"
import { OrgPage, OrgsPage } from "./routes/orgs"
import { ExplorePage } from "./routes/explore"
import { HealthPage, MirrorsPage, RegistriesPage } from "./routes/remote"
import { ReplicationPage } from "./routes/replication"
import { AboutPage } from "./routes/about"
import { StarsPage } from "./routes/stars"
import { LoginPage } from "./routes/login"

declare module "@tanstack/react-query" {
  interface Register {
    /** `success`: toast when it succeeds. `error`: toast title when it fails, for actions
     * that have nowhere to show the error inline. */
    mutationMeta: { success?: string; error?: string }
  }
}

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, staleTime: 5_000 } },
  mutationCache: new MutationCache({
    onSuccess: (_data, _vars, _ctx, mutation) => { if (mutation.meta?.success) toast.success(mutation.meta.success) },
    onError: (error, _vars, _ctx, mutation) => {
      if (mutation.meta?.error) toast.error(mutation.meta.error, { description: error instanceof Error ? error.message : String(error) })
    },
  }),
})

const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  {
    path: "/",
    element: <Layout />,
    children: [
      { index: true, element: <RepositoriesPage /> },
      { path: "activity", element: <LogsPage /> },
      { path: "logs", element: <Navigate to="/activity" replace /> },
      { path: "settings", element: <SettingsPage /> },
      { path: "settings/:section", element: <SettingsPage /> },
      { path: "explore", element: <ExplorePage /> },
      { path: "stars", element: <StarsPage /> },
      { path: "orgs", element: <OrgsPage /> },
      { path: "orgs/:name", element: <OrgPage /> },
      { path: "orgs/:name/:tab", element: <OrgPage /> },
      { path: "orgs/:name/:tab/:section", element: <OrgPage /> },
      {
        path: "admin",
        element: <AdminLayout />,
        children: [
          { index: true, element: <UsersPage /> },
          { path: "roles", element: <RolesPage /> },
          { path: "gc", element: <GcPage /> },
          { path: "storage", element: <StoragePage /> },
          { path: "registries", element: <RegistriesPage /> },
          { path: "mirrors", element: <MirrorsPage /> },
          { path: "replication", element: <ReplicationPage /> },
          { path: "runners", element: <AdminRunnersPage /> },
          { path: "health", element: <HealthPage /> },
          { path: "about", element: <AboutPage /> },
        ],
      },
      { path: "r/*", element: <RepoRoute /> },
    ],
  },
])

/** Repository names contain slashes, so one splat route fans out on its tail. */
function RepoRoute() {
  const { pathname } = useLocation()
  const tail = decodeURIComponent(pathname.replace(/^\/r\//, ""))
  if (tail.endsWith("/compare")) return <ComparePage />
  if (tail.includes("/s/")) return <ScanPage />
  if (tail.includes("/m/")) return <ManifestPage />
  return <RepositoryPage />
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <SessionProvider>
        <ScopeProvider>
          <RouterProvider router={router} />
          <Toaster position="bottom-right" />
        </ScopeProvider>
      </SessionProvider>
    </QueryClientProvider>
  </StrictMode>,
)
