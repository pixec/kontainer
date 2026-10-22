import { CheckIcon, ChevronsUpDownIcon, PlusIcon } from "lucide-react"
import { Avatar, OrgMark } from "@/components/page"
import { Link, useLocation, useNavigate } from "react-router"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useScope, type Scope } from "@/lib/scope"
import { useSession } from "@/lib/session"

/** Pages that already follow the current workspace (or none), so switching can stay on them. */
const SCOPED_PATHS = ["/", "/activity", "/stars", "/explore"]
/** Org tabs only admins see; the rest are open to every member. */
const ADMIN_TABS = ["robots", "settings"]

export function WorkspaceSwitcher() {
  const { me } = useSession()
  const { scope, setScope, orgs, label } = useScope()
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const canCreate = !!me?.globals.includes("orgs:create") || !!me?.globals.includes("system")

  if (!me?.username) return null

  // Pages tied to the old workspace (its repositories, org tabs, personal settings) would keep
  // showing it, so move to the same tab in the new workspace or its repository list.
  const switchTo = (next: Scope) => {
    setScope(next)
    if (SCOPED_PATHS.includes(pathname)) return
    const tab = pathname.match(/^\/orgs\/[^/]+\/([^/]+)/)?.[1]
    if (next.kind === "org" && tab && (!ADMIN_TABS.includes(tab) || orgs.find((o) => o.name === next.name)?.is_admin)) {
      navigate(`/orgs/${encodeURIComponent(next.name)}/${tab}`)
    } else {
      navigate("/")
    }
  }

  const row = "gap-2.5 px-2 py-1.5"
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button type="button" className="-ml-1.5 flex min-w-0 max-w-56 items-center gap-2 rounded-lg px-1.5 py-1 text-left transition-colors hover:bg-accent data-[state=open]:bg-accent">
          {scope.kind === "personal" ? <Avatar name={label} src={me.avatar_url} className="size-6 text-[10px]" /> : <OrgMark name={scope.name} label={label} className="size-6 rounded-md text-[11px]" />}
          <span className="min-w-0 flex-1 truncate text-sm font-semibold">{label}</span>
          <ChevronsUpDownIcon className="size-4 text-muted-foreground" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-64 p-1" align="start" sideOffset={8}>
        <DropdownMenuLabel className="px-2 py-1.5 text-xs font-normal text-muted-foreground">Workspace</DropdownMenuLabel>
        <DropdownMenuItem onClick={() => switchTo({ kind: "personal" })} className={row}>
          <Avatar name={me.display_name || me.username} src={me.avatar_url} className="size-7" />
          <span className="min-w-0 flex-1 truncate">{me.display_name || me.username}</span>
          {scope.kind === "personal" ? <CheckIcon className="size-4" /> : <span className="text-xs text-muted-foreground">Personal</span>}
        </DropdownMenuItem>
        {orgs.length > 0 && <DropdownMenuSeparator />}
        {orgs.length > 0 && <DropdownMenuLabel className="px-2 py-1.5 text-xs font-normal text-muted-foreground">Organizations</DropdownMenuLabel>}
        {orgs.map((o) => (
          <DropdownMenuItem key={o.id} onClick={() => switchTo({ kind: "org", name: o.name })} className={row}>
            <OrgMark name={o.name} label={o.display_name || o.name} className="size-7 rounded-md text-xs" />
            <span className="min-w-0 flex-1 truncate">{o.display_name || o.name}</span>
            {scope.kind === "org" && scope.name === o.name ? <CheckIcon className="size-4" /> : o.is_admin && <span className="text-xs text-muted-foreground">Admin</span>}
          </DropdownMenuItem>
        ))}
        {canCreate && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild className={row}>
              <Link to="/orgs">
                <span className="flex size-7 items-center justify-center rounded-md border border-dashed text-muted-foreground"><PlusIcon className="size-4" /></span>
                <span className="text-muted-foreground">New organization</span>
              </Link>
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
