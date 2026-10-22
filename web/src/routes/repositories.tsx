import { useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { Link, useNavigate } from "react-router"
import { BoxIcon, CopyIcon, DownloadIcon, EllipsisIcon, ExternalLinkIcon, SettingsIcon } from "lucide-react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { endpoints, SETTINGS_ACTIONS } from "@/lib/api"
import { relativeTime } from "@/lib/time"
import { ErrorBox } from "@/components/ui-bits"
import { Skeleton } from "@/components/ui/skeleton"
import { Empty, LabeledSelect, SearchInput } from "@/components/page"
import { useScope } from "@/lib/scope"
import { StarToggle } from "@/components/star-button"
import { useSession } from "@/lib/session"
import { ImportDialog } from "@/components/import-dialog"
import { originLabel } from "@/components/repo-origin"
import { Button } from "@/components/ui/button"
import type { RepoSummary } from "@/lib/api"

const TYPES = { all: "All", public: "Public", private: "Private", mirror: "Mirrors", cache: "Caches", import: "Imported" } as const
type RepoType = keyof typeof TYPES
const SORTS = { updated: "Last updated", name: "Name", stars: "Stars", tags: "Tags" } as const
type Sort = keyof typeof SORTS
const matchesType = (r: RepoSummary, t: RepoType) =>
  t === "all" || (t === "public" || t === "private" ? r.visibility === t : r.origin?.kind === t)
const SORT_FN: Record<Sort, (a: RepoSummary, b: RepoSummary) => number> = {
  updated: (a, b) => (b.updated_at ?? "").localeCompare(a.updated_at ?? ""),
  name: (a, b) => a.name.localeCompare(b.name),
  stars: (a, b) => b.stars - a.stars || a.name.localeCompare(b.name),
  tags: (a, b) => b.tags - a.tags || a.name.localeCompare(b.name),
}

const ROW_PLACEHOLDERS = [["w-36", "w-64"], ["w-28", "w-48"], ["w-44", "w-56"], ["w-32", "w-40"], ["w-40", "w-60"]]

export function RepositoriesPage() {
  const [filter, setFilter] = useState("")
  const q = useQuery({ queryKey: ["repositories"], queryFn: endpoints.repositories })
  const { prefix, scope } = useScope()
  const { me } = useSession()
  const navigate = useNavigate()
  const [importing, setImporting] = useState(false)
  const [type, setType] = useState<RepoType>("all")
  const [sort, setSort] = useState<Sort>("updated")
  if (q.error) return <ErrorBox error={q.error} />
  const ns = prefix.replace(/\/$/, "")
  const mine = (q.data ?? []).filter((r) => r.name.startsWith(prefix))
  // Only offer types that exist here, so the menu never leads to an empty list.
  const types = (Object.keys(TYPES) as RepoType[]).filter((t) => t === "all" || mine.some((r) => matchesType(r, t)))
  const repos = mine.filter((r) => matchesType(r, type) && r.name.slice(prefix.length).toLowerCase().includes(filter.trim().toLowerCase())).sort(SORT_FN[sort])
  const filtered = type !== "all" || !!filter.trim()
  const pushHint = scope.kind === "personal" ? `${me?.username}/<name>` : `${scope.name}/<name>`
  return (
    <>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <SearchInput className="w-full sm:flex-1" placeholder={<>Find a repository in <span className="mx-1 font-mono text-foreground/70">{ns}</span> namespace</>} label={`Find a repository in ${ns} namespace`} value={filter} onChange={setFilter} />
        <div className="grid grid-cols-[1fr_1fr_auto] gap-2 sm:flex">
          <LabeledSelect label="Type" value={type} onChange={setType} options={types.map((t) => [t, TYPES[t]] as [RepoType, string])} className="w-full sm:w-auto" />
          <LabeledSelect label="Sort" value={sort} onChange={setSort} options={SORTS} className="w-full sm:w-auto" />
          {me?.username && <Button variant="outline" size="lg" onClick={() => setImporting(true)} aria-label="Import"><DownloadIcon /><span className="hidden sm:inline">Import</span></Button>}
        </div>
      </div>
      {filtered && (
        <div className="-mt-3 flex items-center gap-2 text-sm text-muted-foreground">
          <span><b className="font-semibold text-foreground tabular-nums">{repos.length}</b> {repos.length === 1 ? "result" : "results"}{type !== "all" && <> for <b className="font-semibold text-foreground">{TYPES[type].toLowerCase()}</b> repositories</>}{filter.trim() && <> matching <b className="font-semibold text-foreground">{filter.trim()}</b></>}</span>
          <button type="button" onClick={() => { setType("all"); setFilter("") }} className="hover:text-foreground hover:underline">Clear</button>
        </div>
      )}
      {me?.username && <ImportDialog namespace={scope.kind === "personal" ? me.username : scope.name} open={importing} onOpenChange={setImporting} />}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="pl-0">Name</TableHead>
            <TableHead className="w-28">Stars</TableHead>
            <TableHead className="w-28">Tags</TableHead>
            <TableHead className="hidden w-48 md:table-cell">Updated</TableHead>
            <TableHead className="w-12 pr-0" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {q.isLoading && ROW_PLACEHOLDERS.map((w, i) => (
            <TableRow key={i} className="placeholder-in hover:bg-transparent">
              <TableCell className="py-4 pl-0">
                <span className="flex items-center gap-4">
                  <span className="flex size-10 shrink-0 items-center justify-center"><Skeleton className="size-6 rounded-md" /></span>
                  <span className="flex-1 space-y-2"><Skeleton className={`h-4 ${w[0]}`} /><Skeleton className={`h-3 opacity-60 ${w[1]}`} /></span>
                </span>
              </TableCell>
              <TableCell><Skeleton className="h-4 w-10" /></TableCell>
              <TableCell><Skeleton className="h-5 w-7 rounded-md" /></TableCell>
              <TableCell className="hidden md:table-cell"><Skeleton className="h-3.5 w-24 opacity-60" /></TableCell>
              <TableCell className="pr-0" />
            </TableRow>
          ))}
          {q.data && repos.length === 0 && (
            <TableRow className="hover:bg-transparent"><TableCell colSpan={5} className="whitespace-normal">
              <Empty>No repositories{filtered ? " match" : " yet"}.{!filtered && <> Push one with <code className="font-mono text-xs">docker push {location.host}/{pushHint}:tag</code></>}</Empty>
            </TableCell></TableRow>
          )}
          {repos.map((r) => (
            <TableRow key={r.name} className="cursor-pointer" onClick={() => navigate(`/r/${r.name}`)}>
              <TableCell className="py-4 pl-0">
                <Link to={`/r/${r.name}`} onClick={(e) => e.stopPropagation()} className="group flex items-center gap-4">
                  <span className="flex size-10 shrink-0 items-center justify-center text-muted-foreground"><BoxIcon className="size-6" strokeWidth={1.5} /></span>
                  <span className="min-w-0">
                    <span className="flex items-center gap-2 text-[15px] font-medium group-hover:underline">
                      {r.name.slice(prefix.length) || r.name}
                      {r.visibility === "public" && <Badge variant="outline" className="font-normal text-muted-foreground">Public</Badge>}
                    </span>
                    {(r.description || r.origin) && (
                      <span className="block truncate text-sm text-muted-foreground">
                        {r.description || (() => { const o = originLabel(r.origin!); return <>{o.verb} <span className="font-mono text-xs">{o.what}</span></> })()}
                      </span>
                    )}
                  </span>
                </Link>
              </TableCell>
              <TableCell><StarToggle name={r.name} state={r} /></TableCell>
              <TableCell><span className="chip min-w-7 justify-center tabular-nums text-foreground">{r.tags}</span></TableCell>
              <TableCell className="hidden text-muted-foreground md:table-cell">{r.updated_at ? relativeTime(r.updated_at) : "—"}</TableCell>
              <TableCell className="pr-0 text-right" onClick={(e) => e.stopPropagation()}>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <button type="button" className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground data-[state=open]:bg-accent" title="Actions"><EllipsisIcon className="size-4" /></button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="w-52">
                    <DropdownMenuItem asChild><Link to={`/r/${r.name}`}><ExternalLinkIcon className="size-4" />Open</Link></DropdownMenuItem>
                    <DropdownMenuItem onClick={() => navigator.clipboard.writeText(`docker pull ${location.host}/${r.name}`).catch(() => {})}><CopyIcon className="size-4" />Copy pull command</DropdownMenuItem>
                    {r.actions.some((a) => SETTINGS_ACTIONS.includes(a)) && <DropdownMenuItem asChild><Link to={`/r/${r.name}?tab=settings`}><SettingsIcon className="size-4" />Settings</Link></DropdownMenuItem>}
                  </DropdownMenuContent>
                </DropdownMenu>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </>
  )
}
