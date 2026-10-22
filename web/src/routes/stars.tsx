import { useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { Link, useNavigate } from "react-router"
import { BoxIcon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { endpoints } from "@/lib/api"
import { relativeTime } from "@/lib/time"
import { ErrorBox, Loading } from "@/components/ui-bits"
import { Empty, SearchInput } from "@/components/page"
import { StarToggle } from "@/components/star-button"
import { useScope } from "@/lib/scope"

export function StarsPage() {
  const [filter, setFilter] = useState("")
  const q = useQuery({ queryKey: ["stars"], queryFn: endpoints.stars })
  const navigate = useNavigate()
  const { prefix, label } = useScope()
  const [everywhere, setEverywhere] = useState(false)
  if (q.isLoading) return <Loading />
  if (q.error) return <ErrorBox error={q.error} />
  // Stars belong to the user; the list follows the workspace switcher unless widened.
  const inScope = (q.data ?? []).filter((r) => everywhere || r.name.startsWith(prefix))
  const hidden = (q.data ?? []).length - inScope.length
  const repos = inScope.filter((r) => r.name.toLowerCase().includes(filter.toLowerCase()))
  return (
    <>
      <SearchInput className="w-full sm:w-full" placeholder={everywhere ? "Find a starred repository..." : <>Find a starred repository in <span className="mx-1 font-mono text-foreground/70">{prefix.replace(/\/$/, "")}</span> namespace</>} label="Find a starred repository" value={filter} onChange={setFilter} />
      {(hidden > 0 || everywhere) && (
        <div className="-mt-2 flex items-center gap-2 text-sm text-muted-foreground">
          {everywhere
            ? <button type="button" className="text-foreground hover:underline" onClick={() => setEverywhere(false)}>Only show {label}</button>
            : <>{hidden} more in other workspaces · <button type="button" className="text-foreground hover:underline" onClick={() => setEverywhere(true)}>Show all</button></>}
        </div>
      )}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="pl-0">Name</TableHead>
            <TableHead className="w-28">Stars</TableHead>
            <TableHead className="w-28">Tags</TableHead>
            <TableHead className="hidden w-48 md:table-cell">Updated</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {repos.length === 0 && (
            <TableRow className="hover:bg-transparent"><TableCell colSpan={4} className="whitespace-normal">
              <Empty>{filter ? "No starred repositories match." : everywhere || hidden === 0 ? "You haven't starred any repositories yet. Use the Star button on a repository to keep it here." : `You haven't starred anything in ${label} yet.`}</Empty>
            </TableCell></TableRow>
          )}
          {repos.map((r) => (
            <TableRow key={r.name} className="cursor-pointer" onClick={() => navigate(`/r/${r.name}`)}>
              <TableCell className="py-4 pl-0">
                <Link to={`/r/${r.name}`} onClick={(e) => e.stopPropagation()} className="group flex items-center gap-4">
                  <span className="flex size-10 shrink-0 items-center justify-center text-muted-foreground"><BoxIcon className="size-6" strokeWidth={1.5} /></span>
                  <span className="min-w-0">
                    <span className="flex items-center gap-2 text-[15px] font-medium group-hover:underline">
                      {everywhere ? r.name : r.name.slice(prefix.length)}
                      {r.visibility === "public" && <Badge variant="outline" className="font-normal text-muted-foreground">Public</Badge>}
                    </span>
                    {r.description && <span className="block truncate text-sm text-muted-foreground">{r.description}</span>}
                  </span>
                </Link>
              </TableCell>
              <TableCell><StarToggle name={r.name} state={{ stars: r.stars, is_starred: true }} /></TableCell>
              <TableCell><span className="chip min-w-7 justify-center tabular-nums text-foreground">{r.tags}</span></TableCell>
              <TableCell className="hidden text-muted-foreground md:table-cell">{r.updated_at ? relativeTime(r.updated_at) : "—"}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </>
  )
}
