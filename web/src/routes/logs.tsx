import { useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { Link } from "react-router"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { endpoints, shortDigest, type AuditEntry } from "@/lib/api"
import { formatDate, relativeTime, daysFromNow } from "@/lib/time"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { Empty, SearchInput } from "@/components/page"
import { useScope } from "@/lib/scope"
import { cn } from "@/lib/utils"
import { DownloadIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { LabeledSelect } from "@/components/page"

const RANGES = { "7": "Last 7 days", "30": "Last 30 days", "90": "Last 90 days", all: "Everything" } as const
const FORMATS = { csv: "CSV", json: "JSON Lines" } as const

/** Download the workspace's activity as CSV or JSON Lines. */
function ExportDialog({ namespace, search, onClose }: { namespace: string; search: string; onClose: () => void }) {
  const [range, setRange] = useState<keyof typeof RANGES>("30")
  const [format, setFormat] = useState<keyof typeof FORMATS>("csv")
  const params = new URLSearchParams({ namespace, format })
  if (search.trim()) params.set("q", search.trim())
  if (range !== "all") params.set("since", daysFromNow(-Number(range)))
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Export activity</DialogTitle>
          <DialogDescription>Everything you can see in {namespace}/{search.trim() ? <> matching “{search.trim()}”</> : null}, newest first. The export itself is logged.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-2 sm:grid-cols-2">
          <LabeledSelect label="Range" value={range} onChange={setRange} options={RANGES} className="w-full" />
          <LabeledSelect label="Format" value={format} onChange={setFormat} options={FORMATS} className="w-full" />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button asChild onClick={() => setTimeout(onClose, 300)}><a href={`/api/v1/logs/export?${params}`} download><DownloadIcon />Download</a></Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Colour by consequence: destructive red, failures amber, writes neutral-bright, reads muted. */
function tone(action: string) {
  if (action.startsWith("delete") || action.endsWith("_deleted") || action === "gc") return "bg-destructive/10 text-destructive"
  if (action.endsWith("_failed")) return "bg-warning/10 text-warning"
  if (action === "pull" || action === "login" || action === "logout") return ""
  return "bg-foreground/10 text-foreground"
}

function Target({ e }: { e: AuditEntry }) {
  if (e.repository) {
    const ref = e.reference ?? (e.digest ? shortDigest(e.digest) : null)
    return (
      <span className="min-w-0 truncate">
        <Link to={`/r/${e.repository}`} className="hover:underline">{e.repository}</Link>
        {ref && <Mono className="text-muted-foreground">:{ref}</Mono>}
      </span>
    )
  }
  if (e.org) return <Link to={`/orgs/${e.org}`} className="truncate hover:underline">{e.org}</Link>
  return <span className="text-muted-foreground">—</span>
}

export function LogsPage() {
  const { prefix, label } = useScope()
  const [search, setSearch] = useState("")
  // The workspace namespace. For the personal one the server also includes the user's own
  // account events (logins, tokens); for an org, its team and robot changes.
  const ns = prefix.replace(/\/$/, "")
  const [exporting, setExporting] = useState(false)
  const q = useQuery({ queryKey: ["logs", ns, search], queryFn: () => endpoints.logs({ namespace: ns, q: search || undefined }) })
  return (
    <>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <SearchInput className="w-full sm:flex-1" placeholder={<>Filter activity in <span className="mx-1 font-mono text-foreground/70">{ns}</span> namespace by repository</>} label="Filter activity by repository" value={search} onChange={setSearch} />
        <Button variant="outline" size="lg" onClick={() => setExporting(true)}><DownloadIcon />Export</Button>
      </div>
      {exporting && <ExportDialog namespace={ns} search={search} onClose={() => setExporting(false)} />}
      {q.isLoading && <Loading />}
      {q.error && <ErrorBox error={q.error} />}
      {q.data && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-36 pl-0">When</TableHead>
              <TableHead className="w-48">Actor</TableHead>
              <TableHead className="w-44">Action</TableHead>
              <TableHead>Target</TableHead>
              <TableHead className="hidden lg:table-cell">Detail</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {q.data.length === 0 && (
              <TableRow className="hover:bg-transparent"><TableCell colSpan={5}><Empty>{search ? "No entries match." : `Nothing has happened in ${label} yet.`}</Empty></TableCell></TableRow>
            )}
            {q.data.map((e) => (
              <TableRow key={e.id}>
                <TableCell className="py-3 pl-0 text-muted-foreground" title={formatDate(e.timestamp)}>{relativeTime(e.timestamp)}</TableCell>
                <TableCell>
                  <span className="flex items-center gap-2">
                    <span className="flex size-6 shrink-0 items-center justify-center rounded-full border bg-secondary text-[11px] font-semibold uppercase">{e.actor[0]}</span>
                    <span className="truncate">{e.actor}</span>
                    {e.is_robot && <span className="rounded border px-1 text-[10px] uppercase tracking-wide text-muted-foreground">bot</span>}
                  </span>
                </TableCell>
                <TableCell><span className={cn("chip", tone(e.action))}>{e.action.replace(/_/g, " ")}</span></TableCell>
                <TableCell className="max-w-0"><Target e={e} /></TableCell>
                <TableCell className="hidden max-w-xs truncate text-muted-foreground lg:table-cell" title={e.detail}>{e.detail}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </>
  )
}
