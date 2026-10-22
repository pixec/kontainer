import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { CheckCircle2Icon, CircleAlertIcon, GlobeIcon, Loader2Icon, RefreshCwIcon, TriangleAlertIcon } from "lucide-react"
import { Panel } from "@/components/page"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ErrorBox, Mono } from "@/components/ui-bits"
import { endpoints, formatBytes, type StorageLocation } from "@/lib/api"
import { relativeTime, formatSeconds } from "@/lib/time"

const DRIVER: Record<StorageLocation["driver"], string> = { filesystem: "Filesystem", s3: "S3", gcs: "Google Cloud Storage", azure: "Azure Blob", memory: "Memory", unknown: "Not configured" }

function LocationStatus({ loc }: { loc: StorageLocation }) {
  if (!loc.configured) {
    return (
      <span className="flex items-center gap-1.5 text-warning">
        <TriangleAlertIcon className="size-3.5 shrink-0" />Unknown location: run <Mono>kontainer storage forget-location {loc.name}</Mono>
      </span>
    )
  }
  if (loc.failed > 0) {
    return (
      <span className="flex min-w-0 items-center gap-1.5" title={loc.last_error ?? undefined}>
        <TriangleAlertIcon className="size-3.5 shrink-0 text-warning" />
        <span className="truncate">{loc.failed.toLocaleString()} copies failed{loc.pending > 0 && <span className="text-muted-foreground"> · {loc.pending.toLocaleString()} pending</span>}</span>
      </span>
    )
  }
  if (loc.pending > 0) return <span className="flex items-center gap-1.5 text-muted-foreground"><Loader2Icon className="size-3.5 animate-spin" />{loc.pending.toLocaleString()} copies pending</span>
  return <span className="flex items-center gap-1.5 text-muted-foreground"><CheckCircle2Icon className="size-3.5 text-emerald-500" />Up to date</span>
}

/** Where storage lives: every location (all peers), with what each holds and still has to receive. */
export function StorageLocations() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["storage-locations"], queryFn: endpoints.storageLocations, refetchInterval: (q) => (q.state.data?.syncing || q.state.data?.pending ? 2000 : 30_000) })
  const sync = useMutation({
    meta: { success: "Storage sync started" },
    mutationFn: endpoints.syncReplicas,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["storage-locations"] }); qc.invalidateQueries({ queryKey: ["jobs"] }) },
  })
  if (q.error) return <ErrorBox error={q.error} />
  if (!q.data) return null
  const d = q.data
  const replicating = d.locations.filter((l) => l.configured).length > 1
  return (
    <Panel icon={<GlobeIcon />} title="Locations"
      description={replicating
        ? <>Each instance writes to its preferred location; new blobs are copied to the others as they arrive, and missing ones are looked for every {formatSeconds(d.replication_interval_secs)}.{d.pending > 0 && <> {d.pending} copies waiting.</>}</>
        : "Add [[storage.locations]] to keep copies in other regions."}
      actions={replicating && (
        <Button variant="outline" size="sm" disabled={d.syncing || sync.isPending} onClick={() => sync.mutate()}>
          <RefreshCwIcon className={d.syncing ? "animate-spin" : ""} />{d.syncing ? "Syncing..." : "Sync now"}
        </Button>
      )}>
      <ul className="divide-y">
        {d.locations.map((loc) => (
          <li key={loc.name} className="flex flex-wrap items-center gap-x-4 gap-y-1.5 px-4 py-3 text-sm">
            <div className="min-w-40 flex-1">
              <div className="flex items-center gap-2 font-medium">
                {loc.name}
                {loc.preferred && <Badge variant="outline" className="font-normal text-muted-foreground">This instance</Badge>}
              </div>
              <div className="text-xs text-muted-foreground">
                {DRIVER[loc.driver]}
                {loc.redirect ? " · downloads redirected" : loc.configured && loc.regions.length === 0 && !loc.preferred ? " · standby" : ""}
                {loc.regions.length > 0 && <> · serves {loc.regions.map((r, j) => <span key={r}>{j > 0 && ", "}<Mono>{r}</Mono></span>)}</>}
              </div>
            </div>
            <div className="flex min-w-0 flex-col items-end gap-0.5 text-right">
              <LocationStatus loc={loc} />
              <span className="text-xs text-muted-foreground">
                {loc.blobs.toLocaleString()} blobs ({formatBytes(loc.bytes)})
                {loc.stats.copied > 0 && <> · {loc.stats.copied.toLocaleString()} copied here by this instance ({formatBytes(loc.stats.copied_bytes)})</>}
              </span>
              {loc.last_error && loc.last_error_at && (
                <span className="flex max-w-md items-center gap-1 truncate text-xs text-destructive" title={loc.last_error}>
                  <CircleAlertIcon className="size-3 shrink-0" />{relativeTime(loc.last_error_at)}: {loc.last_error}
                </span>
              )}
            </div>
          </li>
        ))}
      </ul>
      {replicating && (
        <p className="border-t px-4 py-3 text-xs text-muted-foreground">
          {d.region_header
            ? <>Downloads are read from the location serving the client's <Mono>{d.region_header}</Mono> when it has the blob, else from this instance's location; download links last {formatSeconds(d.redirect_ttl_secs)}.</>
            : <>No <Mono>storage.region_header</Mono> is set: downloads are read from this instance's location, and from the others when it lacks a blob or fails.</>}
        </p>
      )}
      {sync.error && <div className="border-t p-4"><ErrorBox error={sync.error} /></div>}
    </Panel>
  )
}
