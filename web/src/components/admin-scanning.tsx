import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { api } from "@/lib/api"
import { formatDate, relativeTime } from "@/lib/time"

/** `GET /api/v1/admin/scanning`: the automatic-scan budget and the queue, cluster-wide. */
export interface ScanningStatus {
  enabled: boolean
  /** `scanner.max_auto_per_hour`; 0: unlimited. */
  limit: number
  used: number
  window_resets_at: string | null
  skipped_in_window: number
  /** This instance, since it started, by reason (`budget`, `queue_full`). */
  skipped_since_start: Record<string, number>
  queue_depth: number
  /** `scanner.max_queue`; 0: unlimited. */
  max_queue: number
  override_until: string | null
  override_by: string | null
}

const scanning = () => api<ScanningStatus>("/api/v1/admin/scanning")
const setOverride = (hours: number) => api<{ override_until: string | null }>("/api/v1/admin/scanning/override", { method: "POST", body: JSON.stringify({ hours }) })

/** The scan budget: how many automatic scans this hour used, the queue, and an override. */
export function ScanBudget() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["admin-scanning"], queryFn: scanning, refetchInterval: 15_000 })
  const [hours, setHours] = useState("4")
  const lift = useMutation({
    mutationFn: (h: number) => setOverride(h),
    onSuccess: (r) => toast.success(r.override_until ? `Scan budget lifted until ${formatDate(r.override_until)}` : "Scan budget restored"),
    onSettled: () => qc.invalidateQueries({ queryKey: ["admin-scanning"] }),
  })
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorBox error={q.error} />
  const s = q.data
  const skipped = Object.values(s.skipped_since_start).reduce((a, b) => a + b, 0)
  const limited = s.limit > 0 && !s.override_until
  return (
    <div className="space-y-3 rounded-lg border p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-medium">Automatic scan budget</h3>
        {s.override_until ? <Badge variant="secondary">lifted until {formatDate(s.override_until)}{s.override_by ? ` by ${s.override_by}` : ""}</Badge> : s.limit === 0 ? <Badge variant="outline">unlimited</Badge> : null}
      </div>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-4">
        <div><dt className="text-muted-foreground">This hour</dt><dd><b>{s.used}</b>{s.limit > 0 && <> of {s.limit}</>}</dd></div>
        <div><dt className="text-muted-foreground">Resets</dt><dd>{s.window_resets_at ? relativeTime(s.window_resets_at) : "—"}</dd></div>
        <div><dt className="text-muted-foreground">Queue</dt><dd><b>{s.queue_depth}</b>{s.max_queue > 0 && <> of {s.max_queue}</>}</dd></div>
        <div><dt className="text-muted-foreground">Skipped</dt><dd><b>{s.skipped_in_window}</b> this hour · {skipped} here since start</dd></div>
      </dl>
      <p className="text-xs text-muted-foreground">
        Scans on push and scheduled rescans count against <Mono>scanner.max_auto_per_hour</Mono>; beyond it they are skipped. Scans someone starts are not counted. Every scan is skipped while the queue holds <Mono>scanner.max_queue</Mono>.
      </p>
      <div className="flex flex-wrap items-end gap-2">
        <div className="space-y-1">
          <Label htmlFor="scan-override-hours">Lift for (hours)</Label>
          <Input id="scan-override-hours" className="w-24" type="number" min={1} max={744} value={hours} onChange={(e) => setHours(e.target.value)} />
        </div>
        <Button variant="outline" disabled={lift.isPending || !(Number(hours) > 0)} onClick={() => lift.mutate(Math.floor(Number(hours)))}>{limited || s.limit === 0 ? "Lift budget" : "Extend"}</Button>
        {s.override_until && <Button variant="ghost" disabled={lift.isPending} onClick={() => lift.mutate(0)}>End override</Button>}
      </div>
      {lift.error && <ErrorBox error={lift.error} />}
    </div>
  )
}
