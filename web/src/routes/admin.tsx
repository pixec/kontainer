import { useForm } from "@tanstack/react-form"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState, type ReactNode } from "react"
import { toast } from "sonner"
import { Outlet } from "react-router"
import { ActivityIcon, SendIcon, CheckCircle2Icon, CircleAlertIcon, InfoIcon, CopyIcon, GlobeIcon, HardDriveIcon, Loader2Icon, RefreshCwIcon, ShieldCheckIcon, Trash2Icon, UsersIcon, ServerIcon } from "lucide-react"
import { Link } from "react-router"
import { QuotaDialog, UsageBar } from "@/components/storage"
import { CveAllowlist } from "@/components/security-policy"
import { StorageLocations } from "@/components/storage-locations"
import { ScanBudget } from "@/components/admin-scanning"
import { Empty } from "@/components/page"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { endpoints, formatBytes, type Global, type Role, type Rule } from "@/lib/api"
import { formatDate, relativeTime } from "@/lib/time"
import { useSession } from "@/lib/session"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { cn } from "@/lib/utils"
import { RuleEditor } from "@/components/rule-editor"
import { Panel, SideNav } from "@/components/page"

export function AdminLayout() {
  const { me } = useSession()
  const has = (g: Global) => !!me?.globals.includes(g) || !!me?.globals.includes("system")
  return (
    <>
      <div className="grid items-start gap-8 lg:grid-cols-[13rem_minmax(0,1fr)]">
        <SideNav className="lg:sticky lg:top-30" items={[
          ...(has("users:read") ? [{ label: "Users", to: "/admin", exact: true, icon: <UsersIcon /> }] : []),
          ...(has("users:read") || has("roles:write") ? [{ label: "Roles", to: "/admin/roles", icon: <ShieldCheckIcon /> }] : []),
          ...(has("gc") || has("users:read") ? [{ label: "Storage", to: "/admin/storage", icon: <HardDriveIcon /> }] : []),
          ...(has("gc") ? [{ label: "Maintenance", to: "/admin/gc", icon: <Trash2Icon /> }] : []),
          ...(has("users:write") ? [{ label: "Registries", to: "/admin/registries", icon: <GlobeIcon /> }] : []),
          { label: "Mirrors", to: "/admin/mirrors", icon: <CopyIcon /> },
          ...(has("users:write") ? [{ label: "Replication", to: "/admin/replication", icon: <SendIcon /> }] : []),
          ...(me?.builds && me.globals.includes("system") ? [{ label: "Runners", to: "/admin/runners", icon: <ServerIcon /> }] : []),
          ...(has("gc") || has("users:read") ? [{ label: "Health", to: "/admin/health", icon: <ActivityIcon /> }] : []),
          { label: "About", to: "/admin/about", icon: <InfoIcon /> },
        ]} />
        <div className="flex min-w-0 flex-col gap-6"><Outlet /></div>
      </div>
    </>
  )
}


export function RolesPage() {
  const qc = useQueryClient()
  const { me } = useSession()
  const canWrite = me?.globals.includes("roles:write") || me?.globals.includes("system")
  const roles = useQuery({ queryKey: ["roles"], queryFn: endpoints.roles })
  const perms = useQuery({ queryKey: ["permissions"], queryFn: endpoints.permissions })
  const [draft, setDraft] = useState<Omit<Role, "is_managed"> | null>(null)
  const [isNew, setIsNew] = useState(false)
  const invalidate = () => qc.invalidateQueries({ queryKey: ["roles"] })
  const save = useMutation({
    meta: { success: "Role saved" },
    mutationFn: (r: Omit<Role, "is_managed">) => (isNew ? endpoints.createRole(r) : endpoints.updateRole(r.name, { description: r.description, rules: r.rules, global: r.global })),
    onSuccess: () => { setDraft(null); invalidate() },
  })
  const del = useMutation({ meta: { success: "Role deleted" }, mutationFn: endpoints.deleteRole, onSuccess: invalidate })
  if (roles.isLoading || perms.isLoading) return <Loading />
  if (roles.error) return <ErrorBox error={roles.error} />
  const startNew = () => { setIsNew(true); setDraft({ name: "", description: "", rules: [{ repositories: ["**"], actions: ["pull"] }], global: [] }) }
  return (
    <div className="space-y-4">
      {canWrite && !draft && <Button onClick={startNew}>New role</Button>}
      {draft && perms.data && (
        <Card>
          <CardHeader><CardTitle>{isNew ? "New role" : `Edit ${draft.name}`}</CardTitle><CardDescription>Repository rules grant actions on matching repositories (<Mono>*</Mono> one segment, <Mono>**</Mono> any depth). Global permissions apply registry-wide.</CardDescription></CardHeader>
          <CardContent className="space-y-4">
            <div className="grid sm:grid-cols-2 gap-2">
              <div className="space-y-1"><Label>Name</Label><Input value={draft.name} disabled={!isNew} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="team-a-developers" /></div>
              <div className="space-y-1"><Label>Description</Label><Input value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} /></div>
            </div>
            <div className="space-y-1"><Label>Repository rules</Label><RuleEditor rules={draft.rules} onChange={(rules: Rule[]) => setDraft({ ...draft, rules })} perms={perms.data} /></div>
            <div className="space-y-1">
              <Label>Global permissions</Label>
              <div className="grid sm:grid-cols-2 gap-1">
                {perms.data.global.map((g) => (
                  <label key={g.name} className="flex items-start gap-2 text-sm">
                    <Checkbox className="mt-0.5" checked={draft.global.includes(g.name)} onCheckedChange={(c) => setDraft({ ...draft, global: c ? [...draft.global, g.name] : draft.global.filter((x) => x !== g.name) })} />
                    <span><Mono>{g.name}</Mono> <span className="text-muted-foreground">— {g.description}</span></span>
                  </label>
                ))}
              </div>
            </div>
            <div className="flex gap-2"><Button onClick={() => save.mutate(draft)} disabled={save.isPending || !draft.name}>Save</Button><Button variant="ghost" onClick={() => setDraft(null)}>Cancel</Button></div>
            {save.error && <ErrorBox error={save.error} />}
          </CardContent>
        </Card>
      )}
      <Panel>
      <Table>
        <TableHeader><TableRow><TableHead className="pl-5">Role</TableHead><TableHead>Grants</TableHead><TableHead /></TableRow></TableHeader>
        <TableBody>
          {roles.data?.map((r) => (
            <TableRow key={r.name}>
              <TableCell className="pl-5"><div className="font-medium">{r.name} {r.is_managed && <Badge variant="secondary" title="defined in the config file">config</Badge>}</div><div className="text-xs text-muted-foreground">{r.description}</div></TableCell>
              <TableCell className="text-xs space-y-0.5">
                {r.global.length > 0 && <div><span className="text-muted-foreground">global:</span> {r.global.join(", ")}</div>}
                {r.rules.map((rule, i) => <div key={i}><Mono>{rule.repositories.join(", ")}</Mono> → {rule.actions.join(", ")}</div>)}
              </TableCell>
              <TableCell className="whitespace-nowrap text-right">
                {canWrite && !r.is_managed && (
                  <>
                    <Button variant="ghost" size="sm" onClick={() => { setIsNew(false); setDraft({ name: r.name, description: r.description, rules: r.rules, global: r.global }) }}>Edit</Button>
                    <Button variant="ghost" size="sm" onClick={() => { if (confirm(`Delete role ${r.name}? Users holding it lose those permissions.`)) del.mutate(r.name) }}>Delete</Button>
                  </>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      </Panel>
      {del.error && <ErrorBox error={del.error} />}
    </div>
  )
}

/** Garbage collection and scanning everything: run now, see the schedule and past runs. */
export function GcPage() {
  const qc = useQueryClient()
  const gc = useMutation({ mutationFn: (v: { dryRun: boolean; deleteUntagged: boolean }) => endpoints.gc(v.dryRun, v.deleteUntagged), onSettled: () => qc.invalidateQueries({ queryKey: ["task-runs", "gc"] }) })
  const form = useForm({
    defaultValues: { dryRun: true, deleteUntagged: false },
    onSubmit: async ({ value }) => {
      if (!value.dryRun && !confirm("Run garbage collection now? Make sure no pushes are in progress.")) return
      await gc.mutateAsync(value)
    },
  })
  const r = gc.data
  return (
    <div className="grid max-w-3xl gap-6">
      <Card>
        <CardHeader><CardTitle>Garbage collection</CardTitle><CardDescription>Removes blobs no manifest references. Objects written within the grace window are never touched.</CardDescription></CardHeader>
        <CardContent className="space-y-5">
          <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); form.handleSubmit() }}>
            <form.Field name="dryRun" children={(f) => (<label className="flex items-center gap-2 text-sm"><Checkbox checked={f.state.value} onCheckedChange={(c) => f.handleChange(!!c)} />Dry run (report only)</label>)} />
            <form.Field name="deleteUntagged" children={(f) => (<label className="flex items-center gap-2 text-sm"><Checkbox checked={f.state.value} onCheckedChange={(c) => f.handleChange(!!c)} />Also remove manifests not reachable from any tag</label>)} />
            <form.Subscribe selector={(s) => s.isSubmitting} children={(busy) => <Button type="submit" disabled={busy}>{busy ? "Running..." : "Run now"}</Button>} />
          </form>
          {gc.error && <ErrorBox error={gc.error} />}
          {r && (
            <div className="space-y-1 text-sm">
              <p>{r.is_dry_run ? "Would remove" : "Removed"} <b>{r.blobs_removed.length}</b> blobs ({formatBytes(r.bytes_freed)}), <b>{r.links_removed.length}</b> links, <b>{r.manifests_removed.length}</b> manifests, <b>{r.scans_removed.length}</b> scan reports across {r.repositories} repositories.</p>
              {r.blobs_removed.length > 0 && <pre className="max-h-60 overflow-auto rounded-lg border bg-muted/40 p-3 text-xs">{r.blobs_removed.join("\n")}</pre>}
            </div>
          )}
          <RunHistory kind="gc" scheduleHint={(i) => i ? <>Runs every <b>{i}</b> (<Mono>gc.interval</Mono>).</> : <>Not scheduled. Set <Mono>gc.interval</Mono> (e.g. <Mono>24h</Mono>) to run it automatically.</>} />
        </CardContent>
      </Card>
      <ScanEverything />
      <RegistryAllowlist />
    </div>
  )
}

function ScanEverything() {
  const qc = useQueryClient()
  const run = useMutation({
    mutationFn: (missingOnly: boolean) => endpoints.scanAll(missingOnly),
    onSuccess: (s) => toast.success(`Queued ${s.queued} of ${s.images} images for scanning`),
    onSettled: () => qc.invalidateQueries({ queryKey: ["task-runs", "scan_all"] }),
  })
  return (
    <Card>
      <CardHeader><CardTitle>Vulnerability scans</CardTitle><CardDescription>New vulnerabilities are published every day, so old reports go stale. Rescan every tagged image, or just the ones never scanned.</CardDescription></CardHeader>
      <CardContent className="space-y-5">
        <div className="flex flex-wrap gap-2">
          <Button disabled={run.isPending} onClick={() => run.mutate(false)}>Scan everything</Button>
          <Button variant="outline" disabled={run.isPending} onClick={() => run.mutate(true)}>Scan unscanned only</Button>
        </div>
        {run.error && <ErrorBox error={run.error} />}
        <ScanBudget />
        <RunHistory kind="scan_all" scheduleHint={(i) => i ? <>Images with reports older than <b>{i}</b> are rescanned automatically (<Mono>scanner.rescan_interval</Mono>).</> : <>No automatic rescans. Set <Mono>scanner.rescan_interval</Mono> (e.g. <Mono>7d</Mono>) to keep reports fresh.</>} />
      </CardContent>
    </Card>
  )
}

function RegistryAllowlist() {
  const { me } = useSession()
  const canEdit = !!me?.globals.includes("users:write") || !!me?.globals.includes("system")
  return (
    <Card>
      <CardHeader><CardTitle>Registry-wide CVE allowlist</CardTitle><CardDescription>Vulnerabilities that never count towards blocking pulls, in any namespace. Namespaces can add their own.</CardDescription></CardHeader>
      <CardContent><CveAllowlist namespace={null} canEdit={canEdit} /></CardContent>
    </Card>
  )
}

function RunHistory({ kind, scheduleHint }: { kind: "gc" | "scan_all"; scheduleHint: (interval: string | null) => ReactNode }) {
  const q = useQuery({ queryKey: ["task-runs", kind], queryFn: () => endpoints.taskRuns(kind), refetchInterval: (s) => (s.state.data?.runs.some((r) => r.status === "running") ? 2000 : false) })
  if (!q.data) return q.error ? <ErrorBox error={q.error} /> : null
  return (
    <div className="space-y-2 border-t pt-4">
      <p className="text-sm text-muted-foreground">{scheduleHint(q.data.interval)}</p>
      {q.data.runs.length > 0 && (
        <ul className="divide-y rounded-lg border text-sm">
          {q.data.runs.slice(0, 10).map((r) => (
            <li key={r.id} className="flex items-center gap-3 px-3 py-2">
              {r.status === "running" ? <Loader2Icon className="size-4 shrink-0 animate-spin text-muted-foreground" /> : r.status === "succeeded" ? <CheckCircle2Icon className="size-4 shrink-0 text-emerald-500" /> : <CircleAlertIcon className="size-4 shrink-0 text-destructive" />}
              <span className={cn("min-w-0 flex-1 truncate", r.status === "failed" && "text-destructive")} title={r.summary ?? ""}>{r.summary ?? "Running..."}</span>
              <span className="shrink-0 text-xs text-muted-foreground" title={formatDate(r.started_at)}>{r.trigger === "schedule" ? "scheduled" : r.actor} · {relativeTime(r.started_at)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export function StoragePage() {
  const { me } = useSession()
  const canSetQuota = !!me?.globals.includes("users:write") || !!me?.globals.includes("system")
  const canGc = !!me?.globals.includes("gc") || !!me?.globals.includes("system")
  const [refresh, setRefresh] = useState(false)
  const q = useQuery({ queryKey: ["storage", refresh], queryFn: () => endpoints.storageReport(refresh) })
  const [quotaFor, setQuotaFor] = useState<{ namespace: string; quota: number | null } | null>(null)
  const [sort, setSort] = useState<"bytes" | "unique_bytes" | "untagged_bytes">("bytes")
  if (q.isLoading) return <Loading />
  if (q.error) return <ErrorBox error={q.error} />
  const r = q.data!
  const stat = (label: string, value: string, hint: string) => (
    <div className="rounded-lg border bg-card p-4">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      <div className="mt-1 text-xs text-muted-foreground">{hint}</div>
    </div>
  )
  return (
    <>
      {canGc && <StorageLocations />}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">Computed {relativeTime(r.computed_at)} · {r.blobs} blobs across {r.repositories.length} repositories</p>
        <Button variant="outline" size="sm" onClick={() => setRefresh(true)} disabled={q.isFetching}><RefreshCwIcon className={q.isFetching ? "animate-spin" : ""} />Recompute</Button>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {stat("Physical", formatBytes(r.physical_bytes), "Everything stored, once per blob")}
        {stat("Logical", formatBytes(r.logical_bytes), "Sum of every repository's size")}
        {stat("Saved by sharing layers", formatBytes(r.dedup_savings), r.logical_bytes ? `${((r.dedup_savings / r.logical_bytes) * 100).toFixed(0)}% of logical` : "—")}
        {stat("Reclaimable now", formatBytes(r.unreferenced_bytes), `+ ${formatBytes(r.untagged_bytes)} held only by untagged manifests`)}
      </div>
      {(r.unreferenced_bytes > 0 || r.untagged_bytes > 0) && (
        <p className="text-sm text-muted-foreground">Run <Link to="/admin/gc" className="text-foreground underline-offset-4 hover:underline">garbage collection</Link> to free unreferenced space; enable "delete untagged" to also free space held by untagged manifests.</p>
      )}

      <Panel title="Namespaces" description="Distinct bytes per namespace (shared layers count once each), against its quota.">
        <Table>
          <TableHeader><TableRow><TableHead className="pl-4">Namespace</TableHead><TableHead className="text-right">Repositories</TableHead><TableHead className="w-80">Usage</TableHead><TableHead className="text-right">Unique</TableHead>{canSetQuota && <TableHead className="pr-4" />}</TableRow></TableHeader>
          <TableBody>
            {r.namespaces.length === 0 && <TableRow className="hover:bg-transparent"><TableCell colSpan={5}><Empty>Nothing stored yet.</Empty></TableCell></TableRow>}
            {[...r.namespaces].sort((a, b) => b.bytes - a.bytes).map((n) => (
              <TableRow key={n.namespace}>
                <TableCell className="pl-4 font-medium">{n.namespace}</TableCell>
                <TableCell className="text-right tabular-nums text-muted-foreground">{n.repositories}</TableCell>
                <TableCell><UsageBar used={n.bytes} quota={n.quota} /></TableCell>
                <TableCell className="text-right tabular-nums text-muted-foreground">{formatBytes(n.unique_bytes)}</TableCell>
                {canSetQuota && <TableCell className="pr-4 text-right"><Button size="sm" variant="ghost" onClick={() => setQuotaFor({ namespace: n.namespace, quota: n.quota })}>{n.quota ? "Change quota" : "Set quota"}</Button></TableCell>}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>

      <Panel title="Repositories" actions={
        <div className="flex gap-1 text-sm">
          {([["bytes", "Size"], ["unique_bytes", "Unique"], ["untagged_bytes", "Untagged"]] as const).map(([k, l]) => (
            <button key={k} type="button" onClick={() => setSort(k)} className={`rounded-md px-2 py-1 ${sort === k ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground"}`}>{l}</button>
          ))}
        </div>
      }>
        <Table>
          <TableHeader><TableRow><TableHead className="pl-4">Repository</TableHead><TableHead className="text-right">Tags</TableHead><TableHead className="text-right">Size</TableHead><TableHead className="text-right">Unique</TableHead><TableHead className="pr-4 text-right">Untagged</TableHead></TableRow></TableHeader>
          <TableBody>
            {[...r.repositories].sort((a, b) => b[sort] - a[sort]).slice(0, 50).map((x) => (
              <TableRow key={x.name}>
                <TableCell className="pl-4"><Link to={`/r/${x.name}`} className="hover:underline">{x.name}</Link></TableCell>
                <TableCell className="text-right tabular-nums text-muted-foreground">{x.tags}</TableCell>
                <TableCell className="text-right tabular-nums">{formatBytes(x.bytes)}</TableCell>
                <TableCell className="text-right tabular-nums text-muted-foreground">{formatBytes(x.unique_bytes)}</TableCell>
                <TableCell className="pr-4 text-right tabular-nums text-muted-foreground">{x.untagged_bytes ? formatBytes(x.untagged_bytes) : "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>

      {r.shared_layers.length > 0 && (
        <Panel title="Most shared layers" description="Stored once, used by several repositories. These are what deduplication saves.">
          <ul className="divide-y">
            {r.shared_layers.map((l) => (
              <li key={l.digest} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-sm">
                <Mono className="text-muted-foreground">{l.digest.slice(7, 19)}</Mono>
                <span className="tabular-nums">{formatBytes(l.size)}</span>
                <span className="text-muted-foreground">× {l.repositories.length} repositories</span>
                <span className="min-w-0 flex-1 truncate text-right text-xs text-muted-foreground" title={l.repositories.join(", ")}>{l.repositories.slice(0, 3).join(", ")}{l.repositories.length > 3 && ` +${l.repositories.length - 3}`}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
      {quotaFor && <QuotaDialog key={quotaFor.namespace} namespace={quotaFor.namespace} quota={quotaFor.quota} open onOpenChange={(v) => { if (!v) setQuotaFor(null) }} />}
    </>
  )
}
