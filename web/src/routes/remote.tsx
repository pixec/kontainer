import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { Link } from "react-router"
import { CheckCircle2Icon, CircleAlertIcon, Loader2Icon, PlusIcon, RefreshCwIcon, TriangleAlertIcon } from "lucide-react"
import { Empty, Panel } from "@/components/page"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { endpoints, type HealthCheck, type Job, type Mirror, type MirrorInput, type ProxyCache, type RegistryInput, type UpstreamRegistry } from "@/lib/api"
import { relativeTime, formatSeconds } from "@/lib/time"
import { cn } from "@/lib/utils"

const DURATIONS = [300, 900, 3600, 6 * 3600, 86400, 7 * 86400]

function Field({ id, label, hint, children }: { id?: string; label: string; hint?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

function DurationSelect({ value, onChange, id }: { value: number; onChange: (v: number) => void; id?: string }) {
  return (
    <Select value={String(value)} onValueChange={(v) => onChange(Number(v))}>
      <SelectTrigger id={id} className="w-full"><SelectValue /></SelectTrigger>
      <SelectContent>{DURATIONS.map((v) => <SelectItem key={v} value={String(v)}>{formatSeconds(v)}</SelectItem>)}</SelectContent>
    </Select>
  )
}

export function RegistrySelect({ registries, value, onChange, id }: { registries: UpstreamRegistry[]; value: number | null; onChange: (v: number) => void; id?: string }) {
  return (
    <Select value={value ? String(value) : undefined} onValueChange={(v) => onChange(Number(v))}>
      <SelectTrigger id={id} className="w-full"><SelectValue placeholder="Choose a registry" /></SelectTrigger>
      <SelectContent>{registries.map((r) => <SelectItem key={r.id} value={String(r.id)}>{r.name} <span className="text-muted-foreground">{r.url}</span></SelectItem>)}</SelectContent>
    </Select>
  )
}

// Registries
function RegistryDialog({ registry, onClose }: { registry: UpstreamRegistry | null; onClose: () => void }) {
  const qc = useQueryClient()
  const [v, setV] = useState<RegistryInput>({ name: registry?.name ?? "", url: registry?.url ?? "", username: registry?.username ?? "", password: "", is_insecure: registry?.is_insecure ?? false })
  const save = useMutation({
    meta: { success: "Registry saved" },
    mutationFn: () => {
      const body = { ...v, username: v.username || undefined, password: v.password || undefined }
      return registry ? endpoints.updateRegistry(registry.id, body) : endpoints.createRegistry(body)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["registries"] }); onClose() },
  })
  const set = (patch: Partial<RegistryInput>) => setV((x) => ({ ...x, ...patch }))
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-lg">
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
          <DialogHeader>
            <DialogTitle>{registry ? `Edit ${registry.name}` : "Add registry"}</DialogTitle>
            <DialogDescription>Another registry to cache, mirror or import from.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field id="reg-name" label="Name"><Input id="reg-name" autoFocus value={v.name} onChange={(e) => set({ name: e.target.value })} placeholder="dockerhub" /></Field>
            <Field id="reg-url" label="URL"><Input id="reg-url" value={v.url} onChange={(e) => set({ url: e.target.value })} placeholder="docker.io" /></Field>
            <Field id="reg-user" label="Username"><Input id="reg-user" autoComplete="off" value={v.username ?? ""} onChange={(e) => set({ username: e.target.value })} placeholder="optional" /></Field>
            <Field id="reg-pass" label="Password or token"><Input id="reg-pass" type="password" autoComplete="new-password" value={v.password ?? ""} onChange={(e) => set({ password: e.target.value })} placeholder={registry ? "unchanged" : "optional"} /></Field>
          </div>
          <label className="flex items-center gap-2 text-sm"><Checkbox checked={v.is_insecure} onCheckedChange={(c) => set({ is_insecure: !!c })} />Skip TLS certificate verification</label>
          {save.error && <ErrorBox error={save.error} />}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={!v.name || !v.url || save.isPending}>{registry ? "Save" : "Add registry"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function TestResult({ id }: { id: number }) {
  const test = useMutation({ meta: { error: "Connection test failed" }, mutationFn: () => endpoints.testRegistry(id) })
  return (
    <span className="inline-flex items-center gap-2">
      {test.data && (test.data.ok
        ? <span className="inline-flex items-center gap-1 text-xs text-emerald-500"><CheckCircle2Icon className="size-3.5" />{test.data.latency_ms} ms</span>
        : <span className="inline-flex max-w-56 items-center gap-1 truncate text-xs text-destructive" title={test.data.message}><CircleAlertIcon className="size-3.5 shrink-0" />{test.data.message}</span>)}
      <Button size="sm" variant="ghost" disabled={test.isPending} onClick={() => test.mutate()}>{test.isPending ? <Loader2Icon className="animate-spin" /> : "Test"}</Button>
    </span>
  )
}

function ProxyDialog({ registries, onClose }: { registries: UpstreamRegistry[]; onClose: () => void }) {
  const qc = useQueryClient()
  const [v, setV] = useState({ namespace: "", registry_id: registries[0]?.id ?? 0, ttl_secs: 3600, is_public: false })
  const save = useMutation({
    meta: { success: "Pull-through cache saved" },
    mutationFn: () => endpoints.createProxyCache(v),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["proxy-caches"] }); onClose() },
  })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
          <DialogHeader>
            <DialogTitle>New pull-through cache</DialogTitle>
            <DialogDescription>Pulls under the namespace are fetched from the registry the first time and served locally after.</DialogDescription>
          </DialogHeader>
          <Field id="px-ns" label="Namespace" hint={v.namespace && <>e.g. <Mono>docker pull {location.host}/{v.namespace}/library/alpine</Mono></>}>
            <Input id="px-ns" autoFocus value={v.namespace} onChange={(e) => setV({ ...v, namespace: e.target.value.toLowerCase() })} placeholder="hub" />
          </Field>
          <Field id="px-reg" label="Upstream"><RegistrySelect id="px-reg" registries={registries} value={v.registry_id} onChange={(id) => setV({ ...v, registry_id: id })} /></Field>
          <Field id="px-ttl" label="Recheck tags after" hint="Pulls by digest never recheck. If the upstream is down, the cached copy is served."><DurationSelect id="px-ttl" value={v.ttl_secs} onChange={(t) => setV({ ...v, ttl_secs: t })} /></Field>
          <label className="flex items-center gap-2 text-sm"><Checkbox checked={v.is_public} onCheckedChange={(c) => setV({ ...v, is_public: !!c })} />Allow anonymous pulls</label>
          {save.error && <ErrorBox error={save.error} />}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={!v.namespace || !v.registry_id || save.isPending}>Create cache</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export function RegistriesPage() {
  const qc = useQueryClient()
  const regs = useQuery({ queryKey: ["registries"], queryFn: endpoints.registries })
  const proxies = useQuery({ queryKey: ["proxy-caches"], queryFn: endpoints.proxyCaches })
  const [editing, setEditing] = useState<UpstreamRegistry | "new" | null>(null)
  const [proxyOpen, setProxyOpen] = useState(false)
  const delReg = useMutation({ meta: { success: "Registry deleted" }, mutationFn: endpoints.deleteRegistry, onSuccess: () => qc.invalidateQueries({ queryKey: ["registries"] }) })
  const delProxy = useMutation({ meta: { success: "Pull-through cache deleted" }, mutationFn: endpoints.deleteProxyCache, onSuccess: () => qc.invalidateQueries({ queryKey: ["proxy-caches"] }) })
  if (regs.isLoading) return <Loading />
  if (regs.error) return <ErrorBox error={regs.error} />
  const list = regs.data ?? []
  const name = (id: number) => list.find((r) => r.id === id)?.name ?? `#${id}`
  return (
    <>
      <Panel title="Registries" description="Credentials for other registries, used by caches, mirrors and imports." actions={<Button size="sm" onClick={() => setEditing("new")}><PlusIcon />Add registry</Button>}>
        <Table>
          <TableHeader><TableRow><TableHead className="pl-4">Name</TableHead><TableHead>URL</TableHead><TableHead className="hidden md:table-cell">Auth</TableHead><TableHead className="pr-4" /></TableRow></TableHeader>
          <TableBody>
            {list.length === 0 && <TableRow className="hover:bg-transparent"><TableCell colSpan={4}><Empty>No registries yet. Add Docker Hub, GHCR or another Kontainer to get started.</Empty></TableCell></TableRow>}
            {list.map((r) => (
              <TableRow key={r.id}>
                <TableCell className="pl-4 font-medium">{r.name}</TableCell>
                <TableCell><Mono className="text-muted-foreground">{r.url}</Mono> {r.is_insecure && <Badge variant="outline">insecure</Badge>}</TableCell>
                <TableCell className="hidden text-muted-foreground md:table-cell">{r.username ?? "anonymous"}</TableCell>
                <TableCell className="whitespace-nowrap pr-4 text-right">
                  <TestResult id={r.id} />
                  <Button size="sm" variant="ghost" onClick={() => setEditing(r)}>Edit</Button>
                  <Button size="sm" variant="ghost" onClick={() => { if (confirm(`Remove ${r.name}?`)) delReg.mutate(r.id) }}>Remove</Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
      {delReg.error && <ErrorBox error={delReg.error} />}

      <Panel title="Pull-through caches" description="A namespace that fetches from an upstream on first pull." actions={<Button size="sm" variant="outline" disabled={!list.length} onClick={() => setProxyOpen(true)}><PlusIcon />New cache</Button>}>
        <Table>
          <TableHeader><TableRow><TableHead className="pl-4">Namespace</TableHead><TableHead>Upstream</TableHead><TableHead className="hidden md:table-cell">Recheck tags</TableHead><TableHead className="hidden md:table-cell">Access</TableHead><TableHead className="pr-4" /></TableRow></TableHeader>
          <TableBody>
            {proxies.data?.length === 0 && <TableRow className="hover:bg-transparent"><TableCell colSpan={5}><Empty>No caches. Create one to pull through, say, <Mono>{location.host}/hub/library/alpine</Mono>.</Empty></TableCell></TableRow>}
            {proxies.data?.map((p: ProxyCache) => (
              <TableRow key={p.namespace}>
                <TableCell className="pl-4"><span className="font-medium">{p.namespace}/</span></TableCell>
                <TableCell>{name(p.registry_id)}</TableCell>
                <TableCell className="hidden text-muted-foreground md:table-cell">{formatSeconds(p.ttl_secs)}</TableCell>
                <TableCell className="hidden md:table-cell">{p.is_public ? <Badge variant="outline">public</Badge> : <span className="text-muted-foreground">signed in</span>}</TableCell>
                <TableCell className="pr-4 text-right"><Button size="sm" variant="ghost" onClick={() => { if (confirm(`Remove the ${p.namespace} cache? Already cached images stay until you delete them.`)) delProxy.mutate(p.namespace) }}>Remove</Button></TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
      {delProxy.error && <ErrorBox error={delProxy.error} />}

      {editing && <RegistryDialog registry={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
      {proxyOpen && <ProxyDialog registries={list} onClose={() => setProxyOpen(false)} />}
    </>
  )
}

// Mirrors
function MirrorDialog({ mirror, registries, onClose }: { mirror: Mirror | null; registries: UpstreamRegistry[]; onClose: () => void }) {
  const qc = useQueryClient()
  const [v, setV] = useState<MirrorInput>({
    registry_id: mirror?.registry_id ?? registries[0]?.id ?? 0, source: mirror?.source ?? "", target: mirror?.target ?? "",
    tags: mirror?.tags ?? [], interval_secs: mirror?.interval_secs ?? 3600, is_enabled: mirror?.is_enabled ?? true,
  })
  const [tags, setTags] = useState(v.tags.join(", "))
  const save = useMutation({
    meta: { success: "Mirror saved" },
    mutationFn: () => {
      const body = { ...v, tags: tags.split(/[\s,]+/).filter(Boolean) }
      return mirror ? endpoints.updateMirror(mirror.id, body) : endpoints.createMirror(body)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["mirrors"] }); onClose() },
  })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-lg">
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
          <DialogHeader>
            <DialogTitle>{mirror ? "Edit mirror" : "New mirror"}</DialogTitle>
            <DialogDescription>Copies tags from another registry on a schedule. Only tags whose digest changed are copied.</DialogDescription>
          </DialogHeader>
          <Field id="mr-reg" label="From registry"><RegistrySelect id="mr-reg" registries={registries} value={v.registry_id} onChange={(id) => setV({ ...v, registry_id: id })} /></Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field id="mr-src" label="Source repository"><Input id="mr-src" autoFocus value={v.source} onChange={(e) => setV({ ...v, source: e.target.value })} placeholder="library/alpine" /></Field>
            <Field id="mr-dst" label="Target repository"><Input id="mr-dst" value={v.target} onChange={(e) => setV({ ...v, target: e.target.value.toLowerCase() })} placeholder="mirror/alpine" /></Field>
          </div>
          <Field id="mr-tags" label="Tags" hint="Comma separated; * and ? wildcards work. Empty mirrors every tag (up to 200).">
            <Input id="mr-tags" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="latest, 3.*" />
          </Field>
          <Field id="mr-int" label="Sync every"><DurationSelect id="mr-int" value={v.interval_secs} onChange={(s) => setV({ ...v, interval_secs: s })} /></Field>
          <label className="flex items-center gap-2 text-sm"><Checkbox checked={v.is_enabled} onCheckedChange={(c) => setV({ ...v, is_enabled: !!c })} />Sync on schedule</label>
          {save.error && <ErrorBox error={save.error} />}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={!v.registry_id || !v.source || !v.target || save.isPending}>{mirror ? "Save" : "Create mirror"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function SyncStatus({ m }: { m: Mirror }) {
  if (!m.last_sync_at) return <span className="text-muted-foreground">never synced</span>
  return (
    <span className="flex min-w-0 items-center gap-1.5" title={m.last_message ?? undefined}>
      {m.last_status === "error" ? <CircleAlertIcon className="size-3.5 shrink-0 text-destructive" /> : <CheckCircle2Icon className="size-3.5 shrink-0 text-emerald-500" />}
      <span className="truncate">{relativeTime(m.last_sync_at)}<span className="text-muted-foreground"> · {m.last_message}</span></span>
    </span>
  )
}

export function JobStatus({ job }: { job: Job }) {
  if (job.status === "running") return <Badge variant="secondary" className="gap-1"><Loader2Icon className="size-3 animate-spin" />running</Badge>
  if (job.status === "failed") return <Badge variant="destructive">failed</Badge>
  if (job.status === "cancelled") return <Badge variant="outline">cancelled</Badge>
  return <Badge variant="outline">done</Badge>
}

export function JobsPanel({ kinds }: { kinds?: string[] }) {
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: endpoints.jobs, refetchInterval: (q) => (q.state.data?.some((j) => j.status === "running") ? 1500 : 10_000) })
  const list = (jobs.data ?? []).filter((j) => !kinds || kinds.includes(j.kind))
  return (
    <Panel title="Recent jobs" description="Imports and syncs started since the server last restarted.">
      {jobs.error ? <div className="p-4"><ErrorBox error={jobs.error} /></div> : (
        <ul className="divide-y">
          {list.length === 0 && <li><Empty>Nothing has run yet.</Empty></li>}
          {list.slice(0, 20).map((j) => (
            <li key={j.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm">
              <JobStatus job={j} />
              <span className="min-w-0 flex-1 truncate font-medium">{j.title}</span>
              <span className="text-xs text-muted-foreground">{j.actor} · {relativeTime(j.finished_at ?? j.started_at)}</span>
              {j.message && <p className={cn("w-full truncate text-xs", j.status === "failed" ? "text-destructive" : "text-muted-foreground")} title={j.message}>{j.message}</p>}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

export function MirrorsPage() {
  const qc = useQueryClient()
  const regs = useQuery({ queryKey: ["registries"], queryFn: endpoints.registries })
  const mirrors = useQuery({ queryKey: ["mirrors"], queryFn: endpoints.mirrors, refetchInterval: 10_000 })
  const [editing, setEditing] = useState<Mirror | "new" | null>(null)
  const sync = useMutation({ meta: { success: "Mirror sync started" }, mutationFn: endpoints.syncMirror, onSuccess: () => { qc.invalidateQueries({ queryKey: ["jobs"] }); setTimeout(() => qc.invalidateQueries({ queryKey: ["mirrors"] }), 2000) } })
  const toggle = useMutation({ meta: { success: "Mirror updated" }, mutationFn: (m: Mirror) => endpoints.updateMirror(m.id, { ...m, is_enabled: !m.is_enabled }), onSuccess: () => qc.invalidateQueries({ queryKey: ["mirrors"] }) })
  const del = useMutation({ meta: { success: "Mirror deleted" }, mutationFn: endpoints.deleteMirror, onSuccess: () => qc.invalidateQueries({ queryKey: ["mirrors"] }) })
  if (mirrors.isLoading || regs.isLoading) return <Loading />
  if (mirrors.error) return <ErrorBox error={mirrors.error} />
  const registries = regs.data ?? []
  const name = (id: number) => registries.find((r) => r.id === id)?.name ?? `#${id}`
  return (
    <>
      <Panel title="Mirrors" description="Repositories kept in sync with another registry." actions={
        <Button size="sm" disabled={!registries.length} onClick={() => setEditing("new")} title={registries.length ? undefined : "Add a registry first"}><PlusIcon />New mirror</Button>
      }>
        <Table>
          <TableHeader><TableRow><TableHead className="pl-4">Source</TableHead><TableHead>Target</TableHead><TableHead className="hidden lg:table-cell">Schedule</TableHead><TableHead className="hidden md:table-cell">Last sync</TableHead><TableHead className="pr-4" /></TableRow></TableHeader>
          <TableBody>
            {mirrors.data?.length === 0 && (
              <TableRow className="hover:bg-transparent"><TableCell colSpan={5}><Empty>{registries.length ? "No mirrors yet." : <>Add a <Link to="/admin/registries" className="text-foreground hover:underline">registry</Link> to mirror from first.</>}</Empty></TableCell></TableRow>
            )}
            {mirrors.data?.map((m) => (
              <TableRow key={m.id}>
                <TableCell className="pl-4">
                  <div className="font-medium">{m.source}</div>
                  <div className="text-xs text-muted-foreground">{name(m.registry_id)} · {m.tags.length ? m.tags.join(", ") : "all tags"}</div>
                </TableCell>
                <TableCell><Link to={`/r/${m.target}`} className="hover:underline">{m.target}</Link></TableCell>
                <TableCell className="hidden lg:table-cell">{m.is_enabled ? <span>every {formatSeconds(m.interval_secs)}</span> : <Badge variant="outline">paused</Badge>}</TableCell>
                <TableCell className="hidden max-w-72 text-xs md:table-cell"><SyncStatus m={m} /></TableCell>
                <TableCell className="whitespace-nowrap pr-4 text-right">
                  <Button size="sm" variant="ghost" disabled={sync.isPending && sync.variables === m.id} onClick={() => sync.mutate(m.id)}><RefreshCwIcon className={sync.isPending && sync.variables === m.id ? "animate-spin" : ""} />Sync</Button>
                  <Button size="sm" variant="ghost" onClick={() => toggle.mutate(m)}>{m.is_enabled ? "Pause" : "Resume"}</Button>
                  <Button size="sm" variant="ghost" onClick={() => setEditing(m)}>Edit</Button>
                  <Button size="sm" variant="ghost" onClick={() => { if (confirm(`Delete the mirror of ${m.source}? Already copied images stay.`)) del.mutate(m.id) }}>Delete</Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
      {(sync.error || toggle.error || del.error) && <ErrorBox error={sync.error ?? toggle.error ?? del.error} />}
      <JobsPanel />
      {editing && <MirrorDialog mirror={editing === "new" ? null : editing} registries={registries} onClose={() => setEditing(null)} />}
    </>
  )
}

// Health
const GROUPS: Record<string, string> = { core: "Core", replicas: "Storage replicas", upstreams: "Upstream registries", mirrors: "Mirrors", jobs: "Jobs" }

function StatusIcon({ status, className }: { status: HealthCheck["status"]; className?: string }) {
  if (status === "ok") return <CheckCircle2Icon className={cn("text-emerald-500", className)} />
  if (status === "warn") return <TriangleAlertIcon className={cn("text-amber-500", className)} />
  return <CircleAlertIcon className={cn("text-destructive", className)} />
}

export function HealthPage() {
  const q = useQuery({ queryKey: ["health"], queryFn: endpoints.health, refetchInterval: 30_000 })
  if (q.isLoading) return <Loading />
  if (q.error) return <ErrorBox error={q.error} />
  const r = q.data!
  const groups = Object.keys(GROUPS).filter((g) => r.checks.some((c) => c.group === g))
  const headline = { ok: "All systems operational", warn: "Operational, with warnings", error: "Something is failing" }[r.status]
  return (
    <>
      <div className={cn("flex flex-wrap items-center gap-4 rounded-lg border bg-card p-5",
        r.status === "error" && "border-destructive/40", r.status === "warn" && "border-amber-500/40")}>
        <StatusIcon status={r.status} className="size-6" />
        <div className="min-w-0 flex-1">
          <div className="font-semibold">{headline}</div>
          <div className="text-sm text-muted-foreground">Kontainer {r.version} · up {formatSeconds(r.uptime_seconds)} · checked {relativeTime(r.checked_at)}</div>
        </div>
        <Button variant="outline" size="sm" onClick={() => q.refetch()} disabled={q.isFetching}><RefreshCwIcon className={q.isFetching ? "animate-spin" : ""} />Check again</Button>
      </div>
      {groups.map((g) => (
        <Panel key={g} title={GROUPS[g]}>
          <ul className="divide-y">
            {r.checks.filter((c) => c.group === g).map((c) => (
              <li key={c.name} className="flex items-start gap-3 px-4 py-3 text-sm">
                <StatusIcon status={c.status} className="mt-0.5 size-4 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="font-medium">{c.name}</div>
                  <div className="whitespace-pre-line break-words text-muted-foreground">{c.message}</div>
                </div>
                {c.latency_ms !== undefined && <span className="shrink-0 tabular-nums text-xs text-muted-foreground">{c.latency_ms} ms</span>}
              </li>
            ))}
          </ul>
        </Panel>
      ))}
      <p className="text-sm text-muted-foreground">
        Orchestrators can probe <Mono>/livez</Mono> (process up) and <Mono>/readyz</Mono> (database and storage answer) without signing in. Prometheus metrics are at <Mono>/metrics</Mono> once <Mono>metrics.token</Mono> is set.
      </p>
    </>
  )
}
