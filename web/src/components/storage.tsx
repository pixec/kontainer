import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { Link } from "react-router"
import { PencilIcon, PlayIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { endpoints, formatBytes, type QuotaSource, type RetentionInput, type RetentionOutcome, type RetentionPolicy } from "@/lib/api"
import { relativeTime } from "@/lib/time"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { Empty, FormSection } from "@/components/page"
import { cn } from "@/lib/utils"

const GiB = 1024 ** 3

/** Used vs quota, as a bar. Turns amber past 80% and red past 95%. */
export function UsageBar({ used, quota, source, className }: { used: number; quota: number | null; source?: QuotaSource; className?: string }) {
  if (!quota) return <div className={cn("text-sm text-muted-foreground", className)}>{formatBytes(used)} · {source === "namespace" ? "no limit" : "no quota"}</div>
  const pct = Math.min(100, (used / quota) * 100)
  return (
    <div className={cn("space-y-1.5", className)}>
      <div className="flex justify-between text-sm"><span className="tabular-nums">{formatBytes(used)}</span><span className="tabular-nums text-muted-foreground">of {formatBytes(quota)}{source === "default" && " (default)"} · {pct.toFixed(0)}%</span></div>
      <div className="h-2 overflow-hidden rounded-full bg-foreground/10">
        <div className={cn("h-full rounded-full", pct > 95 ? "bg-destructive" : pct > 80 ? "bg-warning" : "bg-foreground")} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

type QuotaChoice = "default" | "limit" | "none"

/** Set a namespace's quota: the configured default, a limit of its own, or no limit at all. */
export function QuotaDialog({ namespace, quota, source, defaultQuota, open, onOpenChange }: {
  namespace: string; quota: number | null; source?: QuotaSource; defaultQuota?: number | null; open: boolean; onOpenChange: (v: boolean) => void
}) {
  const qc = useQueryClient()
  const [choice, setChoice] = useState<QuotaChoice>(source === "default" ? "default" : source === "namespace" && quota === null ? "none" : quota || !defaultQuota ? "limit" : "default")
  const [gb, setGb] = useState(quota && source !== "default" ? String(+(quota / GiB).toFixed(2)) : "")
  const save = useMutation({
    meta: { success: "Quota saved" },
    mutationFn: (v: number | null) => endpoints.setQuota(namespace, v),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["storage"] }); qc.invalidateQueries({ queryKey: ["ns-storage", namespace] }); onOpenChange(false) },
  })
  const value = Number(gb)
  // `null` falls back to the default (or no quota when there is none); `0` means no limit.
  const submit = () => save.mutate(choice === "limit" ? Math.round(value * GiB) : choice === "none" ? (defaultQuota ? 0 : null) : null)
  const options: [QuotaChoice, string, string][] = [
    ...(defaultQuota ? [["default", "Default", `${formatBytes(defaultQuota)}, from the registry configuration`] as [QuotaChoice, string, string]] : []),
    ["limit", "Custom limit", "A limit for this namespace only"],
    ["none", "No limit", defaultQuota ? "Exempt from the default" : "Pushes are never refused for size"],
  ]
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <form className="grid gap-5" onSubmit={(e) => { e.preventDefault(); if (choice !== "limit" || value > 0) submit() }}>
          <DialogHeader>
            <DialogTitle>Quota for {namespace}</DialogTitle>
            <DialogDescription>Pushes that would take the namespace past its quota are refused. Layers shared between its repositories count once.</DialogDescription>
          </DialogHeader>
          <div role="radiogroup" aria-label="Quota" className="grid gap-2">
            {options.map(([key, label, hint]) => (
              <label key={key} className={cn("flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors", choice === key ? "border-foreground/40 bg-accent/40" : "hover:bg-accent/20")}>
                <input type="radio" name="quota-choice" className="mt-1" checked={choice === key} onChange={() => setChoice(key)} />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium">{label}</span>
                  <span className="block text-xs text-muted-foreground">{hint}</span>
                  {key === "limit" && choice === "limit" && (
                    <span className="mt-2 flex items-center gap-2">
                      <Input id="quota-gb" type="number" min="0.01" step="0.01" autoFocus value={gb} onChange={(e) => setGb(e.target.value)} placeholder="50" className="w-32" />
                      <span className="text-sm text-muted-foreground">GB</span>
                    </span>
                  )}
                </span>
              </label>
            ))}
          </div>
          {save.error && <ErrorBox error={save.error} />}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={(choice === "limit" && !(value > 0)) || save.isPending}>Save</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Storage and retention for one namespace: used in org settings and personal settings. */
export function NamespaceStorageSections({ namespace, canManage, canSetQuota }: { namespace: string; canManage: boolean; canSetQuota: boolean }) {
  const qc = useQueryClient()
  const [refresh, setRefresh] = useState(false)
  const q = useQuery({ queryKey: ["ns-storage", namespace, refresh], queryFn: () => endpoints.namespaceStorage(namespace, refresh) })
  const [quotaOpen, setQuotaOpen] = useState(false)
  return (
    <>
      <FormSection title="Storage" description={<>What {namespace}/ takes. Layers shared between its repositories count once.</>}>
        {q.isLoading && <Loading rows={2} />}
        {q.error && <ErrorBox error={q.error} />}
        {q.data && (
          <div className="space-y-4">
            <UsageBar used={q.data.bytes} quota={q.data.quota} source={q.data.quota_source} />
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <span>Updated {relativeTime(q.data.computed_at)}</span>
              <button type="button" className="inline-flex items-center gap-1 hover:text-foreground" onClick={() => { setRefresh(true); qc.invalidateQueries({ queryKey: ["ns-storage", namespace] }) }}><RefreshCwIcon className="size-3" />Recompute</button>
              {canSetQuota && <Button size="sm" variant="outline" className="ml-auto" onClick={() => setQuotaOpen(true)}>{q.data.quota_source === "none" ? "Set quota" : "Change quota"}</Button>}
            </div>
            {q.data.repositories.length > 0 && (
              <Table>
                <TableHeader><TableRow><TableHead className="pl-0">Repository</TableHead><TableHead className="text-right">Tags</TableHead><TableHead className="text-right">Size</TableHead><TableHead className="pr-0 text-right">Unique</TableHead></TableRow></TableHeader>
                <TableBody>
                  {[...q.data.repositories].sort((a, b) => b.bytes - a.bytes).slice(0, 10).map((r) => (
                    <TableRow key={r.name}>
                      <TableCell className="pl-0"><Link to={`/r/${r.name}`} className="hover:underline">{r.name.slice(namespace.length + 1)}</Link></TableCell>
                      <TableCell className="text-right tabular-nums text-muted-foreground">{r.tags}</TableCell>
                      <TableCell className="text-right tabular-nums">{formatBytes(r.bytes)}</TableCell>
                      <TableCell className="pr-0 text-right tabular-nums text-muted-foreground">{formatBytes(r.unique_bytes)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            {canSetQuota && <QuotaDialog key={`${q.data.quota_source}:${q.data.quota}`} namespace={namespace} quota={q.data.quota} source={q.data.quota_source} defaultQuota={q.data.default_quota} open={quotaOpen} onOpenChange={setQuotaOpen} />}
          </div>
        )}
      </FormSection>
      <RetentionSection namespace={namespace} canManage={canManage} />
    </>
  )
}

function describe(p: Pick<RetentionPolicy, "keep_last" | "max_age_days">) {
  if (p.keep_last && p.max_age_days) return `Delete tags outside the newest ${p.keep_last} that are older than ${p.max_age_days} days`
  if (p.keep_last) return `Keep the newest ${p.keep_last} tags`
  return `Delete tags older than ${p.max_age_days} days`
}

function RetentionSection({ namespace, canManage }: { namespace: string; canManage: boolean }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["retention", namespace], queryFn: () => endpoints.retention(namespace) })
  const [editing, setEditing] = useState<RetentionPolicy | "new" | null>(null)
  const [preview, setPreview] = useState<{ policy: RetentionPolicy; outcome?: RetentionOutcome } | null>(null)
  const invalidate = () => qc.invalidateQueries({ queryKey: ["retention", namespace] })
  const toggle = useMutation({ meta: { success: "Retention policy updated" }, mutationFn: (p: RetentionPolicy) => endpoints.updateRetention(namespace, p.id, { ...p, is_enabled: !p.is_enabled }), onSuccess: invalidate })
  const remove = useMutation({ meta: { success: "Retention policy deleted" }, mutationFn: (id: number) => endpoints.deleteRetention(namespace, id), onSuccess: invalidate })
  return (
    <FormSection title="Tag retention" description="Delete old tags automatically. Runs hourly; deleted tags free space at the next garbage collection.">
      <div className="space-y-3">
        {q.isLoading && <Loading rows={2} />}
        {q.error && <ErrorBox error={q.error} />}
        {q.data?.length === 0 && <div className="rounded-lg border border-dashed"><Empty>No retention policies. Tags are kept forever.</Empty></div>}
        {q.data?.map((p) => (
          <div key={p.id} className="flex flex-wrap items-center gap-3 rounded-lg border bg-card p-4">
            <div className="min-w-0 flex-1 space-y-1">
              <div className="text-sm font-medium">{describe(p)}</div>
              <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                <span>in <Mono className="text-foreground">{namespace}/{p.repositories}</Mono></span>
                {p.protect.length > 0 && <span>protects {p.protect.map((t) => <Mono key={t} className="ml-1 text-foreground">{t}</Mono>)}</span>}
                <span>{p.last_run_at ? `last run ${relativeTime(p.last_run_at)}, deleted ${p.last_deleted ?? 0}` : "not run yet"}</span>
              </div>
            </div>
            {canManage && (
              <div className="flex items-center gap-1">
                <Switch checked={p.is_enabled} onCheckedChange={() => toggle.mutate(p)} aria-label="Enabled" />
                <Button size="sm" variant="ghost" onClick={() => setPreview({ policy: p })}><PlayIcon />Preview</Button>
                <Button size="icon" variant="ghost" className="size-8 text-muted-foreground" title="Edit" onClick={() => setEditing(p)}><PencilIcon /></Button>
                <Button size="icon" variant="ghost" className="size-8 text-muted-foreground hover:text-destructive" title="Delete" onClick={() => { if (confirm("Delete this retention policy?")) remove.mutate(p.id) }}><Trash2Icon /></Button>
              </div>
            )}
          </div>
        ))}
        {canManage && <Button variant="outline" onClick={() => setEditing("new")}><PlusIcon />New policy</Button>}
        {(toggle.error || remove.error) && <ErrorBox error={toggle.error ?? remove.error} />}
      </div>
      {editing && <PolicyDialog namespace={namespace} policy={editing === "new" ? null : editing} onClose={() => setEditing(null)} onSaved={invalidate} />}
      {preview && <PreviewDialog namespace={namespace} policy={preview.policy} onClose={() => { setPreview(null); invalidate() }} />}
    </FormSection>
  )
}

function PolicyDialog({ namespace, policy, onClose, onSaved }: { namespace: string; policy: RetentionPolicy | null; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState({
    repositories: policy?.repositories ?? "**",
    keep_last: policy?.keep_last ? String(policy.keep_last) : "10",
    max_age_days: policy?.max_age_days ? String(policy.max_age_days) : "",
    protect: (policy?.protect ?? ["latest"]).join(", "),
  })
  const input = (): RetentionInput => ({
    repositories: form.repositories.trim() || "**",
    keep_last: form.keep_last ? Number(form.keep_last) : null,
    max_age_days: form.max_age_days ? Number(form.max_age_days) : null,
    protect: form.protect.split(",").map((s) => s.trim()).filter(Boolean),
    is_enabled: policy?.is_enabled ?? true,
  })
  const save = useMutation({
    meta: { success: "Retention policy saved" },
    mutationFn: () => (policy ? endpoints.updateRetention(namespace, policy.id, input()) : endpoints.createRetention(namespace, input())),
    onSuccess: () => { onSaved(); onClose() },
  })
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value })
  const i = input()
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="sm:max-w-lg">
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
          <DialogHeader>
            <DialogTitle>{policy ? "Edit retention policy" : "New retention policy"}</DialogTitle>
            <DialogDescription>{i.keep_last || i.max_age_days ? describe(i) + "." : "Set a number of tags to keep, a maximum age, or both."}</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="ret-repos">Repositories</Label>
            <div className="relative">
              <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 font-mono text-sm text-muted-foreground">{namespace}/</span>
              <Input id="ret-repos" className="font-mono" style={{ paddingLeft: `calc(${namespace.length + 1}ch + 0.75rem + 1px)` }} value={form.repositories} onChange={set("repositories")} />
            </div>
            <p className="text-xs text-muted-foreground"><Mono className="text-foreground">**</Mono> for every repository, <Mono className="text-foreground">api/*</Mono> for one level under api/.</p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2"><Label htmlFor="ret-keep">Keep newest</Label><Input id="ret-keep" type="number" min="1" placeholder="no limit" value={form.keep_last} onChange={set("keep_last")} /></div>
            <div className="space-y-2"><Label htmlFor="ret-age">Delete older than (days)</Label><Input id="ret-age" type="number" min="1" placeholder="no limit" value={form.max_age_days} onChange={set("max_age_days")} /></div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="ret-protect">Never delete</Label>
            <Input id="ret-protect" className="font-mono" value={form.protect} onChange={set("protect")} placeholder="latest, v*, release-*" />
            <p className="text-xs text-muted-foreground">Comma-separated tag patterns. Immutable tags are always kept.</p>
          </div>
          {save.error && <ErrorBox error={save.error} />}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={(!i.keep_last && !i.max_age_days) || save.isPending}>{policy ? "Save" : "Create policy"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function PreviewDialog({ namespace, policy, onClose }: { namespace: string; policy: RetentionPolicy; onClose: () => void }) {
  const preview = useQuery({ queryKey: ["retention-preview", policy.id], queryFn: () => endpoints.previewRetention(namespace, policy.id), gcTime: 0 })
  const run = useMutation({ meta: { success: "Retention policy is running" }, mutationFn: () => endpoints.runRetention(namespace, policy.id) })
  const outcome = run.data ?? preview.data
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{run.data ? "Retention ran" : "Preview"}</DialogTitle>
          <DialogDescription>{describe(policy)} in {namespace}/{policy.repositories}.</DialogDescription>
        </DialogHeader>
        {preview.isLoading && <Loading rows={3} />}
        {(preview.error || run.error) && <ErrorBox error={preview.error ?? run.error} />}
        {outcome && (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              {run.data ? "Deleted" : "Would delete"} <b className="text-foreground">{outcome.deletions.length}</b> {outcome.deletions.length === 1 ? "tag" : "tags"} across {outcome.repositories} {outcome.repositories === 1 ? "repository" : "repositories"}
              {outcome.kept_protected > 0 && <>, keeping {outcome.kept_protected} protected</>}.
            </p>
            {outcome.deletions.length > 0 && (
              <div className="max-h-[45vh] overflow-auto rounded-lg border">
                <Table>
                  <TableHeader className="sticky top-0 bg-popover"><TableRow><TableHead className="pl-4">Tag</TableHead><TableHead>Pushed</TableHead><TableHead>Why</TableHead></TableRow></TableHeader>
                  <TableBody>
                    {outcome.deletions.map((d) => (
                      <TableRow key={`${d.repository}:${d.tag}`}>
                        <TableCell className="pl-4"><span className="text-muted-foreground">{d.repository.slice(namespace.length + 1)}:</span><span className="font-medium">{d.tag.length > 24 ? d.tag.slice(0, 22) + "..." : d.tag}</span></TableCell>
                        <TableCell className="text-muted-foreground">{d.pushed_at ? relativeTime(d.pushed_at) : "—"}</TableCell>
                        <TableCell className="text-muted-foreground">{d.reason}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </div>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>Close</Button>
          {!run.data && (
            <Button variant="destructive" disabled={!preview.data || preview.data.deletions.length === 0 || run.isPending}
              onClick={() => { if (confirm(`Delete ${preview.data!.deletions.length} tags now?`)) run.mutate() }}>
              {run.isPending ? "Deleting..." : "Run now"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
