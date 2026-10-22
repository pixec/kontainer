import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { Link } from "react-router"
import { CheckCircle2Icon, CircleAlertIcon, Loader2Icon, PlayIcon, PlusIcon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Empty, LabeledSelect, Panel } from "@/components/page"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { endpoints, type ReplicationInput, type ReplicationRule, type ReplicationTrigger, type UpstreamRegistry } from "@/lib/api"
import { formatDate, formatSeconds, relativeTime } from "@/lib/time"
import { cn } from "@/lib/utils"

const TRIGGERS: Record<ReplicationTrigger, string> = { push: "On every push", schedule: "On a schedule", manual: "Only by hand" }
const INTERVALS: [string, string][] = [["900", "Every 15 minutes"], ["3600", "Every hour"], ["21600", "Every 6 hours"], ["86400", "Every day"]]

/** Admin → Replication: push local repositories to other registries. */
export function ReplicationPage() {
  const qc = useQueryClient()
  const regs = useQuery({ queryKey: ["registries"], queryFn: endpoints.registries })
  const rules = useQuery({ queryKey: ["replication-rules"], queryFn: endpoints.replicationRules, refetchInterval: 10_000 })
  const [editing, setEditing] = useState<ReplicationRule | "new" | null>(null)
  const [history, setHistory] = useState<ReplicationRule | null>(null)
  const invalidate = () => qc.invalidateQueries({ queryKey: ["replication-rules"] })
  const run = useMutation({ meta: { success: "Replication started" }, mutationFn: endpoints.runReplicationRule, onSuccess: () => setTimeout(invalidate, 1500) })
  const del = useMutation({ meta: { success: "Replication rule deleted" }, mutationFn: endpoints.deleteReplicationRule, onSuccess: invalidate })
  if (rules.isLoading || regs.isLoading) return <Loading />
  if (rules.error) return <ErrorBox error={rules.error} />
  const registries = regs.data ?? []
  const regName = (id: number) => registries.find((r) => r.id === id)?.name ?? `#${id}`
  return (
    <>
      <Panel title="Replication" description="Copy repositories from this registry to others: a disaster-recovery copy, an edge site, a cloud registry." actions={
        <Button size="sm" disabled={!registries.length} onClick={() => setEditing("new")} title={registries.length ? undefined : "Add a registry first"}><PlusIcon />New rule</Button>
      }>
        {rules.data?.length === 0 && <Empty>{registries.length ? "No replication rules yet." : <>Add the <Link to="/admin/registries" className="text-foreground hover:underline">registry</Link> to replicate to first.</>}</Empty>}
        <ul className="divide-y">
          {rules.data?.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{r.name}</span>
                  <span className="text-sm text-muted-foreground">→ {regName(r.registry_id)}{r.destination && <Mono className="ml-1">/{r.destination}</Mono>}</span>
                  {!r.is_enabled && <Badge variant="outline">paused</Badge>}
                </div>
                <div className="mt-0.5 text-xs text-muted-foreground">
                  {r.repositories.join(", ")} · {r.tags.length ? r.tags.join(", ") : "all tags"} · {r.trigger === "schedule" ? `every ${formatSeconds(r.interval_secs ?? 0)}` : TRIGGERS[r.trigger].toLowerCase()}{r.is_replicate_deletes && " · deletes too"}
                </div>
              </div>
              <button type="button" onClick={() => setHistory(r)} className="flex max-w-80 items-center gap-1.5 rounded-md px-2 py-1 text-left text-xs text-muted-foreground hover:bg-accent hover:text-foreground" title={r.last_message ?? "History"}>
                {r.last_status === "succeeded" ? <CheckCircle2Icon className="size-3.5 shrink-0 text-emerald-500" /> : r.last_status === "failed" ? <CircleAlertIcon className="size-3.5 shrink-0 text-destructive" /> : null}
                <span className="truncate">{r.last_run_at ? <>{relativeTime(r.last_run_at)} · {r.last_message}</> : "Never run"}</span>
              </button>
              <div className="flex items-center gap-1">
                <Button size="sm" variant="ghost" disabled={!r.is_enabled || (run.isPending && run.variables === r.id)} onClick={() => run.mutate(r.id)}><PlayIcon />Run</Button>
                <Button size="sm" variant="ghost" onClick={() => setEditing(r)}>Edit</Button>
                <Button size="sm" variant="ghost" onClick={() => { if (confirm(`Delete the rule ${r.name}? Already replicated images stay on the target.`)) del.mutate(r.id) }}>Delete</Button>
              </div>
            </li>
          ))}
        </ul>
      </Panel>
      {(run.error || del.error) && <ErrorBox error={run.error ?? del.error} />}
      {editing && <RuleDialog rule={editing === "new" ? null : editing} registries={registries} onClose={() => setEditing(null)} />}
      {history && <HistoryDialog rule={history} onClose={() => setHistory(null)} />}
    </>
  )
}

function RuleDialog({ rule, registries, onClose }: { rule: ReplicationRule | null; registries: UpstreamRegistry[]; onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    name: rule?.name ?? "", registry_id: String(rule?.registry_id ?? registries[0]?.id ?? ""),
    repositories: (rule?.repositories ?? ["**"]).join(" "), tags: (rule?.tags ?? []).join(" "), destination: rule?.destination ?? "",
    trigger: rule?.trigger ?? ("push" as ReplicationTrigger), interval: String(rule?.interval_secs ?? 3600),
    is_replicate_deletes: rule?.is_replicate_deletes ?? false, is_enabled: rule?.is_enabled ?? true,
  })
  const set = (patch: Partial<typeof form>) => setForm({ ...form, ...patch })
  const split = (s: string) => s.split(/[\s,]+/).filter(Boolean)
  const save = useMutation({
    meta: { success: rule ? "Replication rule saved" : "Replication rule added" },
    mutationFn: () => {
      const input: ReplicationInput = {
        name: form.name, registry_id: Number(form.registry_id), repositories: split(form.repositories), tags: split(form.tags), destination: form.destination,
        trigger: form.trigger, interval_secs: form.trigger === "schedule" ? Number(form.interval) : null, is_replicate_deletes: form.is_replicate_deletes, is_enabled: form.is_enabled,
      }
      return rule ? endpoints.updateReplicationRule(rule.id, input) : endpoints.createReplicationRule(input)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["replication-rules"] }); onClose() },
  })
  const target = registries.find((r) => String(r.id) === form.registry_id)
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-xl">
        <form className="grid gap-5" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
          <DialogHeader>
            <DialogTitle>{rule ? `Edit ${rule.name}` : "New replication rule"}</DialogTitle>
            <DialogDescription>Images that match are pushed to the target registry with its stored credentials. Signatures and attestations go along.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5"><Label htmlFor="rr-name">Name</Label><Input id="rr-name" autoFocus required maxLength={64} value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="DR copy" /></div>
            <div className="space-y-1.5"><Label>Target</Label><LabeledSelect label="Registry" value={form.registry_id} onChange={(registry_id) => set({ registry_id })} options={registries.map((r) => [String(r.id), r.name] as [string, string])} className="w-full" /></div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rr-repos">Repositories</Label>
            <Input id="rr-repos" className="font-mono text-xs" value={form.repositories} onChange={(e) => set({ repositories: e.target.value })} placeholder="acme/** web/*" />
            <p className="text-xs text-muted-foreground">Separated by spaces. <Mono>*</Mono> stays within one path segment, <Mono>**</Mono> crosses them.</p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="rr-tags">Tags <span className="font-normal text-muted-foreground">(optional)</span></Label>
              <Input id="rr-tags" className="font-mono text-xs" value={form.tags} onChange={(e) => set({ tags: e.target.value })} placeholder="v* latest" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="rr-dest">Destination prefix <span className="font-normal text-muted-foreground">(optional)</span></Label>
              <Input id="rr-dest" className="font-mono text-xs" value={form.destination} onChange={(e) => set({ destination: e.target.value })} placeholder="dr" />
            </div>
          </div>
          <p className="-mt-2 text-xs text-muted-foreground">
            <Mono>acme/api</Mono> goes to <Mono>{target?.name ?? "target"}/{form.destination.trim().replace(/^\/+|\/+$/g, "") ? `${form.destination.trim().replace(/^\/+|\/+$/g, "")}/` : ""}acme/api</Mono>.
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5"><Label>When</Label><LabeledSelect label="Trigger" value={form.trigger} onChange={(trigger) => set({ trigger })} options={TRIGGERS} className="w-full" /></div>
            {form.trigger === "schedule" && <div className="space-y-1.5"><Label>How often</Label><LabeledSelect label="Interval" value={form.interval} onChange={(interval) => set({ interval })} options={INTERVALS} className="w-full" /></div>}
          </div>
          <div className="flex flex-wrap gap-x-6 gap-y-3">
            <label className="flex items-center gap-2 text-sm"><Switch checked={form.is_replicate_deletes} onCheckedChange={(is_replicate_deletes) => set({ is_replicate_deletes })} />Delete tags on the target when they're deleted here</label>
            <label className="flex items-center gap-2 text-sm"><Switch checked={form.is_enabled} onCheckedChange={(is_enabled) => set({ is_enabled })} />Active</label>
          </div>
          {save.error && <ErrorBox error={save.error} />}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={!form.name.trim() || !form.registry_id || save.isPending}>{rule ? "Save" : "Add rule"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function HistoryDialog({ rule, onClose }: { rule: ReplicationRule; onClose: () => void }) {
  const q = useQuery({ queryKey: ["replication-runs", rule.id], queryFn: () => endpoints.replicationRuns(rule.id), refetchInterval: (s) => (s.state.data?.some((r) => r.status === "running") ? 2000 : false) })
  const TRIGGER: Record<string, string> = { push: "push", delete: "delete", schedule: "scheduled", manual: "manual" }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader><DialogTitle>Runs of {rule.name}</DialogTitle><DialogDescription>The last 50: replications on push, deletions, scheduled and manual runs.</DialogDescription></DialogHeader>
        {q.isLoading && <Loading rows={3} />}
        {q.error && <ErrorBox error={q.error} />}
        {q.data?.length === 0 && <p className="rounded-lg border border-dashed p-4 text-center text-sm text-muted-foreground">Nothing replicated yet.</p>}
        <ul className="max-h-[60svh] divide-y overflow-y-auto rounded-lg border text-sm">
          {q.data?.map((r) => (
            <li key={r.id} className="flex items-start gap-3 px-3 py-2">
              {r.status === "running" ? <Loader2Icon className="mt-0.5 size-4 shrink-0 animate-spin text-muted-foreground" /> : r.status === "succeeded" ? <CheckCircle2Icon className="mt-0.5 size-4 shrink-0 text-emerald-500" /> : <CircleAlertIcon className="mt-0.5 size-4 shrink-0 text-destructive" />}
              <span className={cn("min-w-0 flex-1 break-words", r.status === "failed" && "text-destructive")}>{r.summary ?? "Running..."}</span>
              <span className="shrink-0 text-xs text-muted-foreground" title={formatDate(r.started_at)}>{TRIGGER[r.trigger] ?? r.trigger} · {relativeTime(r.started_at)}</span>
            </li>
          ))}
        </ul>
        <DialogFooter><Button variant="outline" onClick={onClose}>Close</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
