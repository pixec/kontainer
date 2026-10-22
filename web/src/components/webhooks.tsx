import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { CheckCircle2Icon, ChevronRightIcon, CircleAlertIcon, Clock3Icon, PencilIcon, PlusIcon, RotateCwIcon, SendIcon, Trash2Icon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Empty, FormSection, LabeledSelect } from "@/components/page"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { endpoints, type DeliveryStatus, type Webhook, type WebhookDelivery, type WebhookFormat, type WebhookInput } from "@/lib/api"
import { formatDate, relativeTime } from "@/lib/time"
import { cn } from "@/lib/utils"

const FORMATS: Record<WebhookFormat, string> = { default: "Kontainer JSON", cloudevents: "CloudEvents", slack: "Slack" }
const EVENT_LABELS: Record<string, string> = {
  push: "Push", pull: "Pull", delete: "Delete", scan: "Scan finished", quota_exceeded: "Quota exceeded", quota_warning: "Quota above 90%",
  retention: "Retention ran", mirror_sync: "Mirror synced", build: "Build finished", replication: "Replication",
}

function DeliveryDot({ status }: { status: DeliveryStatus }) {
  if (status === "succeeded") return <CheckCircle2Icon className="size-3.5 text-emerald-500" />
  if (status === "failed") return <CircleAlertIcon className="size-3.5 text-destructive" />
  return <Clock3Icon className="size-3.5 text-muted-foreground" />
}

/** A namespace's webhooks: where events go, in what format, and how deliveries went. */
export function WebhooksPanel({ namespace }: { namespace: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["webhooks", namespace], queryFn: () => endpoints.webhooks(namespace) })
  const [editing, setEditing] = useState<Webhook | "new" | null>(null)
  const [history, setHistory] = useState<Webhook | null>(null)
  const invalidate = () => qc.invalidateQueries({ queryKey: ["webhooks", namespace] })
  const remove = useMutation({ meta: { success: "Webhook deleted" }, mutationFn: (id: number) => endpoints.deleteWebhook(namespace, id), onSuccess: invalidate })
  const test = useMutation({
    mutationFn: (id: number) => endpoints.testWebhook(namespace, id),
    onSuccess: invalidate,
  })
  const hooks = q.data ?? []
  return (
    <FormSection title="Webhooks" description={<>Get a request at your endpoint when something happens in <Mono>{namespace}/</Mono>: pushes, scans, builds and more.</>}>
      <div className="space-y-3">
      {q.isLoading && <Loading rows={2} />}
      {q.error && <ErrorBox error={q.error} />}
      {q.data && hooks.length === 0 && <div className="rounded-lg border border-dashed"><Empty>No webhooks yet. Add one to notify Slack, a CI system or your own service.</Empty></div>}
      {hooks.length > 0 && <ul className="space-y-3">
        {hooks.map((h) => (
          <li key={h.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border bg-card p-4">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className={cn("font-medium", !h.is_enabled && "text-muted-foreground line-through")}>{h.name}</span>
                <span className="chip">{FORMATS[h.format]}</span>
                {!h.is_enabled && <span className="chip">Paused</span>}
              </div>
              <div className="mt-0.5 truncate font-mono text-xs text-muted-foreground" title={h.url}>{h.url}</div>
              <div className="mt-1 text-xs text-muted-foreground">
                {h.events.length === 0 ? "All events" : h.events.map((e) => EVENT_LABELS[e] ?? e).join(", ")}
                {h.repositories.length > 0 && <> · {h.repositories.map((r) => `${namespace}/${r}`).join(", ")}</>}
              </div>
            </div>
            <button type="button" onClick={() => setHistory(h)} className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground" title="Delivery history">
              {h.last_delivery
                ? <><DeliveryDot status={h.last_delivery.status} />{h.last_delivery.response_code ?? "—"} · {relativeTime(h.last_delivery.at)}</>
                : "No deliveries yet"}
            </button>
            <div className="flex items-center gap-1">
              <Button size="sm" variant="ghost" disabled={test.isPending} onClick={() => test.mutate(h.id, { onSuccess: () => setHistory(h) })} title="Send a test event"><SendIcon />Test</Button>
              <Button size="icon-sm" variant="ghost" aria-label="Edit" onClick={() => setEditing(h)}><PencilIcon /></Button>
              <Button size="icon-sm" variant="ghost" aria-label="Delete" disabled={remove.isPending} onClick={() => { if (confirm(`Delete the webhook ${h.name}?`)) remove.mutate(h.id) }}><Trash2Icon /></Button>
            </div>
          </li>
        ))}
      </ul>}
      {test.error && <ErrorBox error={test.error} />}
      <Button variant="outline" onClick={() => setEditing("new")}><PlusIcon />Add webhook</Button>
      </div>
      {editing && <WebhookDialog namespace={namespace} hook={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
      {history && <DeliveriesDialog namespace={namespace} hook={history} onClose={() => setHistory(null)} />}
    </FormSection>
  )
}

function WebhookDialog({ namespace, hook, onClose }: { namespace: string; hook: Webhook | null; onClose: () => void }) {
  const qc = useQueryClient()
  const meta = useQuery({ queryKey: ["webhook-events"], queryFn: endpoints.webhookEvents, staleTime: Infinity })
  const [form, setForm] = useState({
    name: hook?.name ?? "", url: hook?.url ?? "", format: hook?.format ?? ("default" as WebhookFormat),
    events: hook?.events ?? [], repositories: (hook?.repositories ?? []).join(" "),
    secret: "", auth_header: "", is_verify_tls: hook?.is_verify_tls ?? true, is_enabled: hook?.is_enabled ?? true,
  })
  const set = (patch: Partial<typeof form>) => setForm({ ...form, ...patch })
  const save = useMutation({
    meta: { success: hook ? "Webhook saved" : "Webhook added" },
    mutationFn: () => {
      const input: WebhookInput = {
        name: form.name, url: form.url, format: form.format, events: form.events,
        repositories: form.repositories.split(/[\s,]+/).filter(Boolean), is_verify_tls: form.is_verify_tls, is_enabled: form.is_enabled,
        // Empty keeps what is stored on an edit.
        secret: form.secret || (hook ? undefined : ""), auth_header: form.auth_header || (hook ? undefined : ""),
      }
      return hook ? endpoints.updateWebhook(namespace, hook.id, input) : endpoints.createWebhook(namespace, input)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["webhooks", namespace] }); onClose() },
  })
  const events = meta.data?.events ?? Object.keys(EVENT_LABELS)
  const all = form.events.length === 0
  const toggle = (e: string) => set({ events: all ? [e] : form.events.includes(e) ? form.events.filter((x) => x !== e) : [...form.events, e] })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-xl">
        <form className="grid gap-5" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
          <DialogHeader>
            <DialogTitle>{hook ? `Edit ${hook.name}` : "Add a webhook"}</DialogTitle>
            <DialogDescription>Kontainer sends a POST request to this URL for each event you pick.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 sm:grid-cols-[1fr_12rem]">
            <div className="space-y-1.5"><Label htmlFor="wh-name">Name</Label><Input id="wh-name" autoFocus required maxLength={64} value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="Slack #deploys" /></div>
            <div className="space-y-1.5"><Label>Format</Label><LabeledSelect label="Format" value={form.format} onChange={(format) => set({ format })} options={FORMATS} className="w-full" /></div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="wh-url">URL</Label>
            <Input id="wh-url" type="url" required className="font-mono text-xs" value={form.url} onChange={(e) => set({ url: e.target.value })} placeholder={form.format === "slack" ? "https://hooks.slack.com/services/..." : "https://ci.example.com/hooks/registry"} />
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>Events</Label>
              <button type="button" className="text-xs text-muted-foreground hover:text-foreground hover:underline" onClick={() => set({ events: [] })}>{all ? "Every event, including new ones" : "Send everything"}</button>
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
              {events.map((e) => (
                <label key={e} className="flex cursor-pointer items-center gap-2 text-sm">
                  <Checkbox checked={all || form.events.includes(e)} onCheckedChange={() => toggle(e)} />{EVENT_LABELS[e] ?? e}
                </label>
              ))}
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="wh-repos">Repositories <span className="font-normal text-muted-foreground">(optional)</span></Label>
            <Input id="wh-repos" className="font-mono text-xs" value={form.repositories} onChange={(e) => set({ repositories: e.target.value })} placeholder="api web/*" />
            <p className="text-xs text-muted-foreground">Inside <Mono>{namespace}/</Mono>, separated by spaces. Empty means every repository.</p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="wh-secret">Signing secret <span className="font-normal text-muted-foreground">(optional)</span></Label>
              <Input id="wh-secret" type="password" autoComplete="new-password" value={form.secret} onChange={(e) => set({ secret: e.target.value })} placeholder={hook?.has_secret ? "Stored; type to replace" : ""} />
              <p className="text-xs text-muted-foreground">Each request is signed: <Mono>X-Kontainer-Signature: sha256=...</Mono></p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="wh-auth">Authorization header <span className="font-normal text-muted-foreground">(optional)</span></Label>
              <Input id="wh-auth" type="password" autoComplete="off" value={form.auth_header} onChange={(e) => set({ auth_header: e.target.value })} placeholder={hook?.has_auth_header ? "Stored; type to replace" : "Bearer ..."} />
            </div>
          </div>
          <div className="flex flex-wrap gap-x-6 gap-y-3">
            <label className="flex items-center gap-2 text-sm"><Switch checked={form.is_enabled} onCheckedChange={(is_enabled) => set({ is_enabled })} />Active</label>
            <label className="flex items-center gap-2 text-sm"><Switch checked={form.is_verify_tls} onCheckedChange={(is_verify_tls) => set({ is_verify_tls })} />Verify TLS certificates</label>
          </div>
          {save.error && <ErrorBox error={save.error} />}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={!form.name.trim() || !form.url.trim() || save.isPending}>{hook ? "Save" : "Add webhook"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function DeliveriesDialog({ namespace, hook, onClose }: { namespace: string; hook: Webhook; onClose: () => void }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["webhook-deliveries", hook.id], queryFn: () => endpoints.webhookDeliveries(namespace, hook.id), refetchInterval: (s) => (s.state.data?.some((d) => d.status === "pending") ? 2000 : false) })
  const [open, setOpen] = useState<number | null>(null)
  const redeliver = useMutation({
    meta: { success: "Delivered again" },
    mutationFn: (d: WebhookDelivery) => endpoints.redeliverWebhook(namespace, hook.id, d.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["webhook-deliveries", hook.id] }); qc.invalidateQueries({ queryKey: ["webhooks", namespace] }) },
  })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Deliveries to {hook.name}</DialogTitle>
          <DialogDescription>The last 50. Failed deliveries are retried twice; you can send any of them again.</DialogDescription>
        </DialogHeader>
        {q.isLoading && <Loading rows={3} />}
        {q.error && <ErrorBox error={q.error} />}
        {q.data?.length === 0 && <p className="rounded-lg border border-dashed p-4 text-center text-sm text-muted-foreground">Nothing sent yet. Use Test to send one.</p>}
        <ul className="max-h-[60svh] divide-y overflow-y-auto rounded-lg border">
          {q.data?.map((d) => (
            <li key={d.id}>
              <button type="button" onClick={() => setOpen(open === d.id ? null : d.id)} className="flex w-full items-center gap-3 px-3 py-2 text-left text-sm hover:bg-accent/40">
                <ChevronRightIcon className={cn("size-3.5 shrink-0 text-muted-foreground transition-transform", open === d.id && "rotate-90")} />
                <DeliveryDot status={d.status} />
                <span className="font-medium">{EVENT_LABELS[d.event] ?? d.event}</span>
                <span className="flex-1 truncate text-xs text-muted-foreground">{d.response_code ? `HTTP ${d.response_code}` : d.error ?? d.status}{d.attempts > 1 && ` · ${d.attempts} attempts`}</span>
                {d.duration_ms !== null && <span className="text-xs tabular-nums text-muted-foreground">{d.duration_ms} ms</span>}
                <span className="text-xs text-muted-foreground" title={formatDate(d.created_at)}>{relativeTime(d.created_at)}</span>
              </button>
              {open === d.id && (
                <div className="space-y-2 bg-muted/20 px-3 pt-1 pb-3">
                  {d.error && <p className="text-xs text-destructive">{d.error}</p>}
                  <div className="text-xs font-medium">Request</div>
                  <pre className="max-h-48 overflow-auto rounded bg-background p-2 font-mono text-xs leading-5">{pretty(d.payload)}</pre>
                  {d.response_body && <><div className="text-xs font-medium">Response</div><pre className="max-h-32 overflow-auto rounded bg-background p-2 font-mono text-xs leading-5">{d.response_body}</pre></>}
                  <Button size="sm" variant="outline" disabled={redeliver.isPending} onClick={() => redeliver.mutate(d)}><RotateCwIcon />Redeliver</Button>
                </div>
              )}
            </li>
          ))}
        </ul>
        {redeliver.error && <ErrorBox error={redeliver.error} />}
        <DialogFooter><Button variant="outline" onClick={onClose}>Close</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function pretty(json: string) {
  try { return JSON.stringify(JSON.parse(json), null, 2) } catch { return json }
}
