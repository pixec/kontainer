import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { CpuIcon, KeyRoundIcon, PencilIcon, PlusIcon, ServerIcon, Trash2Icon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { CopyField, Empty, FormSection, PageHeader, Secret } from "@/components/page"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { endpoints, type Runner, type RunnerInput, type RunnerStatus, type RunnerWithToken } from "@/lib/api"
import { formatDate, relativeTime } from "@/lib/time"
import { cn } from "@/lib/utils"

const STATUS: Record<RunnerStatus, { label: string; dot: string }> = {
  online: { label: "Online", dot: "bg-success" },
  offline: { label: "Offline", dot: "bg-muted-foreground/50" },
  never: { label: "Waiting for it to connect", dot: "bg-warning" },
}

function StatusDot({ runner: r }: { runner: Runner }) {
  const s = r.is_enabled ? STATUS[r.status] : { label: "Disabled", dot: "bg-muted-foreground/30" }
  return (
    <span className="relative flex size-2.5 shrink-0" title={r.last_seen_at ? `${s.label} · last seen ${formatDate(r.last_seen_at)}` : s.label}>
      {r.is_enabled && r.status === "online" && <span className="absolute inline-flex size-full animate-ping rounded-full bg-success opacity-50" />}
      <span className={cn("relative inline-flex size-2.5 rounded-full", s.dot)} />
    </span>
  )
}

/** One runner: who it is, whether it's there, what it's doing. */
function RunnerRow({ runner: r, canManage, showScope, onEdit, onToken, onDelete }: {
  runner: Runner; canManage: boolean; showScope: boolean; onEdit: () => void; onToken: () => void; onDelete: () => void
}) {
  const busy = r.status === "online" && r.concurrency ? `${r.running ?? 0} of ${r.concurrency} running` : null
  const details = [
    r.executor && `${r.executor === "local" ? "Builds on its machine" : r.executor === "docker" ? "Docker containers" : "Kubernetes Jobs"}`,
    busy,
    r.hostname,
    r.version && `v${r.version}`,
  ].filter(Boolean)
  return (
    <li className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border bg-card p-4">
      <ServerIcon className="size-5 shrink-0 text-muted-foreground" strokeWidth={1.5} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <StatusDot runner={r} />
          <span className={cn("font-medium", !r.is_enabled && "text-muted-foreground")}>{r.name}</span>
          {r.namespace === null ? <span className="chip">Shared</span> : showScope && <span className="chip">Self-hosted · {r.namespace}</span>}
          {r.is_from_config && <span className="chip" title="Defined in the registry's configuration file">Config</span>}
          {!r.is_enabled && <span className="chip">Disabled</span>}
        </div>
        <div className="mt-1 text-xs text-muted-foreground">
          {!r.is_enabled ? "Gets no builds while disabled" : r.status === "never" ? "Start it with the token it was registered with" : details.join(" · ") || "Connected"}
          {r.last_seen_at && r.status !== "online" && <> · last seen <span title={formatDate(r.last_seen_at)}>{relativeTime(r.last_seen_at)}</span></>}
        </div>
        {showScope && r.namespace === null && (
          <div className="mt-1 text-xs text-muted-foreground">
            {r.is_all_namespaces ? "Builds for every user and organization" : r.namespaces?.length ? <>Builds for {r.namespaces.map((n, i) => <span key={n}>{i > 0 && ", "}<Mono className="text-foreground">{n}</Mono></span>)}</> : "Assigned to no one yet: it gets no builds"}
          </div>
        )}
      </div>
      {canManage && !r.is_from_config && (
        <div className="flex items-center gap-1">
          <Button size="sm" variant="ghost" onClick={onToken} title="Replace its token; the old one stops working"><KeyRoundIcon />New token</Button>
          <Button size="icon-sm" variant="ghost" aria-label="Edit" onClick={onEdit}><PencilIcon /></Button>
          <Button size="icon-sm" variant="ghost" aria-label="Delete" onClick={onDelete}><Trash2Icon /></Button>
        </div>
      )}
    </li>
  )
}

/** The token, once, and how to start a runner with it. */
function TokenReveal({ runner: r, onClose }: { runner: RunnerWithToken; onClose: () => void }) {
  const env = `-e KONTAINER_SERVER=${r.server_url} -e KONTAINER_RUNNER_TOKEN=${r.token}`
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Start {r.name}</DialogTitle>
          <DialogDescription>The runner connects to the registry with this token. Run one of these where builds should happen; it shows as online here once it connects.</DialogDescription>
        </DialogHeader>
        <Secret label="Runner token" value={r.token} />
        <div className="space-y-4 text-sm">
          <div className="space-y-1.5">
            <p className="font-medium">On a machine with Docker</p>
            <p className="text-xs text-muted-foreground">Each build gets a fresh pair of containers. The runner needs the Docker socket.</p>
            <CopyField wrap value={`docker run -d --name kontainer-runner --restart unless-stopped --user root -v /var/run/docker.sock:/var/run/docker.sock ${env} -e KONTAINER_RUNNER__EXECUTOR=docker -e KONTAINER_RUNNER__DOCKER__IMAGE=kontainer:0.2.0 kontainer:0.2.0 runner`} />
          </div>
          <div className="space-y-1.5">
            <p className="font-medium">On Kubernetes</p>
            <p className="text-xs text-muted-foreground">Each build runs as a Job next to a rootless BuildKit.</p>
            <CopyField wrap value={`helm install kontainer-runner deploy/helm/kontainer-runner --set server=${r.server_url} --set token=${r.token}`} />
          </div>
          <div className="space-y-1.5">
            <p className="font-medium">With the kontainer binary</p>
            <p className="text-xs text-muted-foreground">Builds in this process, with the machine's Docker (or <Mono>--backend buildctl --buildkit-addr ...</Mono>).</p>
            <CopyField wrap value={`kontainer runner --server ${r.server_url} --token ${r.token}`} />
          </div>
        </div>
        <DialogFooter><Button onClick={onClose}>Done</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

const splitNames = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

/** Register a runner, or edit one. `namespace`: a self-hosted runner of it; otherwise shared. */
function RunnerDialog({ runner, namespace, onClose, onCreated }: { runner: Runner | null; namespace?: string; onClose: () => void; onCreated: (r: RunnerWithToken) => void }) {
  const qc = useQueryClient()
  const shared = runner ? runner.namespace === null : !namespace
  const [name, setName] = useState(runner?.name ?? "")
  const [enabled, setEnabled] = useState(runner?.is_enabled ?? true)
  const [all, setAll] = useState(runner?.is_all_namespaces ?? false)
  const [names, setNames] = useState((runner?.namespaces ?? []).join(", "))
  const save = useMutation({
    meta: { success: runner ? "Runner saved" : undefined },
    mutationFn: async () => {
      const input: RunnerInput = { name, is_enabled: enabled, ...(shared ? { all_namespaces: all, namespaces: all ? [] : splitNames(names) } : runner ? {} : { namespace }) }
      return runner ? endpoints.updateRunner(runner.id, input) : endpoints.createRunner(input)
    },
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["runners"] })
      if ("token" in r) onCreated(r as RunnerWithToken)
      onClose()
    },
  })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
          <DialogHeader>
            <DialogTitle>{runner ? `Edit ${runner.name}` : shared ? "Register a shared runner" : "Register a runner"}</DialogTitle>
            <DialogDescription>
              {shared ? "A runner the registry provides. Choose who it builds for." : <>A runner of your own, on your machines, for repositories in <Mono>{namespace}/</Mono>.</>}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5"><Label htmlFor="runner-name">Name</Label><Input id="runner-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder={shared ? "shared-eu-1" : "build-server"} /></div>
          {shared && (
            <div className="space-y-3">
              <label className="flex items-center justify-between gap-3 text-sm"><span>Builds for every user and organization</span><Switch checked={all} onCheckedChange={setAll} /></label>
              {!all && (
                <div className="space-y-1.5">
                  <Label htmlFor="runner-ns">Users and organizations</Label>
                  <Input id="runner-ns" value={names} onChange={(e) => setNames(e.target.value)} placeholder="acme, zack" />
                  <p className="text-xs text-muted-foreground">Only these get builds from it, and the Builds tab once it's set up.</p>
                </div>
              )}
            </div>
          )}
          {runner && <label className="flex items-center justify-between gap-3 text-sm"><span>Enabled</span><Switch checked={enabled} onCheckedChange={setEnabled} /></label>}
          {save.error && <ErrorBox error={save.error} />}
          <DialogFooter><Button type="button" variant="outline" onClick={onClose}>Cancel</Button><Button type="submit" disabled={!name.trim() || save.isPending}>{runner ? "Save" : "Register"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function useRunnerActions() {
  const qc = useQueryClient()
  const [token, setToken] = useState<RunnerWithToken | null>(null)
  const rotate = useMutation({ mutationFn: endpoints.rotateRunnerToken, onSuccess: (r) => { setToken(r); qc.invalidateQueries({ queryKey: ["runners"] }) } })
  const remove = useMutation({ meta: { success: "Runner deleted" }, mutationFn: endpoints.deleteRunner, onSuccess: () => qc.invalidateQueries({ queryKey: ["runners"] }) })
  return {
    token, setToken,
    error: rotate.error ?? remove.error,
    rotate: (r: Runner) => { if (confirm(`Replace ${r.name}'s token? The runner stops getting builds until it's restarted with the new one.`)) rotate.mutate(r.id) },
    remove: (r: Runner) => { if (confirm(`Delete the runner ${r.name}? Builds it's running are failed when it next checks in.`)) remove.mutate(r.id) },
  }
}

/** A user's or organization's runners: its own, and the shared ones that build for it. */
export function RunnersSection({ namespace }: { namespace: string }) {
  const q = useQuery({ queryKey: ["runners", namespace], queryFn: () => endpoints.namespaceRunners(namespace), refetchInterval: 10000 })
  const [editing, setEditing] = useState<Runner | "new" | null>(null)
  const actions = useRunnerActions()
  const runners = q.data?.runners ?? []
  const own = runners.filter((r) => r.namespace !== null)
  const shared = runners.filter((r) => r.namespace === null)
  return (
    <FormSection title="Runners" description={<>Runners build images from Git for repositories in <Mono>{namespace}/</Mono>. Without one there are no builds, and no Builds tab.</>}>
      <div className="space-y-3">
        {q.isLoading && <Loading rows={2} />}
        {q.error && <ErrorBox error={q.error} />}
        {q.data && runners.length === 0 && (
          <div className="rounded-lg border border-dashed">
            <Empty>{q.data.self_hosted ? "No runners yet. Register one to run builds on your own machines, or ask an administrator for a shared one." : "No runners yet. Ask an administrator to share one with you."}</Empty>
          </div>
        )}
        {(own.length > 0 || shared.length > 0) && (
          <ul className="space-y-3">
            {own.map((r) => <RunnerRow key={r.id} runner={r} canManage showScope={false} onEdit={() => setEditing(r)} onToken={() => actions.rotate(r)} onDelete={() => actions.remove(r)} />)}
            {shared.map((r) => <RunnerRow key={r.id} runner={r} canManage={false} showScope={false} onEdit={() => {}} onToken={() => {}} onDelete={() => {}} />)}
          </ul>
        )}
        {actions.error && <ErrorBox error={actions.error} />}
        {q.data?.self_hosted && <Button variant="outline" onClick={() => setEditing("new")}><PlusIcon />Register runner</Button>}
      </div>
      {editing && <RunnerDialog runner={editing === "new" ? null : editing} namespace={namespace} onClose={() => setEditing(null)} onCreated={actions.setToken} />}
      {actions.token && <TokenReveal runner={actions.token} onClose={() => actions.setToken(null)} />}
    </FormSection>
  )
}

/** Admin → Runners: shared runners, and every self-hosted one. */
export function AdminRunnersPage() {
  const q = useQuery({ queryKey: ["runners"], queryFn: endpoints.runners, refetchInterval: 10000 })
  const [editing, setEditing] = useState<Runner | "new" | null>(null)
  const actions = useRunnerActions()
  const runners = q.data ?? []
  const shared = runners.filter((r) => r.namespace === null)
  const selfHosted = runners.filter((r) => r.namespace !== null)
  const online = runners.filter((r) => r.is_enabled && r.status === "online")
  const capacity = online.reduce((n, r) => n + (r.concurrency ?? 0), 0)
  const busy = online.reduce((n, r) => n + (r.running ?? 0), 0)
  return (
    <div className="space-y-8">
      <PageHeader
        title="Runners"
        description="Runners build images from Git. Users and organizations can bring their own; shared ones are yours to hand out."
        actions={q.data && <span className="flex items-center gap-2 text-sm text-muted-foreground"><CpuIcon className="size-4" />{online.length} online · {busy} of {capacity} build slots busy</span>}
      />
      {q.isLoading && <Loading rows={3} />}
      {q.error && <ErrorBox error={q.error} />}
      <section className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="font-semibold">Shared</h2>
          <Button variant="outline" size="sm" onClick={() => setEditing("new")}><PlusIcon />Register shared runner</Button>
        </div>
        {q.data && shared.length === 0 && <div className="rounded-lg border border-dashed"><Empty>No shared runners. Register one to give users and organizations builds without running their own.</Empty></div>}
        <ul className="space-y-3">
          {shared.map((r) => <RunnerRow key={r.id} runner={r} canManage showScope onEdit={() => setEditing(r)} onToken={() => actions.rotate(r)} onDelete={() => actions.remove(r)} />)}
        </ul>
      </section>
      {selfHosted.length > 0 && (
        <section className="space-y-3">
          <h2 className="font-semibold">Self-hosted</h2>
          <ul className="space-y-3">
            {selfHosted.map((r) => <RunnerRow key={r.id} runner={r} canManage showScope onEdit={() => setEditing(r)} onToken={() => actions.rotate(r)} onDelete={() => actions.remove(r)} />)}
          </ul>
        </section>
      )}
      {actions.error && <ErrorBox error={actions.error} />}
      {editing && <RunnerDialog runner={editing === "new" ? null : editing} onClose={() => setEditing(null)} onCreated={actions.setToken} />}
      {actions.token && <TokenReveal runner={actions.token} onClose={() => actions.setToken(null)} />}
    </div>
  )
}
