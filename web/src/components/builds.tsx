import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { BuildSteps } from "@/components/build-steps"
import { useEffect, useRef, useState } from "react"
import { toast } from "sonner"
import { Link } from "react-router"
import { CheckCircle2Icon, ChevronRightIcon, CircleAlertIcon, CircleSlashIcon, GitBranchIcon, GitCommitHorizontalIcon, HammerIcon, Loader2Icon, PlayIcon, PlusIcon, RefreshCwIcon, TimerIcon, TriangleAlertIcon } from "lucide-react"
import { Avatar, CopyField, Empty, FormSection, LabeledSelect, Panel, Secret } from "@/components/page"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { endpoints, shortDigest, type Build, type BuildLogChunk, type BuildTrigger, type TriggerInput } from "@/lib/api"
import { formatDate, relativeTime, elapsed } from "@/lib/time"
import { cn } from "@/lib/utils"

const active = (b: Build) => b.status === "queued" || b.status === "running"
const shortRef = (r: string) => r.replace(/^refs\/(heads|tags)\//, "")

/** The runner a build ran on: `build-server (host-1)` → runner build-server on host-1. */
function agentLabel(agent: string) {
  const m = /^(.*) \((.*)\)$/.exec(agent)
  return m ? <>runner <Mono className="text-foreground">{m[1]}</Mono> on {m[2]}</> : <>runner <Mono className="text-foreground">{agent}</Mono></>
}

const duration = (b: Build) => (b.started_at ? elapsed(b.started_at, b.finished_at) : null)

export function BuildStatusIcon({ status, className }: { status: Build["status"]; className?: string }) {
  const c = cn("size-4 shrink-0", className)
  if (status === "succeeded") return <CheckCircle2Icon className={cn(c, "text-success")} />
  if (status === "failed") return <CircleAlertIcon className={cn(c, "text-destructive")} />
  if (status === "cancelled") return <CircleSlashIcon className={cn(c, "text-muted-foreground")} />
  if (status === "running") return <Loader2Icon className={cn(c, "animate-spin text-foreground")} />
  return <TimerIcon className={cn(c, "text-muted-foreground")} />
}

/**
 * A running build's log as it arrives: the server streams its chunks (server-sent events, the
 * session cookie authenticates). EventSource reconnects by itself and resumes after the last
 * chunk it got (Last-Event-ID); chunks seen before are skipped all the same. `onDone` runs once
 * the build has ended. `null`: not following (not running, or the stream can't be opened).
 */
function useLiveLog(id: number, running: boolean, onDone: () => void, onFail: () => void): string | null {
  const [log, setLog] = useState<{ id: number; text: string } | null>(null)
  const handlers = useRef({ onDone, onFail })
  useEffect(() => { handlers.current = { onDone, onFail } })
  useEffect(() => {
    if (!running) return
    let last = 0
    let acc = ""
    let frame = 0
    // A burst of chunks renders once.
    const flush = () => { frame = 0; setLog({ id, text: acc }) }
    const es = new EventSource(endpoints.buildLogStream(id))
    es.onmessage = (e: MessageEvent<string>) => {
      const c = JSON.parse(e.data) as BuildLogChunk
      if (c.seq <= last) return
      last = c.seq
      acc += c.data
      if (!frame) frame = requestAnimationFrame(flush)
    }
    es.addEventListener("done", () => {
      es.close()
      if (frame) cancelAnimationFrame(frame)
      frame = 0
      setLog({ id, text: acc })
      handlers.current.onDone()
    })
    // Refused outright (signed out, gone): EventSource gives up, so fall back to polling.
    es.onerror = () => { if (es.readyState === EventSource.CLOSED) handlers.current.onFail() }
    return () => { es.close(); if (frame) cancelAnimationFrame(frame) }
  }, [id, running])
  if (!running) return null
  return log?.id === id ? log.text : ""
}

function BuildLog({ id }: { id: number }) {
  const qc = useQueryClient()
  // While the log comes over the stream, polls leave it out and only look for news (commit, agent).
  const live = useRef(false)
  const [streamFailed, setStreamFailed] = useState(false)
  const q = useQuery({
    queryKey: ["build", id],
    queryFn: () => endpoints.build(id, !live.current),
    refetchInterval: (s) => (s.state.data && active(s.state.data) ? (live.current ? 10000 : 1500) : false),
  })
  const following = q.data?.status === "running" && !streamFailed
  useEffect(() => { live.current = following }, [following])
  const liveLog = useLiveLog(id, following, () => {
    // Over: fetch the build once more, with its whole log and outcome.
    live.current = false
    qc.invalidateQueries({ queryKey: ["build", id] })
    qc.invalidateQueries({ queryKey: ["builds"] })
  }, () => setStreamFailed(true))
  const cancel = useMutation({ meta: { success: "Build cancelled" }, mutationFn: () => endpoints.cancelBuild(id), onSuccess: () => qc.invalidateQueries({ queryKey: ["build", id] }) })
  if (!q.data) return <div className="p-4"><Loading rows={3} /></div>
  const b = q.data
  return (
    <div className="space-y-2 border-t bg-canvas-subtle px-4 py-3">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        {b.commit_sha && <span>Commit <Mono className="text-foreground">{b.commit_sha.slice(0, 12)}</Mono></span>}
        {b.agent && <span title={b.agent}>· On {agentLabel(b.agent)}</span>}
        {b.digest && <span>· Image <Link to={`/r/${b.repository}/m/${b.digest}`} className="font-mono text-foreground hover:underline">{shortDigest(b.digest)}</Link></span>}
        <span className="flex-1" />
        {active(b) && <Button size="sm" variant="outline" disabled={cancel.isPending} onClick={() => cancel.mutate()}>Cancel build</Button>}
      </div>
      <BuildSteps log={(following && liveLog) || b.log || ""} status={b.status} />
      {cancel.error && <ErrorBox error={cancel.error} />}
    </div>
  )
}

/** What the server makes of a ref typed by hand: `main` → `refs/heads/main`; full refs and commits as they are. */
const fullRef = (r: string) => (r.startsWith("refs/") || /^[0-9a-f]{40}$/i.test(r) ? r : `refs/heads/${r}`)

/** `#3`, `#3 and #4`, `#3, #4 and #5`. */
const buildList = (ids: number[]) => {
  const s = ids.map((id) => `#${id}`)
  return s.length > 1 ? `${s.slice(0, -1).join(", ")} and ${s[s.length - 1]}` : s[0] ?? ""
}

function StartBuildDialog({ triggers, builds, onClose, onStarted }: { triggers: BuildTrigger[]; builds: Build[]; onClose: () => void; onStarted: (id: number) => void }) {
  const [tid, setTid] = useState(String(triggers[0]?.id ?? ""))
  const t = triggers.find((x) => String(x.id) === tid)
  const [ref, setRef] = useState(t?.branches.find((b) => !/[*?]/.test(b)) ?? "main")
  const [tags, setTags] = useState("")
  const tagList = tags.split(/[\s,]+/).filter(Boolean)
  // Queued builds of the same trigger and ref: starting this one cancels them.
  const replaced = builds.filter((b) => b.status === "queued" && String(b.trigger_id) === tid && b.git_ref === fullRef(ref.trim())).map((b) => b.id).sort((x, y) => x - y)
  const run = useMutation({
    mutationFn: () => endpoints.runBuild(Number(tid), ref, tagList.length ? tagList : undefined),
    onSuccess: (r) => {
      toast.success(`Build #${r.build} queued`, { description: r.superseded.length ? `Cancelled the queued ${r.superseded.length === 1 ? "build" : "builds"} it replaces: ${buildList(r.superseded)}.` : undefined })
      onStarted(r.build); onClose()
    },
  })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <form className="grid gap-5" onSubmit={(e) => { e.preventDefault(); run.mutate() }}>
          <DialogHeader><DialogTitle>Start a build</DialogTitle><DialogDescription>Builds the latest commit of a branch or tag, or a specific commit.</DialogDescription></DialogHeader>
          {triggers.length > 1 && <LabeledSelect label="Trigger" value={tid} onChange={setTid} options={triggers.map((x) => [String(x.id), x.name] as [string, string])} className="w-full" />}
          <div className="space-y-1.5"><Label htmlFor="build-ref">Branch, tag or commit</Label><Input id="build-ref" autoFocus value={ref} onChange={(e) => setRef(e.target.value)} placeholder="main" /></div>
          <div className="space-y-1.5">
            <Label htmlFor="build-tags">Image tags <span className="font-normal text-muted-foreground">(optional)</span></Label>
            <Input id="build-tags" className="font-mono text-xs" value={tags} onChange={(e) => setTags(e.target.value)} placeholder={t?.tags.join(" ") || "{branch} {sha7}"} />
            <p className="text-xs text-muted-foreground">Separate with spaces. Leave empty for the trigger's tags. <Mono>{"{branch}"}</Mono>, <Mono>{"{sha7}"}</Mono> and <Mono>{"{sha}"}</Mono> work here too.</p>
          </div>
          {replaced.length > 0 && (
            <div role="alert" className="flex gap-2.5 rounded-lg border border-warning/40 bg-warning/10 px-3 py-2.5 text-sm">
              <TriangleAlertIcon className="mt-0.5 size-4 shrink-0 text-warning" />
              <p>
                {replaced.length === 1 ? <>Build {buildList(replaced)} of <Mono>{shortRef(fullRef(ref.trim()))}</Mono> is still queued.</> : <>Builds {buildList(replaced)} of <Mono>{shortRef(fullRef(ref.trim()))}</Mono> are still queued.</>}{" "}
                Starting this one cancels {replaced.length === 1 ? "it" : "them"}, since only the newest is worth building.
              </p>
            </div>
          )}
          {run.error && <ErrorBox error={run.error} />}
          <DialogFooter><Button type="button" variant="outline" onClick={onClose}>Cancel</Button><Button type="submit" disabled={!tid || !ref.trim() || run.isPending}><PlayIcon />{replaced.length ? "Start and cancel queued" : "Start build"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Where a queued build stands: "Next up", "3 ahead", or waiting on its namespace's limit. */
function QueueNote({ queue: q }: { queue: NonNullable<Build["queue"]> }) {
  const atLimit = q.namespace_limit !== null && q.namespace_running >= q.namespace_limit
  const text = atLimit
    ? `Waiting for ${q.namespace}'s ${q.namespace_running === 1 ? "running build" : `${q.namespace_running} running builds`}`
    : q.ahead === 0 ? "Next up" : `${q.ahead} ahead`
  const title = atLimit
    ? `${q.namespace} may run ${q.namespace_limit} ${q.namespace_limit === 1 ? "build" : "builds"} at once (builds.max_per_namespace). Other namespaces' builds go first meanwhile.`
    : q.ahead === 0 ? "Starts as soon as a worker is free" : `${q.ahead} queued ${q.ahead === 1 ? "build was" : "builds were"} queued before this one`
  return <span className="flex items-center gap-1 text-xs text-muted-foreground" title={title}><TimerIcon className="size-3.5" />{text}</span>
}

/** Who started a build: their avatar and name, and whether a Git push (webhook) did it. */
function BuildActor({ build: b }: { build: Build }) {
  const u = b.actor_user
  if (u?.via_poll) return <span className="flex items-center gap-1.5" title="Started when polling found a new commit"><GitCommitHorizontalIcon className="size-4" /><span className="text-foreground/80">New commit</span></span>
  const name = u?.display_name || u?.name || b.actor
  return (
    <span className="flex items-center gap-1.5" title={u ? `${u.display_name ? `${u.display_name} (${u.name})` : u.name}${u.via_webhook ? ", by pushing to Git" : ""}` : b.actor}>
      <Avatar name={name} src={u?.avatar_url} className="size-4.5 text-[9px]" />
      <span className="text-foreground/80">{name}</span>
      {u?.via_webhook && <span>via push</span>}
    </span>
  )
}

/** Repository → Builds tab. */
/** The Builds tab. `canManage` (the `builds` action) offers adding the first trigger here;
 *  `addingTrigger` / `onAddingTriggerChange` let the page open that dialog (an empty
 *  repository's "Set up a build from Git"). */
export function BuildsPanel({ repo, canPush, canManage, addingTrigger, onAddingTriggerChange }: { repo: string; canPush: boolean; canManage?: boolean; addingTrigger?: boolean; onAddingTriggerChange?: (v: boolean) => void }) {
  const triggers = useQuery({ queryKey: ["build-triggers", repo], queryFn: () => endpoints.buildTriggers(repo) })
  const builds = useQuery({ queryKey: ["builds", repo], queryFn: () => endpoints.builds(repo), refetchInterval: (s) => (s.state.data?.some(active) ? 2000 : 15000) })
  const [open, setOpen] = useState<number | null>(null)
  const [starting, setStarting] = useState(false)
  const [localAdding, setLocalAdding] = useState(false)
  const adding = addingTrigger ?? localAdding
  const setAdding = onAddingTriggerChange ?? setLocalAdding
  const [secret, setSecret] = useState<{ secret: string; url: string } | null>(null)
  const list = builds.data ?? []
  const hasTriggers = (triggers.data?.length ?? 0) > 0
  const addTrigger = canManage && triggers.isSuccess && !hasTriggers
  return (
    <div className="space-y-4">
      {secret && (
        <Panel padded icon={<HammerIcon />} title="Build trigger created" description="Point the Git host's push webhook here, or let it poll on its schedule. Change it under Settings.">
          <div className="space-y-3">
            <CopyField label="Webhook URL" value={secret.url} />
            <Secret label="Webhook secret" value={secret.secret} hint="Copy it now: it is not shown again." />
          </div>
        </Panel>
      )}
      <Panel icon={<HammerIcon />} title="Builds" actions={<>
        {addTrigger && <Button size="sm" variant="outline" onClick={() => setAdding(true)}><PlusIcon />Add build trigger</Button>}
        {canPush && hasTriggers && <Button size="sm" onClick={() => setStarting(true)}><PlayIcon />Start build</Button>}
      </>}>
        {builds.isLoading && <div className="p-4"><Loading rows={3} /></div>}
        {builds.error && <div className="p-4"><ErrorBox error={builds.error} /></div>}
        {builds.data && list.length === 0 && (
          <Empty>{hasTriggers ? "No builds yet. Push to the Git repository or start one." : addTrigger ? "Add a build trigger to build this repository from a Git repository's Dockerfile." : <>Add a build trigger under Settings to build this repository from Git.</>}</Empty>
        )}
        <ul className="divide-y">
          {list.map((b) => (
            <li key={b.id}>
              <button type="button" onClick={() => setOpen(open === b.id ? null : b.id)} className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-left text-sm hover:bg-accent/40">
                <ChevronRightIcon className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open === b.id && "rotate-90")} />
                <BuildStatusIcon status={b.status} />
                <span className="font-medium tabular-nums">#{b.id}</span>
                <span className="flex items-center gap-1 text-muted-foreground"><GitBranchIcon className="size-3.5" />{shortRef(b.git_ref)}</span>
                {b.commit_sha && <Mono className="text-xs text-muted-foreground">{b.commit_sha.slice(0, 7)}</Mono>}
                <span className="flex min-w-0 flex-1 flex-wrap gap-1">{(b.status === "succeeded" || b.status === "running") && b.tags.map((t) => <span key={t} className="chip">{t}</span>)}</span>
                {b.status === "failed" && b.message && <span className="max-w-72 truncate text-xs text-destructive" title={b.message}>{b.message}</span>}
                {b.status === "cancelled" && b.message?.startsWith("Superseded") && <span className="text-xs text-muted-foreground">{b.message}</span>}
                {b.queue && <QueueNote queue={b.queue} />}
                <span className="flex items-center gap-1.5 text-xs text-muted-foreground" title={formatDate(b.created_at)}>
                  <BuildActor build={b} />
                  <span>· {relativeTime(b.created_at)}{duration(b) && <> · {duration(b)}</>}</span>
                </span>
              </button>
              {open === b.id && <BuildLog id={b.id} />}
            </li>
          ))}
        </ul>
      </Panel>
      {starting && triggers.data && <StartBuildDialog triggers={triggers.data} builds={list} onClose={() => setStarting(false)} onStarted={(id) => { setOpen(id); builds.refetch() }} />}
      {adding && <TriggerDialog repo={repo} trigger={null} onClose={() => setAdding(false)} onCreated={setSecret} />}
    </div>
  )
}

const POLL_OPTIONS: [string, string][] = [["", "Webhook only"], ["60", "Every minute"], ["300", "Every 5 minutes"], ["900", "Every 15 minutes"], ["3600", "Every hour"]]

/** `60` → "minute", `300` → "5 minutes". */
function every(secs: number) {
  if (secs % 3600 === 0) return secs === 3600 ? "hour" : `${secs / 3600} hours`
  if (secs % 60 === 0) return secs === 60 ? "minute" : `${secs / 60} minutes`
  return `${secs} seconds`
}

/** What a trigger last saw and built, and how it hears about new commits. */
function TriggerStatus({ trigger: t, repo }: { trigger: BuildTrigger; repo: string }) {
  const qc = useQueryClient()
  const check = useMutation({
    mutationFn: () => endpoints.checkBuildTrigger(t.id),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["build-triggers", repo] })
      qc.invalidateQueries({ queryKey: ["builds", repo] })
      if (r.check_error) toast.error(`Couldn't check Git: ${r.check_error}`)
      else toast.success(r.queued.length ? `New commits found. Queued build ${r.queued.map((id) => `#${id}`).join(", ")}` : "Checked Git: nothing new since the last check")
    },
  })
  const refs = Object.entries(t.seen_refs)
  const last = t.last_build
  return (
    <div className="space-y-1.5 rounded-md bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        {t.poll_secs ? <RefreshCwIcon className="size-3.5" /> : <GitBranchIcon className="size-3.5" />}
        <span>
          {!t.is_enabled ? "Paused: builds only start by hand" : t.poll_secs ? <>Checks Git every {every(t.poll_secs)}{t.checked_at ? <>, last <span title={formatDate(t.checked_at)}>{relativeTime(t.checked_at)}</span></> : ", first check soon"}</> : "Waits for push webhooks"}
        </span>
        {t.poll_secs && t.is_enabled && (
          <Button size="xs" variant="ghost" className="-my-1 ml-auto" disabled={check.isPending} onClick={() => check.mutate()}>
            <RefreshCwIcon className={cn("size-3", check.isPending && "animate-spin")} />Check now
          </Button>
        )}
      </div>
      {t.check_error && <p className="text-destructive">Last check failed: {t.check_error}</p>}
      {refs.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span>Last seen</span>
          {refs.slice(0, 6).map(([r, sha]) => (
            <span key={r} className="inline-flex items-center gap-1 rounded border bg-background px-1.5 py-0.5" title={`${r} at ${sha}`}>
              <span className="text-foreground">{shortRef(r)}</span><Mono>{sha.slice(0, 7)}</Mono>
            </span>
          ))}
          {refs.length > 6 && <span>and {refs.length - 6} more</span>}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-1.5">
        {last ? (
          <>
            <span>Last build</span>
            <BuildStatusIcon status={last.status} className="size-3.5" />
            <span className="text-foreground tabular-nums">#{last.id}</span>
            <span>{shortRef(last.git_ref)}{last.commit_sha && <> @ <Mono>{last.commit_sha.slice(0, 7)}</Mono></>}</span>
            <span title={formatDate(last.created_at)}>· {relativeTime(last.created_at)}</span>
          </>
        ) : <span>No builds yet</span>}
      </div>
    </div>
  )
}

const split = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

function TriggerDialog({ repo, trigger, onClose, onCreated }: { repo: string; trigger: BuildTrigger | null; onClose: () => void; onCreated: (secret: { secret: string; url: string }) => void }) {
  const qc = useQueryClient()
  const [v, setV] = useState({
    name: trigger?.name ?? "main", git_url: trigger?.git_url ?? "", git_username: trigger?.git_username ?? "", git_token: "",
    branches: (trigger?.branches ?? ["main"]).join(", "), dockerfile: trigger?.dockerfile ?? "Dockerfile", context: trigger?.context ?? ".",
    tags: (trigger?.tags ?? []).join(", "), is_enabled: trigger?.is_enabled ?? true, poll: String(trigger?.poll_secs ?? ""),
  })
  const input = (): TriggerInput => ({ ...v, poll_secs: v.poll ? Number(v.poll) : null, git_username: v.git_username || undefined, git_token: v.git_token || undefined, branches: split(v.branches), tags: split(v.tags) })
  const save = useMutation({
    meta: { success: "Build trigger saved" },
    mutationFn: async (): Promise<BuildTrigger & { secret?: string }> => trigger ? endpoints.updateBuildTrigger(trigger.id, input()) : endpoints.createBuildTrigger(repo, input()),
    onSuccess: (t) => { qc.invalidateQueries({ queryKey: ["build-triggers", repo] }); if (t.secret && t.webhook_url) onCreated({ secret: t.secret, url: t.webhook_url }); onClose() },
  })
  const set = (patch: Partial<typeof v>) => setV({ ...v, ...patch })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-xl">
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
          <DialogHeader>
            <DialogTitle>{trigger ? `Edit ${trigger.name}` : "New build trigger"}</DialogTitle>
            <DialogDescription>Builds the Git repository's Dockerfile into {repo} on every push to a matching branch or tag.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 sm:grid-cols-[10rem_1fr]">
            <div className="space-y-1.5"><Label htmlFor="bt-name">Name</Label><Input id="bt-name" value={v.name} onChange={(e) => set({ name: e.target.value })} /></div>
            <div className="space-y-1.5"><Label htmlFor="bt-url">Git URL</Label><Input id="bt-url" autoFocus={!trigger} value={v.git_url} onChange={(e) => set({ git_url: e.target.value })} placeholder="https://github.com/acme/api.git" /></div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5"><Label htmlFor="bt-br">Branches and tags</Label><Input id="bt-br" value={v.branches} onChange={(e) => set({ branches: e.target.value })} placeholder="main, release/*, v*" /></div>
            <div className="space-y-1.5">
              <Label htmlFor="bt-tags">Image tags <span className="font-normal text-muted-foreground">(optional)</span></Label>
              <Input id="bt-tags" className="font-mono text-xs" value={v.tags} onChange={(e) => set({ tags: e.target.value })} placeholder="{branch}, {sha7}" />
              <div className="flex flex-wrap gap-1">
                {["{branch}", "{sha7}", "{sha}", "{tag}", "latest"].filter((x) => !split(v.tags).includes(x)).map((x) => (
                  <button key={x} type="button" onClick={() => set({ tags: [...split(v.tags), x].join(", ") })} className="rounded-md border px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground hover:border-ring hover:text-foreground">+ {x}</button>
                ))}
              </div>
            </div>
            <div className="space-y-1.5"><Label htmlFor="bt-df">Dockerfile</Label><Input id="bt-df" value={v.dockerfile} onChange={(e) => set({ dockerfile: e.target.value })} /></div>
            <div className="space-y-1.5"><Label htmlFor="bt-ctx">Context</Label><Input id="bt-ctx" value={v.context} onChange={(e) => set({ context: e.target.value })} /></div>
          </div>
          <p className="text-xs text-muted-foreground">Tags are templates: <Mono>{"{branch}"}</Mono>, <Mono>{"{tag}"}</Mono> (Git tag pushes), <Mono>{"{sha}"}</Mono>, <Mono>{"{sha7}"}</Mono>, or fixed names like <Mono>latest</Mono>. Leave them empty to push each build by digest only.</p>
          <details className="rounded-lg border px-3 py-2 text-sm">
            <summary className="cursor-pointer text-muted-foreground">Private repository</summary>
            <div className="mt-3 grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5"><Label htmlFor="bt-user">Username</Label><Input id="bt-user" value={v.git_username} onChange={(e) => set({ git_username: e.target.value })} placeholder="x-access-token" /></div>
              <div className="space-y-1.5"><Label htmlFor="bt-tok">Token</Label><Input id="bt-tok" type="password" autoComplete="new-password" value={v.git_token} onChange={(e) => set({ git_token: e.target.value })} placeholder={trigger?.has_token ? "unchanged" : "read-only deploy token"} /></div>
            </div>
          </details>
          <div className="space-y-2">
            <LabeledSelect label="Watch for changes" value={POLL_OPTIONS.some(([k]) => k === v.poll) ? v.poll : ""} onChange={(poll) => set({ poll })} options={POLL_OPTIONS} className="w-full" />
            <p className="text-xs text-muted-foreground">{v.poll ? "Kontainer asks the Git host for new commits on this schedule, so no webhook is needed (handy when the Git host can't reach this registry). Webhooks still work and are faster." : "Builds start when the Git host calls the trigger's webhook. Choose a schedule if it can't reach this registry."}</p>
          </div>
          <label className="flex items-center gap-2 text-sm"><Checkbox checked={v.is_enabled} onCheckedChange={(c) => set({ is_enabled: !!c })} />Build new commits automatically</label>
          {save.error && <ErrorBox error={save.error} />}
          <DialogFooter><Button type="button" variant="outline" onClick={onClose}>Cancel</Button><Button type="submit" disabled={!v.git_url || save.isPending}>{trigger ? "Save" : "Create trigger"}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Repository → Settings: where builds come from. */
export function BuildTriggersSection({ repo }: { repo: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["build-triggers", repo], queryFn: () => endpoints.buildTriggers(repo) })
  const [editing, setEditing] = useState<BuildTrigger | "new" | null>(null)
  const [secret, setSecret] = useState<{ secret: string; url: string } | null>(null)
  const del = useMutation({ meta: { success: "Build trigger deleted" }, mutationFn: endpoints.deleteBuildTrigger, onSuccess: () => qc.invalidateQueries({ queryKey: ["build-triggers", repo] }) })
  const rotate = useMutation({ mutationFn: endpoints.rotateBuildSecret, onSuccess: (r) => setSecret({ secret: r.secret, url: r.webhook_url }) })
  return (
    <FormSection title="Build triggers" description="Build images from a Git repository when it changes. Point the Git host's push webhook at the trigger's URL.">
      <div className="space-y-3">
        {q.isLoading && <Loading rows={2} />}
        {q.data?.map((t) => (
          <div key={t.id} className="space-y-2 rounded-lg border p-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <HammerIcon className="size-4 text-muted-foreground" />
              <span className="font-medium">{t.name}</span>
              {!t.is_enabled && <span className="chip">paused</span>}
              <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground" title={t.git_url}>{t.git_url}</span>
              <Button size="sm" variant="ghost" onClick={() => setEditing(t)}>Edit</Button>
              <Button size="sm" variant="ghost" onClick={() => rotate.mutate(t.id)}>New secret</Button>
              <Button size="sm" variant="ghost" className="text-destructive hover:text-destructive" onClick={() => { if (confirm(`Delete trigger ${t.name}? Past builds are kept.`)) del.mutate(t.id) }}>Delete</Button>
            </div>
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <span>Branches <Mono className="text-foreground">{t.branches.join(", ")}</Mono></span>
              <span>Tags {t.tags.length ? <Mono className="text-foreground">{t.tags.join(", ")}</Mono> : <span className="text-foreground">none (by digest)</span>}</span>
              <span>Dockerfile <Mono className="text-foreground">{t.context === "." ? t.dockerfile : `${t.context} · ${t.dockerfile}`}</Mono></span>
            </div>
            <TriggerStatus trigger={t} repo={repo} />
            {t.webhook_url && <CopyField value={t.webhook_url} />}
          </div>
        ))}
        {secret && (
          <div className="space-y-2">
            <Secret label="Webhook secret" value={secret.secret} hint="Copy it now. GitHub: Settings → Webhooks → Add webhook, Payload URL above, content type application/json, this secret, Just the push event. GitLab: Settings → Webhooks, Secret token, Push and Tag push events." />
          </div>
        )}
        {(del.error || rotate.error) && <ErrorBox error={del.error ?? rotate.error} />}
        <Button variant="outline" onClick={() => setEditing("new")}><PlusIcon />Add build trigger</Button>
      </div>
      {editing && <TriggerDialog repo={repo} trigger={editing === "new" ? null : editing} onClose={() => setEditing(null)} onCreated={setSecret} />}
    </FormSection>
  )
}
