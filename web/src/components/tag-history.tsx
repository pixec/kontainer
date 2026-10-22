import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { Link } from "react-router"
import { ArchiveRestoreIcon, ArrowRightIcon, CloudDownloadIcon, CopyIcon, HistoryIcon, HourglassIcon, ImportIcon, LockIcon, RefreshCwIcon, ScissorsIcon, TagIcon, Trash2Icon, UploadIcon } from "lucide-react"
import { Empty, FormSection, Panel, SearchInput } from "@/components/page"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ErrorBox, Loading } from "@/components/ui-bits"
import { endpoints, shortDigest, type RepoState, type RepoStateKind, type TagEvent } from "@/lib/api"
import { formatDate, relativeTime, formatSeconds, within, daysFromNow, toLocalInput } from "@/lib/time"
import { cn } from "@/lib/utils"

/** A Time Machine window: "7 days", or "off". */
export const formatWindow = (secs: number) => (secs > 0 ? formatSeconds(secs) : "off")

/** "Expires in 3 days", amber when under a day. */
export function ExpiryChip({ at }: { at: string }) {
  const soon = within(at, 86400)
  return (
    <span className={cn("chip", soon && "bg-warning/15 text-warning")} title={`Deleted automatically ${formatDate(at)}`}>
      <HourglassIcon className="size-3" />Expires {relativeTime(at)}
    </span>
  )
}

const PRESETS: [string, number][] = [["1 day", 1], ["7 days", 7], ["30 days", 30], ["90 days", 90]]

export function ExpirationDialog({ repo, tag, current, onClose }: { repo: string; tag: string; current?: string; onClose: () => void }) {
  const qc = useQueryClient()
  const [custom, setCustom] = useState("")
  const save = useMutation({
    meta: { success: "Saved" },
    mutationFn: (at: string | null) => endpoints.setTagExpiration(repo, tag, at),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["tags", repo] }); qc.invalidateQueries({ queryKey: ["manifest"] }); onClose() },
  })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Expiration for {tag}</DialogTitle>
          <DialogDescription>
            The tag is deleted automatically at this time{current ? <>; it currently expires {formatDate(current)}</> : null}. Within the Time Machine window it can still be restored from History.
          </DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {PRESETS.map(([label, d]) => <Button key={d} variant="outline" disabled={save.isPending} onClick={() => save.mutate(daysFromNow(d))}>{label}</Button>)}
        </div>
        <form className="space-y-1.5" onSubmit={(e) => { e.preventDefault(); if (custom) save.mutate(new Date(custom).toISOString()) }}>
          <Label htmlFor="exp-at">Or pick a time</Label>
          <div className="flex gap-2">
            <Input id="exp-at" type="datetime-local" value={custom} onChange={(e) => setCustom(e.target.value)} min={toLocalInput(new Date())} className="flex-1" />
            <Button type="submit" disabled={!custom || save.isPending}>Set</Button>
          </div>
        </form>
        {save.error && <ErrorBox error={save.error} />}
        <DialogFooter>
          {current && <Button variant="ghost" className="mr-auto text-destructive hover:text-destructive" disabled={save.isPending} onClick={() => save.mutate(null)}>Remove expiration</Button>}
          <Button variant="outline" onClick={onClose}>Cancel</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

const ACTION: Record<TagEvent["action"], { icon: typeof TagIcon; verb: string; tone?: string }> = {
  push: { icon: UploadIcon, verb: "Pushed" },
  move: { icon: ArrowRightIcon, verb: "Moved" },
  delete: { icon: Trash2Icon, verb: "Deleted", tone: "text-destructive" },
  restore: { icon: ArchiveRestoreIcon, verb: "Restored", tone: "text-success" },
  expire: { icon: HourglassIcon, verb: "Expired", tone: "text-warning" },
  retention: { icon: ScissorsIcon, verb: "Retention deleted", tone: "text-destructive" },
  sync: { icon: CopyIcon, verb: "Mirror synced" },
  import: { icon: ImportIcon, verb: "Imported" },
  cache: { icon: CloudDownloadIcon, verb: "Cache refreshed" },
}

function DigestLink({ repo, digest }: { repo: string; digest: string }) {
  return <Link to={`/r/${repo}/m/${digest}`} className="font-mono text-xs text-foreground hover:underline">{shortDigest(digest)}</Link>
}

/** A stable hue per image, so the same image is easy to follow down the graph. */
function digestHue(digest: string) {
  let h = 0
  for (const c of digest.slice(-12)) h = (h * 31 + c.charCodeAt(0)) % 360
  return h
}

function ImageDot({ digest, className }: { digest: string | null; className?: string }) {
  return <span aria-hidden className={cn("inline-block shrink-0 rounded-full", className)} style={digest ? { backgroundColor: `hsl(${digestHue(digest)} 70% 55%)` } : undefined} />
}

/** Changes made together (one push, build or sync moving several tags to one image). */
interface EventGroup { key: number; action: TagEvent["action"]; actor: string; at: string; digest: string | null; events: TagEvent[] }

function groupEvents(events: TagEvent[]): EventGroup[] {
  const out: EventGroup[] = []
  for (const e of events) {
    const g = out.at(-1)
    const together = g && g.action === e.action && g.actor === e.actor && g.digest === e.digest && Math.abs(Date.parse(g.at) - Date.parse(e.at)) < 60_000
    if (together) g.events.push(e)
    else out.push({ key: e.id, action: e.action, actor: e.actor, at: e.at, digest: e.digest, events: [e] })
  }
  return out
}

/** Every change to the repository's tags as a graph, with Restore for what the Time Machine can undo. */
export function TagHistoryPanel({ repo, tag }: { repo: string; tag?: string }) {
  const qc = useQueryClient()
  const [filter, setFilter] = useState("")
  const q = useQuery({ queryKey: ["tag-history", repo, tag ?? null], queryFn: () => endpoints.tagHistory(repo, tag) })
  const restore = useMutation({
    meta: { success: "Restored" },
    mutationFn: async (events: TagEvent[]) => { for (const e of events) await endpoints.restoreTag(repo, e.tag, e.previous!) },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["tag-history", repo] }); qc.invalidateQueries({ queryKey: ["tags", repo] }) },
  })
  const events = (q.data?.events ?? []).filter((e) => !filter || e.tag.toLowerCase().includes(filter.toLowerCase()))
  const groups = groupEvents(events)
  return (
    <div className="space-y-4">
      {!tag && <SearchInput className="w-full sm:w-full" placeholder="Filter history by tag..." value={filter} onChange={setFilter} />}
      <Panel icon={<HistoryIcon />} title={tag ? `History of ${tag}` : "Tag history"}
        actions={q.data && <span className="text-xs text-muted-foreground" title="How long a deleted or moved tag can be restored">Time Machine: {formatWindow(q.data.time_machine_secs)}</span>}>
        {q.isLoading && <div className="p-4"><Loading rows={3} /></div>}
        {q.error && <div className="p-4"><ErrorBox error={q.error} /></div>}
        {q.data && events.length === 0 && <Empty>{filter ? "No changes to matching tags." : "No tag changes recorded yet."}</Empty>}
        <ol className="py-2">
          {groups.map((g, i) => <HistoryNode key={g.key} repo={repo} group={g} last={i === groups.length - 1} restoring={restore.isPending} onRestore={(evs) => restore.mutate(evs)} />)}
        </ol>
      </Panel>
      {restore.error && <ErrorBox error={restore.error} />}
    </div>
  )
}

function HistoryNode({ repo, group: g, last, restoring, onRestore }: { repo: string; group: EventGroup; last: boolean; restoring: boolean; onRestore: (events: TagEvent[]) => void }) {
  const a = ACTION[g.action] ?? ACTION.push
  const previous = [...new Set(g.events.map((e) => e.previous).filter((p): p is string => !!p))]
  const restorable = g.events.filter((e) => e.is_restorable)
  const tags = g.events.map((e) => e.tag)
  return (
    <li className="relative flex gap-3 pr-4 pl-4">
      {/* The rail: a dot per change, coloured by the image it points at. */}
      <div className="relative flex w-5 shrink-0 justify-center">
        {!last && <span aria-hidden className="absolute top-5 -bottom-2 w-px bg-border" />}
        <span className="relative mt-2.5 flex size-5 items-center justify-center rounded-full border bg-card">
          {g.digest ? <ImageDot digest={g.digest} className="size-2.5" /> : <a.icon className={cn("size-3 text-muted-foreground", a.tone)} />}
        </span>
      </div>
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1.5 border-b py-2.5 last:border-b-0">
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-1.5 text-sm">
            <a.icon className={cn("size-3.5 text-muted-foreground", a.tone)} />
            <span className={a.tone}>{a.verb}</span>
            {tags.map((t) => <Link key={t} to={`/r/${repo}/m/${encodeURIComponent(t)}`} className="chip font-medium text-foreground hover:underline">{t}</Link>)}
            {g.digest && <><span className="text-muted-foreground">→</span><DigestLink repo={repo} digest={g.digest} /></>}
          </div>
          {previous.length > 0 && (
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              {g.digest ? "was" : "pointed at"}
              {previous.length === 1
                ? <><ImageDot digest={previous[0]} className="size-2" /><DigestLink repo={repo} digest={previous[0]} /></>
                : <span>{previous.length} different images</span>}
            </div>
          )}
        </div>
        <span className="text-xs text-muted-foreground" title={formatDate(g.at)}>{g.actor} · {relativeTime(g.at)}</span>
        {restorable.length > 0 && (
          <Button size="sm" variant="outline" disabled={restoring}
            title={restorable.length === 1 ? `Point ${restorable[0].tag} back at ${shortDigest(restorable[0].previous!)}` : `Point ${restorable.map((e) => e.tag).join(", ")} back where they were`}
            onClick={() => {
              const what = restorable.map((e) => `${e.tag} → ${shortDigest(e.previous!)}`).join(", ")
              if (confirm(`Restore ${what}?`)) onRestore(restorable)
            }}>
            <ArchiveRestoreIcon />Restore
          </Button>
        )}
      </div>
    </li>
  )
}

const STATES: { value: RepoStateKind; label: string; hint: string; icon: typeof TagIcon }[] = [
  { value: "normal", label: "Normal", hint: "Pushes and deletes allowed.", icon: TagIcon },
  { value: "read_only", label: "Read-only", hint: "Pulls only, e.g. during a release freeze.", icon: LockIcon },
  { value: "mirror", label: "Mirror", hint: "Only a mirror sync writes to it.", icon: RefreshCwIcon },
]

export function RepoStateSection({ repo, state }: { repo: string; state: RepoState | null }) {
  const qc = useQueryClient()
  const [value, setValue] = useState<RepoStateKind>(state?.state ?? "normal")
  const [reason, setReason] = useState(state?.reason ?? "")
  const save = useMutation({
    meta: { success: "Saved" },
    mutationFn: () => endpoints.setRepoState(repo, value, reason || undefined),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["repo-meta", repo] }),
  })
  const dirty = value !== (state?.state ?? "normal") || reason !== (state?.reason ?? "")
  return (
    <FormSection title="State" description="Freeze the repository, or reserve it for a mirror.">
      <div className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-3">
          {STATES.map((s) => (
            <label key={s.value} className={cn("flex cursor-pointer items-start gap-3 rounded-lg p-3 ring-1 transition-colors", value === s.value ? "bg-foreground/5 ring-foreground/30" : "ring-border hover:bg-foreground/[0.03]")}>
              <input type="radio" className="mt-1 size-4 accent-foreground" checked={value === s.value} onChange={() => setValue(s.value)} />
              <span>
                <span className="flex items-center gap-1.5 text-sm font-medium"><s.icon className="size-4" />{s.label}</span>
                <span className="block text-sm text-muted-foreground">{s.hint}</span>
              </span>
            </label>
          ))}
        </div>
        {value !== "normal" && (
          <div className="space-y-1.5">
            <Label htmlFor="state-reason">Reason <span className="font-normal text-muted-foreground">(shown to anyone who tries to push)</span></Label>
            <Input id="state-reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={200} placeholder="Release freeze until Friday" />
          </div>
        )}
        {save.error && <ErrorBox error={save.error} />}
        <div className="flex items-center justify-end gap-3">
          <Button onClick={() => save.mutate()} disabled={!dirty || save.isPending}>Save state</Button>
        </div>
      </div>
    </FormSection>
  )
}

/** Under the repository header when writes are blocked. */
export function RepoStateBanner({ state }: { state: RepoState }) {
  const Icon = state.state === "mirror" ? RefreshCwIcon : LockIcon
  return (
    <div className="flex items-start gap-3 rounded-lg border border-warning/30 bg-warning/10 px-4 py-3 text-sm">
      <Icon className="mt-0.5 size-4 shrink-0 text-warning" />
      <div>
        <span className="font-medium">{state.state === "mirror" ? "Mirror" : "Read-only"}</span>
        <span className="text-muted-foreground"> · {state.state === "mirror" ? "only its mirror sync can push or delete" : "pushes and deletes are refused"}{state.reason && <>: {state.reason}</>}</span>
        <div className="text-xs text-muted-foreground">Set by {state.set_by} {relativeTime(state.set_at)}</div>
      </div>
    </div>
  )
}
