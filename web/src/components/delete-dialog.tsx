import { useMutation, useQuery } from "@tanstack/react-query"
import { useState, type ReactNode } from "react"
import { AlertTriangleIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ErrorBox, Mono } from "@/components/ui-bits"
import { endpoints, formatBytes, shortDigest, type DeletePlan, type RepoDeletePreview, type TagDeletePreview } from "@/lib/api"

/**
 * Delete a repository, or some of its tags, after showing what goes and asking for the
 * repository's name. A repository or several tags go through a deletion plan (made when the
 * dialog opens, executed once within five minutes); one tag is deleted directly after its preview.
 */
export function DeleteDialog({ repo, tags, onClose, onDeleted }: { repo: string; tags?: string[]; onClose: () => void; onDeleted: () => void }) {
  const single = tags?.length === 1 ? tags[0] : null
  const [typed, setTyped] = useState("")
  // The plan (or, for one tag, its preview) is fetched when the dialog opens; `gen` makes a new one.
  const [gen, setGen] = useState(0)
  const plan = useQuery({
    queryKey: ["delete-plan", repo, tags, gen],
    queryFn: () => endpoints.deletePlan(repo, tags ? { tags } : { repository: true }),
    enabled: !single,
    staleTime: Infinity,
    gcTime: 0,
    retry: false,
  })
  const preview = useQuery({ queryKey: ["tag-delete-preview", repo, single, gen], queryFn: () => endpoints.tagDeletePreview(repo, single!), enabled: !!single, gcTime: 0, retry: false })
  const run = useMutation({
    meta: { success: single ? `Deleted ${single}` : tags ? `Deleted ${tags.length} tags` : "Repository deleted" },
    mutationFn: async () => {
      if (single) return endpoints.deleteManifest(repo, single)
      return endpoints.executeDeletePlan(plan.data!.id, typed.trim())
    },
    onSuccess: () => { onDeleted(); onClose() },
  })
  const loading = single ? preview.isLoading : plan.isLoading
  const loadError = single ? preview.error : plan.error
  const ready = single ? !!preview.data : !!plan.data
  const blocked = single ? !!preview.data?.is_immutable : immutableIn(plan.data).length > 0
  const what = single ? <>the tag <Mono className="text-foreground">{single}</Mono></> : tags ? <>{tags.length} tags</> : <>the repository <Mono className="text-foreground">{repo}</Mono></>
  const expired = (run.error as { status?: number } | null)?.status === 409
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="sm:max-w-lg">
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (typed.trim() === repo && ready && !blocked) run.mutate() }}>
          <DialogHeader>
            <DialogTitle>Delete {single ? `tag ${single}` : tags ? `${tags.length} tags` : "repository"}?</DialogTitle>
            <DialogDescription>This deletes {what} from <Mono className="text-foreground">{repo}</Mono>. Pulls of it stop working.</DialogDescription>
          </DialogHeader>
          {loading && <p className="text-sm text-muted-foreground">Checking what this affects...</p>}
          {loadError && <ErrorBox error={loadError} />}
          {single && preview.data && <TagImpact p={preview.data} />}
          {plan.data && <PlanImpact plan={plan.data} />}
          {ready && !blocked && (
            <div className="space-y-2">
              <Label htmlFor="delete-confirm">Type <Mono className="text-foreground">{repo}</Mono> to confirm</Label>
              <Input id="delete-confirm" className="font-mono" autoFocus autoComplete="off" value={typed} onChange={(e) => setTyped(e.target.value)} />
            </div>
          )}
          {run.error && <ErrorBox error={run.error} />}
          {expired && !single && <Button type="button" variant="outline" size="sm" onClick={() => { run.reset(); setTyped(""); setGen(gen + 1) }}>Check again</Button>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="destructive" disabled={!ready || blocked || typed.trim() !== repo || run.isPending}>{run.isPending ? "Deleting..." : "Delete"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function immutableIn(plan: DeletePlan | undefined): string[] {
  if (!plan) return []
  const p = plan.preview
  return "immutable_tags" in p ? p.immutable_tags : p.tags.filter((t) => t.is_immutable).map((t) => t.tag)
}

function Note({ warn, children }: { warn?: boolean; children: ReactNode }) {
  return <li className={warn ? "text-foreground" : undefined}>{warn && <AlertTriangleIcon className="mr-1 inline size-3.5 align-[-2px]" />}{children}</li>
}

/** What deleting one tag affects: aliases keep the image; indexes and referrers lose a tag's way in. */
function TagImpact({ p, compact }: { p: TagDeletePreview; compact?: boolean }) {
  return (
    <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
      {!compact && <Note>Points at <Mono className="text-foreground">{shortDigest(p.digest)}</Mono>.</Note>}
      {p.is_immutable && <Note warn><Mono>{p.tag}</Mono> is immutable and cannot be deleted.</Note>}
      {p.other_tags.length > 0
        ? <Note>Also tagged {p.other_tags.map((t, i) => <span key={t}>{i > 0 && ", "}<Mono className="text-foreground">{t}</Mono></span>)}: the image stays under {p.other_tags.length === 1 ? "that tag" : "those tags"}.</Note>
        : <Note>No other tag points at this image; it is removed by the next garbage collection.</Note>}
      {p.index_parents.length > 0 && <Note warn>Part of {p.index_parents.length === 1 ? "a multi-platform index" : `${p.index_parents.length} multi-platform indexes`} ({p.index_parents.map(shortDigest).join(", ")}), which {p.index_parents.length === 1 ? "keeps" : "keep"} it.</Note>}
      {p.referrers > 0 && <Note warn>{p.referrers} attached {p.referrers === 1 ? "artifact (signature, SBOM, ...)" : "artifacts (signatures, SBOMs, ...)"} refer to it.</Note>}
    </ul>
  )
}

function PlanImpact({ plan }: { plan: DeletePlan }) {
  const p = plan.preview
  if ("tags" in p && Array.isArray(p.tags)) {
    return (
      <div className="max-h-72 space-y-3 overflow-y-auto rounded-md border p-3">
        {p.tags.map((t) => (
          <div key={t.tag} className="space-y-1">
            <div className="text-sm"><Mono className="font-medium text-foreground">{t.tag}</Mono> <span className="text-muted-foreground">→ {shortDigest(t.digest)}</span></div>
            <TagImpact p={t} compact />
          </div>
        ))}
      </div>
    )
  }
  const r = p as RepoDeletePreview
  return (
    <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
      <Note>{r.tags} {r.tags === 1 ? "tag" : "tags"} and {r.manifests} {r.manifests === 1 ? "manifest" : "manifests"}, {formatBytes(r.bytes)} in all (layers shared with other repositories stay).</Note>
      {r.immutable_tags.length > 0 && <Note warn>Immutable tags block the deletion: {r.immutable_tags.join(", ")}.</Note>}
      {r.replication.map((x) => <Note key={`r${x.id}`} warn>Replication rule <Mono>{x.name}</Mono> covers {x.tags.length} {x.tags.length === 1 ? "tag" : "tags"} here; copies on its target stay unless it replicates deletions.</Note>)}
      {r.mirrors.map((x) => <Note key={`m${x.id}`} warn>The mirror of <Mono>{x.name}</Mono> brings {x.tags.length > 0 ? `${x.tags.length} ${x.tags.length === 1 ? "tag" : "tags"}` : "its tags"} back on its next sync.</Note>)}
      <Note>Its settings, permissions, stars and history go too. This cannot be undone.</Note>
    </ul>
  )
}
