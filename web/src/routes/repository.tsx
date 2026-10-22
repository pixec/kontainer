import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState, type ReactNode } from "react"
import { Link, useNavigate, useParams, useSearchParams } from "react-router"
import { BookOpenIcon, BoxIcon, HammerIcon, Trash2Icon, ListChecksIcon, HistoryIcon, HourglassIcon, HashIcon, InfoIcon, TerminalIcon, WaypointsIcon, ChevronDownIcon, ChevronUpIcon, CpuIcon, GitCompareIcon, GlobeIcon, LockIcon, SettingsIcon, TagIcon, UsersIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { TabCount, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { endpoints, formatBytes, MAX_BULK_TAGS, SETTINGS_ACTIONS, shortDigest, type Action, type RepoMeta, type TagInfo, type Visibility } from "@/lib/api"
import { formatDate, relativeTime } from "@/lib/time"
import { useSession } from "@/lib/session"
import { Markdown } from "@/components/markdown"
import { Avatar, CopyField, DangerRow, DetailList, DetailRow, ENTITY_MARK, EntityHeader, Empty, FormActions, FormSection, OrgMark, Panel, SearchInput } from "@/components/page"
import { SeverityBar } from "@/components/severity-bar"
import { StarButton } from "@/components/star-button"
import { RepoPermissions } from "@/components/repo-permissions"
import { OriginDetails } from "@/components/repo-origin"
import { BuildsPanel, BuildTriggersSection } from "@/components/builds"
import { ExpirationDialog, ExpiryChip, RepoStateBanner, RepoStateSection, TagHistoryPanel } from "@/components/tag-history"
import { CodeBlock, UseSnippets } from "@/components/use-snippets"
import { Checkbox } from "@/components/ui/checkbox"
import { Skeleton } from "@/components/ui/skeleton"
import { ErrorBox, Mono } from "@/components/ui-bits"
import { DeleteDialog } from "@/components/delete-dialog"

export function RepositoryPage() {
  const { "*": name = "" } = useParams()
  const { me } = useSession()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const q = useQuery({
    queryKey: ["tags", name],
    queryFn: () => endpoints.tags(name),
    refetchInterval: (query) => (query.state.data?.some((t) => t.scan && (t.scan.status === "pending" || t.scan.status === "running")) ? 3000 : false),
  })
  // Under ["repositories"], so whatever refreshes the listing refreshes this too.
  const repo = useQuery({ queryKey: ["repositories", name], queryFn: () => endpoints.repository(name) })
  const canDelete = me?.features.delete && repo.data?.actions.includes("delete_repository")
  const canPush = !!repo.data?.actions.includes("push")
  // Deleting: the repository, or the tags in `deleting` (one from its card, or the bulk selection).
  const [deletingRepo, setDeletingRepo] = useState(false)
  const [deleting, setDeleting] = useState<string[] | null>(null)
  const [selecting, setSelecting] = useState(false)
  const [selected, setSelected] = useState<string[]>([])
  const toggle = (tag: string) => setSelected((s) => (s.includes(tag) ? s.filter((t) => t !== tag) : s.length >= MAX_BULK_TAGS ? s : [...s, tag]))
  const afterTagDelete = () => { setSelected([]); setSelecting(false); qc.invalidateQueries({ queryKey: ["tags", name] }); qc.invalidateQueries({ queryKey: ["repositories"] }) }
  const meta = useQuery({ queryKey: ["repo-meta", name], queryFn: () => endpoints.repoMeta(name) })
  const [filter, setFilter] = useState("")
  const [showAttached, setShowAttached] = useState(false)
  const [params, setParams] = useSearchParams()
  // The header and tabs render at once (the name is in the URL); only what is loading waits.
  if (q.error) return <ErrorBox error={q.error} />
  if (repo.error) return <ErrorBox error={repo.error} />
  const m = meta.data
  // cosign `sha256-<hex>.sig|.att|.sbom` tags are attachments; they are shown on their image instead.
  const attachedTags = (q.data ?? []).filter((t) => t.attached_to).length
  const tags = (q.data ?? []).filter((t) => (showAttached || !t.attached_to) && t.tag.toLowerCase().includes(filter.toLowerCase()))
  const mainTags = (q.data ?? []).filter((t) => !t.attached_to)

  const latest = (q.data ?? []).find((t) => !t.attached_to)
  const platforms = [...new Set((q.data ?? []).flatMap((t) => t.platforms.map((p) => p.platform).filter((p): p is string => !!p)))].sort()
  const owner = name.includes("/") ? name.slice(0, name.lastIndexOf("/")) : ""
  const short = name.slice(name.lastIndexOf("/") + 1)
  const about = (
    <aside className="space-y-4 lg:w-96 lg:shrink-0">
      {!m && <SideCard title="Details" icon={<InfoIcon />}><DetailsPlaceholder /></SideCard>}
      {m && <SideCard title="Details" icon={<InfoIcon />}>
        <DetailList>
          <DetailRow label="Visibility">{m?.visibility === "public" ? <GlobeIcon className="size-3.5 text-muted-foreground" /> : <LockIcon className="size-3.5 text-muted-foreground" />}{m?.visibility === "public" ? "Public" : "Private"}</DetailRow>
          {m?.owner && <DetailRow label="Owner">{(() => {
            const o = m.owner, label = o.display_name || o.name
            const inner = <>{o.kind === "org" ? <OrgMark name={o.name} label={label} className="size-5 rounded text-[10px]" /> : <Avatar name={label} src={o.avatar_url} className="size-5 text-[10px]" />}<span className="truncate">{label}</span></>
            return o.kind === "org"
              ? <Link to={`/orgs/${o.name}`} title={o.name} className="flex min-w-0 items-center gap-2 hover:underline">{inner}</Link>
              : <span title={o.name} className="flex min-w-0 items-center gap-2">{inner}</span>
          })()}</DetailRow>}
          {latest?.pushed_at && <DetailRow label="Last push"><span title={formatDate(latest.pushed_at)}>{relativeTime(latest.pushed_at)}</span></DetailRow>}
          {m?.created_at && <DetailRow label="Created"><span title={formatDate(m.created_at)}>{relativeTime(m.created_at)}</span></DetailRow>}
        </DetailList>
      </SideCard>}
      {latest && (
        <SideCard title="Use This Image" icon={<TerminalIcon />}>
          <UseSnippets name={name} reference={latest.tag} kind={latest.artifact.kind} compact />
        </SideCard>
      )}
      {m?.origin && (
        <SideCard title="Origin" icon={<WaypointsIcon />}><OriginDetails origin={m.origin} canManage={m.actions.includes("mirror")} /></SideCard>
      )}
      {platforms.length > 0 && (
        <SideCard title="Platforms" icon={<CpuIcon />}>
          <div className="flex flex-wrap gap-1.5">{platforms.map((p) => <span key={p} className="chip"><CpuIcon className="size-3" />{p}</span>)}</div>
        </SideCard>
      )}
      {m && m.topics.length > 0 && (
        <SideCard title="Topics" icon={<HashIcon />}>
          <div className="flex flex-wrap gap-1.5">{m.topics.map((t) => <Link key={t} to="/explore" className="chip transition-colors hover:bg-foreground/10 hover:text-foreground">{t}</Link>)}</div>
        </SideCard>
      )}
    </aside>
  )
  const can = (a: Action) => !!m?.actions.includes(a)
  // Created empty (or every tag deleted): how to put something in it.
  const isEmpty = q.data?.length === 0
  const addingTrigger = params.get("trigger") === "new"
  const setAddingTrigger = (v: boolean) => setParams(v ? { tab: "builds", trigger: "new" } : { tab: "builds" }, { replace: true })
  const emptyState = m && (
    <EmptyRepository name={name} canPush={canPush && !m.state}
      onBuild={m.builds && can("builds") && !m.state ? () => setAddingTrigger(true) : undefined} />
  )
  const canDeleteTags = !!me?.features.delete && can("delete") && !m?.state
  const showSettings = SETTINGS_ACTIONS.some((a) => a !== "delete_repository" && can(a)) || !!canDelete

  return (
    <>
      <EntityHeader
        mark={<OrgMark name={owner || short} label={short} className={ENTITY_MARK} />}
        title={short}
        description={m?.description}
        onAddDescription={can("metadata") ? () => setParams({ tab: "settings" }, { replace: true }) : undefined}
        actions={m && <StarButton name={name} state={m} />}
      />
      {m?.state && <RepoStateBanner state={m.state} />}
      <Tabs value={params.get("tab") ?? "overview"} onValueChange={(v) => setParams({ tab: v }, { replace: true })} className="gap-6">
        <TabsList>
          <TabsTrigger value="overview"><BookOpenIcon className="size-4" />Overview</TabsTrigger>
          <TabsTrigger value="tags"><TagIcon className="size-4" />Tags{q.data && <TabCount>{mainTags.length}</TabCount>}</TabsTrigger>
          <TabsTrigger value="history"><HistoryIcon className="size-4" />History</TabsTrigger>
          {m?.builds && <TabsTrigger value="builds"><HammerIcon className="size-4" />Builds</TabsTrigger>}
          {can("permissions") && <TabsTrigger value="permissions"><UsersIcon className="size-4" />Permissions</TabsTrigger>}
          {showSettings && <TabsTrigger value="settings"><SettingsIcon className="size-4" />Settings</TabsTrigger>}
        </TabsList>
        <TabsContent value="overview">
          <div className="flex flex-col gap-6 lg:flex-row">
            <div className="flex min-w-0 flex-1 flex-col gap-6">
              {isEmpty && emptyState}
              <div className="flex flex-1 flex-col">
                <Panel id="readme" icon={<BookOpenIcon />} title="README" className="min-h-64 flex-1">
                  {!m ? <ReadmePlaceholder /> : m.readme.trim() ? <div className="px-6 py-5"><Markdown source={m.readme} /></div> : <Empty>No README yet.{can("metadata") && " Add one in Settings."}</Empty>}
                </Panel>
              </div>
            </div>
            {about}
          </div>
        </TabsContent>
        <TabsContent value="tags">
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <SearchInput placeholder="Filter tags..." value={filter} onChange={setFilter} className="sm:w-72" />
              {attachedTags > 0 && (
                <label className="flex items-center gap-2 px-2 text-sm text-muted-foreground">
                  <Checkbox checked={showAttached} onCheckedChange={(c) => setShowAttached(!!c)} />Show {attachedTags} signature and SBOM {attachedTags === 1 ? "tag" : "tags"}
                </label>
              )}
              {canDeleteTags && tags.length > 0 && (
                <div className="ml-auto flex items-center gap-2">
                  {selecting && <span className="text-sm text-muted-foreground">{selected.length} selected{selected.length >= MAX_BULK_TAGS && ` (at most ${MAX_BULK_TAGS})`}</span>}
                  {selecting && <Button variant="outline" size="sm" onClick={() => setSelected(tags.slice(0, MAX_BULK_TAGS).map((t) => t.tag))}>Select {tags.length > MAX_BULK_TAGS ? `first ${MAX_BULK_TAGS}` : "all"}</Button>}
                  {selecting && <Button variant="destructive" size="sm" disabled={selected.length === 0} onClick={() => setDeleting(selected)}><Trash2Icon />Delete</Button>}
                  <Button variant="outline" size="sm" onClick={() => { setSelecting(!selecting); setSelected([]) }}><ListChecksIcon />{selecting ? "Done" : "Select"}</Button>
                </div>
              )}
              {mainTags.length >= 2 && (
                <Button variant="outline" className={canDeleteTags && tags.length > 0 ? undefined : "ml-auto"} asChild>
                  <Link to={`/r/${name}/compare?a=${encodeURIComponent(mainTags[1].tag)}&b=${encodeURIComponent(mainTags[0].tag)}`}><GitCompareIcon />Compare tags</Link>
                </Button>
              )}
            </div>
            {q.isLoading && <TagCardPlaceholder />}
            {isEmpty ? emptyState : q.data && tags.length === 0 && <Panel><Empty>No tags{filter ? " match" : " yet"}.</Empty></Panel>}
            {tags.map((t) => <TagCard key={t.tag} name={name} tag={t} canEdit={canPush && !m?.state}
              onDelete={canDeleteTags ? () => setDeleting([t.tag]) : undefined}
              selected={selecting ? selected.includes(t.tag) : undefined} onSelect={() => toggle(t.tag)} selectDisabled={!selected.includes(t.tag) && selected.length >= MAX_BULK_TAGS} />)}
            {deleting && <DeleteDialog repo={name} tags={deleting} onClose={() => setDeleting(null)} onDeleted={afterTagDelete} />}
          </div>
        </TabsContent>
        <TabsContent value="history"><TagHistoryPanel repo={name} /></TabsContent>
        {m?.builds && <TabsContent value="builds"><BuildsPanel repo={name} canPush={canPush} canManage={can("builds") && !m.state} addingTrigger={addingTrigger} onAddingTriggerChange={setAddingTrigger} /></TabsContent>}
        {can("permissions") && <TabsContent value="permissions"><RepoPermissions name={name} /></TabsContent>}
        {showSettings && (
          <TabsContent value="settings">
            <div>
              {m && <RepoSettings name={name} meta={m} />}
              {can("builds") && m?.builds && <BuildTriggersSection repo={name} />}
              {m && can("state") && <RepoStateSection key={m.state?.state ?? "normal"} repo={name} state={m.state} />}
              {canDelete && (
                <FormSection title="Danger zone" description="Irreversible actions." className="border-t pt-8">
                  <DangerRow title="Delete this repository" description="Removes every tag and manifest. This cannot be undone."
                    action={<Button variant="destructive" onClick={() => setDeletingRepo(true)}>Delete repository</Button>} />
                  {deletingRepo && <DeleteDialog repo={name} onClose={() => setDeletingRepo(false)} onDeleted={() => { qc.invalidateQueries({ queryKey: ["repositories"] }); navigate("/") }} />}
                </FormSection>
              )}
            </div>
          </TabsContent>
        )}
      </Tabs>
    </>
  )
}

/** A repository with no tags: the push commands, and a build from Git when one can be set up. */
function EmptyRepository({ name, canPush, onBuild }: { name: string; canPush: boolean; onBuild?: () => void }) {
  const host = location.host
  if (!canPush && !onBuild) return <Panel><Empty>This repository is empty. Nothing has been pushed yet.</Empty></Panel>
  return (
    <Panel padded icon={<BoxIcon />} title="This repository is empty" description="Push an image to it, or build one from a Git repository.">
      <div className="space-y-4">
        {canPush && (
          <div className="space-y-2">
            <p className="text-sm font-medium">Push an image</p>
            <CodeBlock code={`docker login ${host}
docker tag <image> ${host}/${name}:latest
docker push ${host}/${name}:latest`} />
          </div>
        )}
        {onBuild && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3">
            <div className="min-w-0">
              <p className="text-sm font-medium">Build from Git</p>
              <p className="text-sm text-muted-foreground">Build a Git repository's Dockerfile into {name} whenever it changes.</p>
            </div>
            <Button onClick={onBuild}><HammerIcon />Set up a build from Git</Button>
          </div>
        )}
      </div>
    </Panel>
  )
}

/** Sidebar card: the same Panel (icon, title, divider) as the main column. */
function SideCard({ title, icon, children }: { title: string; icon: ReactNode; children: ReactNode }) {
  return <Panel padded icon={icon} title={title}>{children}</Panel>
}


function ReadmePlaceholder() {
  return (
    <div className="placeholder-in space-y-3 px-6 py-5">
      <Skeleton className="h-6 w-48" />
      {["w-full", "w-[92%]", "w-[78%]"].map((w) => <Skeleton key={w} className={`h-3.5 ${w}`} />)}
      <Skeleton className="mt-5 h-16 w-full opacity-60" />
      {["w-[88%]", "w-[60%]"].map((w) => <Skeleton key={w} className={`h-3.5 ${w}`} />)}
    </div>
  )
}

function DetailsPlaceholder() {
  return (
    <div className="placeholder-in space-y-3.5 py-0.5">
      {["w-20", "w-28", "w-24", "w-20"].map((w, i) => (
        <div key={i} className="flex items-center justify-between gap-4"><Skeleton className="h-3.5 w-16 opacity-60" /><Skeleton className={`h-3.5 ${w}`} /></div>
      ))}
    </div>
  )
}

/** A tag card's outline while tags load. */
function TagCardPlaceholder() {
  return (
    <Panel className="placeholder-in">
      <div className="flex items-center justify-between gap-3 border-b px-4 py-3">
        <div className="space-y-2"><Skeleton className="h-4 w-24" /><Skeleton className="h-3 w-56 opacity-60" /></div>
        <Skeleton className="h-9 w-80 max-w-[50%]" />
      </div>
      <div className="space-y-3 px-4 py-3.5">
        {[0, 1].map((i) => (
          <div key={i} className="flex items-center gap-4"><Skeleton className="h-3.5 w-28" /><Skeleton className="h-3.5 w-24 opacity-60" /><Skeleton className="h-2 flex-1 opacity-60" /><Skeleton className="h-3.5 w-16" /></div>
        ))}
      </div>
    </Panel>
  )
}

function TagCard({ name, tag, canEdit, onDelete, selected, onSelect, selectDisabled }: { name: string; tag: TagInfo; canEdit: boolean; onDelete?: () => void
  /** Bulk selection is on: whether this tag is in it. */
  selected?: boolean; onSelect?: () => void; selectDisabled?: boolean }) {
  const [all, setAll] = useState(false)
  const [expiring, setExpiring] = useState(false)
  const rows = all ? tag.platforms : tag.platforms.slice(0, 3)
  const hidden = tag.platforms.length - 3
  return (
    <Panel>
      <header className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
        <div className="min-w-0">
          <span className="flex flex-wrap items-center gap-2">
            {selected !== undefined && <Checkbox checked={selected} disabled={selectDisabled} onCheckedChange={() => onSelect?.()} aria-label={`Select ${tag.tag}`} />}
            <Link to={`/r/${name}/m/${encodeURIComponent(tag.tag)}`} className="text-sm font-semibold hover:underline">{tag.tag}</Link>
            {tag.artifact.kind !== "image" && tag.artifact.kind !== "index" && <span className="chip">{tag.artifact.label}</span>}
            {tag.expires_at && <ExpiryChip at={tag.expires_at} />}
          </span>
          <div className="mt-0.5 text-xs text-muted-foreground">
            {tag.pushed_at ? <span title={formatDate(tag.pushed_at)}>Pushed {relativeTime(tag.pushed_at)}</span> : "Push time unknown"}
            <span className="mx-1.5">·</span>
            {tag.kind === "index" ? `${tag.platforms.length} ${tag.platforms.length === 1 ? "platform" : "platforms"}` : "Single image"}
            <span className="mx-1.5">·</span>
            <Mono>{shortDigest(tag.digest)}</Mono>
          </div>
        </div>
        <div className="flex w-full items-center gap-1 sm:w-auto">
          <div className="min-w-0 flex-1 sm:min-w-80"><CopyField value={`docker pull ${location.host}/${name}:${tag.tag}`} /></div>
          {canEdit && <Button variant="ghost" size="icon" title={tag.expires_at ? "Change expiration" : "Set expiration"} aria-label="Set expiration" onClick={() => setExpiring(true)}><HourglassIcon /></Button>}
          {onDelete && <Button variant="ghost" size="icon" className="hover:text-destructive" title="Delete tag" aria-label={`Delete ${tag.tag}`} onClick={onDelete}><Trash2Icon /></Button>}
        </div>
      </header>
      {expiring && <ExpirationDialog repo={name} tag={tag.tag} current={tag.expires_at} onClose={() => setExpiring(false)} />}
      <Table>
        <TableHeader><TableRow><TableHead className="pl-4">Digest</TableHead><TableHead>OS / Arch</TableHead><TableHead>Vulnerabilities</TableHead><TableHead className="pr-4 text-right">Compressed size</TableHead></TableRow></TableHeader>
        <TableBody>
          {rows.length === 0 && <TableRow className="hover:bg-transparent"><TableCell colSpan={4} className="pl-4 text-muted-foreground">This index has no platform images.</TableCell></TableRow>}
          {rows.map((p) => (
            <TableRow key={p.digest}>
              <TableCell className="py-2.5 pl-4"><Link to={`/r/${name}/m/${p.digest}`} className="font-mono text-xs hover:underline">{shortDigest(p.digest)}</Link></TableCell>
              <TableCell>{p.platform ?? <span className="text-muted-foreground">unknown</span>}</TableCell>
              <TableCell><SeverityBar scan={p.scan} to={p.scan?.status === "done" ? `/r/${name}/s/${p.digest}` : undefined} /></TableCell>
              <TableCell className="pr-4 text-right tabular-nums text-muted-foreground">{formatBytes(p.size)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {hidden > 0 && (
        <button type="button" onClick={() => setAll(!all)} className="flex w-full items-center justify-center gap-1.5 border-t px-4 py-2.5 text-sm text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground">
          {all ? <>Show fewer<ChevronUpIcon className="size-4" /></> : <>Show {hidden} more {hidden === 1 ? "platform" : "platforms"}<ChevronDownIcon className="size-4" /></>}
        </button>
      )}
    </Panel>
  )
}

function RepoSettings({ name, meta }: { name: string; meta: RepoMeta }) {
  const canMeta = meta.actions.includes("metadata")
  const canVisibility = meta.actions.includes("visibility")
  const qc = useQueryClient()
  const [description, setDescription] = useState(meta.description)
  const [readme, setReadme] = useState(meta.readme)
  const [visibility, setVisibility] = useState<Visibility>(meta.visibility)
  const [topics, setTopics] = useState(meta.topics.join(", "))
  const save = useMutation({
    meta: { success: "Repository settings saved" },
    // Send only what the caller may change: each part is checked on its own.
    mutationFn: () => endpoints.updateRepoMeta(name, {
      ...(canVisibility ? { visibility } : {}),
      ...(canMeta ? { description, readme, topics: topics.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean) } : {}),
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["repo-meta", name] }); qc.invalidateQueries({ queryKey: ["repositories"] }) },
  })
  if (!canMeta && !canVisibility) return null
  return (
    <>
      {canVisibility && <FormSection title="Visibility" description="Public repositories can be pulled by anyone and appear on the Explore page.">
        <div className="grid gap-3 sm:grid-cols-2">
          {(["private", "public"] as const).map((v) => (
            <label key={v} className={`flex cursor-pointer items-start gap-3 rounded-lg p-3 ring-1 transition-colors ${visibility === v ? "bg-foreground/5 ring-foreground/30" : "ring-border hover:bg-foreground/[0.03]"}`}>
              <input type="radio" className="mt-1 size-4 accent-foreground" checked={visibility === v} onChange={() => setVisibility(v)} />
              <span>
                <span className="flex items-center gap-1.5 text-sm font-medium">{v === "public" ? <GlobeIcon className="size-4" /> : <LockIcon className="size-4" />}{v === "public" ? "Public" : "Private"}</span>
                <span className="block text-sm text-muted-foreground">{v === "public" ? "Anyone can pull. Pushing still needs access." : "Only people with access can pull."}</span>
              </span>
            </label>
          ))}
        </div>
      </FormSection>}
      {canMeta && <><FormSection title="About" description="Shown in the header, on Explore and in search.">
        <div className="space-y-5">
          <div className="space-y-2"><Label htmlFor="rdesc">Short description</Label><Input id="rdesc" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={200} placeholder="Minimal base image" /></div>
          <div className="space-y-2"><Label htmlFor="rtopics">Topics</Label><Input id="rtopics" value={topics} onChange={(e) => setTopics(e.target.value)} placeholder="database, go, base-image" /><p className="text-xs text-muted-foreground">Comma separated: lowercase letters, digits and dashes.</p></div>
        </div>
      </FormSection>
      <FormSection title="README" description="Markdown shown on the Overview tab." className="border-b-0 pb-6">
        <Textarea rows={14} className="font-mono text-xs" value={readme} onChange={(e) => setReadme(e.target.value)} />
      </FormSection></>}
      <FormActions>
        {save.error && <div className="mr-auto"><ErrorBox error={save.error} /></div>}
        <Button onClick={() => save.mutate()} disabled={save.isPending}>{save.isPending ? "Saving..." : "Save changes"}</Button>
      </FormActions>
    </>
  )
}
