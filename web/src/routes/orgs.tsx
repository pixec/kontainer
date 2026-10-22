import { toast } from "sonner"
import { useForm } from "@tanstack/react-form"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useEffect, useState } from "react"
import { Link, Navigate, useNavigate, useParams } from "react-router"
import { BotIcon, BoxIcon, HardDriveIcon, KeyRoundIcon, PlusIcon, SettingsIcon, ShieldAlertIcon, UsersIcon, RefreshCwIcon, WebhookIcon, ServerIcon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { TabCount, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { endpoints, type Level, type Team, type TeamRole } from "@/lib/api"
import { relativeTime } from "@/lib/time"
import { LevelBadge, LevelSelect, TEAM_ROLES } from "@/components/access"
import { PrincipalPicker } from "@/components/principal-picker"
import { useScope } from "@/lib/scope"
import { RenameNamespace } from "@/components/rename-namespace"
import { NamespaceStorageSections } from "@/components/storage"
import { WebhooksPanel } from "@/components/webhooks"
import { RunnersSection } from "@/components/runners"
import { ExpirySelect, RobotStatus } from "@/components/robots"
import { CveAllowlist, SecurityPolicyForm } from "@/components/security-policy"
import { cn } from "@/lib/utils"
import { StarToggle } from "@/components/star-button"
import { useSession } from "@/lib/session"
import { BackLink, ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { formatWindow } from "@/components/tag-history"
import { OrgSsoSection, TeamSyncDialog, syncLabel } from "@/components/org-sso"
import { RobotFederationDialog } from "@/components/robot-federation"
import { DangerRow, ENTITY_MARK, Empty, EntityHeader, FormSection, LabeledSelect, OrgMark, Panel, SearchInput, Secret, SideNav, StackedSections } from "@/components/page"

const NAMESPACE = /^[a-z0-9][a-z0-9._-]*$/
const slugify = (v: string) => v.toLowerCase().trim().replace(/[^a-z0-9._-]+/g, "-").replace(/^[^a-z0-9]+|-+$/g, "")

export function OrgsPage() {
  const { me } = useSession()
  const navigate = useNavigate()
  const q = useQuery({ queryKey: ["orgs"], queryFn: endpoints.orgs })
  const repos = useQuery({ queryKey: ["repositories"], queryFn: endpoints.repositories })
  const [filter, setFilter] = useState("")
  const [open, setOpen] = useState(false)
  const canCreate = me?.globals.includes("orgs:create") || me?.globals.includes("system")
  if (q.isLoading) return <Loading />
  if (q.error) return <ErrorBox error={q.error} />
  const f = filter.toLowerCase()
  const orgs = (q.data ?? []).filter((o) => o.name.includes(f) || (o.display_name ?? "").toLowerCase().includes(f))
  return (
    <>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <SearchInput className="w-full sm:flex-1" placeholder="Find an organization..." value={filter} onChange={setFilter} />
        {canCreate && <Button size="lg" onClick={() => setOpen(true)}><PlusIcon />New organization</Button>}
      </div>
      {orgs.length === 0 && (
        <Panel><Empty>{filter ? "No organizations match." : <>
          Organizations publish images under a shared name like <Mono className="text-foreground">{location.host}/acme/app</Mono>, with teams deciding who can push and pull.
          <br />{canCreate ? "Use New organization to create one." : "Ask an organization admin to add you to a team."}
        </>}</Empty></Panel>
      )}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {orgs.map((o) => {
          const repoCount = (repos.data ?? []).filter((r) => r.name.startsWith(`${o.name}/`)).length
          return (
            <Link key={o.id} to={`/orgs/${o.name}`} className="group flex flex-col rounded-lg border bg-card p-5 transition-colors hover:border-ring">
              <div className="flex items-center justify-between gap-3">
                <OrgMark name={o.name} label={o.display_name || o.name} />
                {o.is_admin ? <Badge variant="outline" className="font-medium text-muted-foreground">Admin</Badge> : o.is_member && <Badge variant="outline" className="font-normal text-muted-foreground">Member</Badge>}
              </div>
              <div className="mt-4 min-w-0">
                <div className="truncate text-base font-semibold group-hover:underline">{o.display_name || o.name}</div>
                <div className="truncate font-mono text-xs text-muted-foreground">{o.name}/</div>
              </div>
              {o.description
                ? <p className="mt-3 line-clamp-2 text-sm text-muted-foreground">{o.description}</p>
                : o.is_admin && <span role="link" onClick={(e) => { e.preventDefault(); navigate(`/orgs/${o.name}/settings`) }} className="mt-3 inline-flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground hover:underline"><PlusIcon className="size-3.5" />Add a description</span>}
              <div className="mt-auto" />
              <div className="mt-5 flex items-center gap-4 border-t pt-4 text-sm text-muted-foreground">
                <span className="flex items-center gap-1.5"><BoxIcon className="size-4" /><b className="font-medium text-foreground tabular-nums">{repoCount}</b> {repoCount === 1 ? "repository" : "repositories"}</span>
                <span className="flex items-center gap-1.5"><UsersIcon className="size-4" /><b className="font-medium text-foreground tabular-nums">{o.teams}</b> {o.teams === 1 ? "team" : "teams"}</span>
              </div>
            </Link>
          )
        })}
      </div>
      <CreateOrgDialog open={open} onOpenChange={setOpen} />
    </>
  )
}

function CreateOrgDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [display, setDisplay] = useState("")
  const [name, setName] = useState("")
  const [nameTouched, setNameTouched] = useState(false)
  const ns = nameTouched ? name : slugify(display)
  const valid = NAMESPACE.test(ns)
  const reset = () => { setDisplay(""); setName(""); setNameTouched(false); create.reset() }
  const create = useMutation({
    meta: { success: "Organization created" },
    mutationFn: () => endpoints.createOrg(ns, display.trim() || undefined),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["orgs"] }); onOpenChange(false); navigate(`/orgs/${ns}`); reset() },
  })
  return (
    <Dialog open={open} onOpenChange={(v) => { onOpenChange(v); if (!v) reset() }}>
      <DialogContent className="sm:max-w-lg">
        <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); if (valid) create.mutate() }}>
          <DialogHeader>
            <DialogTitle>New organization</DialogTitle>
            <DialogDescription>Organizations own a namespace. You become its first admin.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="odisp">Display name</Label>
            <Input id="odisp" autoFocus placeholder="ACME Corp" maxLength={100} value={display} onChange={(e) => setDisplay(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="oname">Namespace</Label>
            <Input id="oname" className="font-mono" placeholder="acme" value={ns} aria-invalid={ns !== "" && !valid} onChange={(e) => { setNameTouched(true); setName(e.target.value.toLowerCase()) }} />
            <p className="text-xs text-muted-foreground">
              {ns && !valid ? "Lowercase letters, digits, . _ and -, starting with a letter or digit." : <>Images are pushed to <Mono className="text-foreground">{location.host}/{ns || "acme"}/&lt;name&gt;</Mono>. This can't be changed later.</>}
            </p>
          </div>
          {create.error && <ErrorBox error={create.error} />}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={!valid || create.isPending}>{create.isPending ? "Creating..." : "Create organization"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export function OrgPage() {
  const { name = "", tab = "repositories" } = useParams()
  // When this org is the current workspace, the navbar tabs already navigate between sections.
  const { scope, setScope, orgs } = useScope()
  const navigate = useNavigate()
  // The URL wins: opening (or refreshing) an org page of yours makes it the workspace, so the
  // switcher and the navbar tabs match the page. Only when the org changes, not on every switch.
  const isMine = orgs.some((o) => o.name === name)
  useEffect(() => {
    if (isMine && !(scope.kind === "org" && scope.name === name)) setScope({ kind: "org", name })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name, isMine])
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["org", name], queryFn: () => endpoints.org(name) })
  const invalidate = () => qc.invalidateQueries({ queryKey: ["org", name] })
  const [draft, setDraft] = useState<{ name: string; description: string; role: TeamRole; base_permission: Level | null; isNew: boolean } | null>(null)
  const [secret, setSecret] = useState<{ username: string; token: string } | null>(null)
  const [robotTeams, setRobotTeams] = useState<string[]>([])
  const saveTeam = useMutation({
    meta: { success: "Team saved" },
    mutationFn: async () => {
      if (!draft) return
      const t = { description: draft.description, role: draft.role, base_permission: draft.role === "admin" ? null : draft.base_permission }
      if (draft.isNew) await endpoints.createTeam(name, { name: draft.name, ...t })
      else await endpoints.updateTeam(name, draft.name, t)
    },
    onSuccess: () => { setDraft(null); invalidate() },
  })
  const deleteTeam = useMutation({ meta: { success: "Team deleted" }, mutationFn: (t: string) => endpoints.deleteTeam(name, t), onSuccess: invalidate })
  const addMember = useMutation({ meta: { success: "Member added" }, mutationFn: (v: { team: string; username: string }) => endpoints.addMember(name, v.team, v.username), onSuccess: invalidate })
  const removeMember = useMutation({ meta: { success: "Member removed" }, mutationFn: (v: { team: string; username: string }) => endpoints.removeMember(name, v.team, v.username), onSuccess: invalidate })
  const [robotExpiry, setRobotExpiry] = useState<number | undefined>(undefined)
  const toggleRobot = useMutation({
    meta: { error: "Couldn't change the robot account" },
    mutationFn: (r: { id: number; is_disabled: boolean }) => endpoints.updateOrgRobot(name, r.id, { is_disabled: !r.is_disabled }),
    onSuccess: (r) => { invalidate(); toast.success(r.is_disabled ? `${r.username} disabled` : `${r.username} enabled`) },
  })
  const createRobot = useMutation({ mutationFn: (v: { name: string; description: string }) => endpoints.createOrgRobot(name, v.name, robotTeams, v.description || undefined, robotExpiry), onSuccess: (r) => { setSecret(r); setRobotTeams([]); setShowRobotForm(false); robotForm.reset(); invalidate() } })
  const deleteRobot = useMutation({ meta: { success: "Robot account deleted" }, mutationFn: (id: number) => endpoints.deleteOrgRobot(name, id), onSuccess: invalidate })
  const rotateRobot = useMutation({ mutationFn: (id: number) => endpoints.rotateOrgRobot(name, id), onSuccess: (r) => { setSecret(r); invalidate() } })
  const [keyless, setKeyless] = useState<{ id: number; name: string } | null>(null)
  const robotForm = useForm({ defaultValues: { name: "", description: "" }, onSubmit: async ({ value, formApi }) => { await createRobot.mutateAsync(value); formApi.reset() } })
  const [showRobotForm, setShowRobotForm] = useState(false)
  const repos = useQuery({ queryKey: ["repositories"], queryFn: endpoints.repositories })
  if (q.isLoading) return <Loading />
  if (q.error) return <ErrorBox error={q.error} />
  const o = q.data!
  const err = deleteTeam.error ?? addMember.error ?? removeMember.error ?? deleteRobot.error ?? rotateRobot.error
  const summary = new Map((repos.data ?? []).map((r) => [r.name, r]))
  const count = (n: number) => <TabCount>{n}</TabCount>
  return (
    <>
      <BackLink to="/orgs" label="Organizations" />
      <EntityHeader
        mark={<OrgMark name={o.name} label={o.display_name || o.name} className={ENTITY_MARK} />}
        title={o.display_name || o.name}
        aside={o.display_name && o.display_name !== o.name ? `${o.name}/` : undefined}
        description={o.description}
        onAddDescription={o.is_admin ? () => navigate(`/orgs/${o.name}/settings`) : undefined}
      />
      {err && <ErrorBox error={err} />}
      {keyless && <RobotFederationDialog robotId={keyless.id} robot={keyless.name} onClose={() => setKeyless(null)} />}
      <Tabs value={tab} onValueChange={(v) => navigate(`/orgs/${o.name}/${v}`)} className="gap-6">
        <TabsList className={cn(scope.kind === "org" && scope.name === o.name && "hidden")}>
          <TabsTrigger value="repositories"><BoxIcon className="size-4" />Repositories{count(o.repositories.length)}</TabsTrigger>
          <TabsTrigger value="teams"><UsersIcon className="size-4" />Teams{count(o.teams.length)}</TabsTrigger>
          {o.is_admin && <TabsTrigger value="robots"><BotIcon className="size-4" />Robot accounts{count(o.robots.length)}</TabsTrigger>}
          {o.is_admin && <TabsTrigger value="settings"><SettingsIcon className="size-4" />Settings</TabsTrigger>}
        </TabsList>

        <TabsContent value="repositories" className="space-y-4">
          <p className="text-sm text-muted-foreground">Push with <Mono className="text-foreground">docker push {location.host}/{o.name}/&lt;name&gt;:&lt;tag&gt;</Mono></p>
          <Table>
            <TableHeader><TableRow><TableHead className="pl-0">Name</TableHead><TableHead className="w-28">Stars</TableHead><TableHead className="w-28">Tags</TableHead><TableHead className="hidden w-48 md:table-cell">Updated</TableHead></TableRow></TableHeader>
            <TableBody>
              {o.repositories.length === 0 && <TableRow className="hover:bg-transparent"><TableCell colSpan={4}><Empty>No repositories yet.</Empty></TableCell></TableRow>}
              {o.repositories.map((r) => {
                const s = summary.get(r)
                return (
                  <TableRow key={r}>
                    <TableCell className="py-4 pl-0">
                      <Link to={`/r/${r}`} className="group flex items-center gap-4">
                        <span className="flex size-10 shrink-0 items-center justify-center text-muted-foreground"><BoxIcon className="size-6" strokeWidth={1.5} /></span>
                        <span className="min-w-0">
                          <span className="block text-[15px] font-medium group-hover:underline">{r.slice(o.name.length + 1)}</span>
                          <span className="block truncate text-sm text-muted-foreground">{s?.description || r}</span>
                        </span>
                      </Link>
                    </TableCell>
                    <TableCell>{s ? <StarToggle name={r} state={s} /> : "—"}</TableCell>
                    <TableCell>{s ? <span className="chip min-w-7 justify-center tabular-nums text-foreground">{s.tags}</span> : "—"}</TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">{s?.updated_at ? relativeTime(s.updated_at) : "—"}</TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </TabsContent>

        <TabsContent value="teams" className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-muted-foreground">Teams grant members access to repositories under <Mono className="text-foreground">{o.name}/</Mono>.</p>
            {o.is_admin && <Button variant="outline" onClick={() => setDraft({ name: "", description: "", role: "member", base_permission: null, isNew: true })}><PlusIcon />New team</Button>}
          </div>
          {o.teams.map((t) => <TeamCard key={t.id} org={o.name} team={t} admin={o.is_admin} onEdit={() => setDraft({ name: t.name, description: t.description, role: t.role, base_permission: t.base_permission, isNew: false })} onDelete={() => { if (confirm(`Delete team ${t.name}?`)) deleteTeam.mutate(t.name) }} onAdd={(u) => addMember.mutate({ team: t.name, username: u })} onRemove={(u) => removeMember.mutate({ team: t.name, username: u })} />)}
        </TabsContent>

        {o.is_admin && (
          <TabsContent value="robots" className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-sm text-muted-foreground">Credentials for CI and automation, named <Mono className="text-foreground">{o.name}+name</Mono>.</p>
              <Button variant="outline" onClick={() => setShowRobotForm(true)}><PlusIcon />New robot</Button>
            </div>
            {secret && <Secret label={`Credential for ${secret.username}`} value={secret.token} />}
            <Table>
              <TableHeader><TableRow><TableHead className="pl-0">Robot</TableHead><TableHead>Teams</TableHead><TableHead>Repository access</TableHead><TableHead /></TableRow></TableHeader>
              <TableBody>
                {o.robots.length === 0 && <TableRow className="hover:bg-transparent"><TableCell colSpan={4}><Empty>No robot accounts yet.</Empty></TableCell></TableRow>}
                {o.robots.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="py-3 pl-0"><div className="flex items-center gap-3"><BotIcon className="size-4 text-muted-foreground" /><div><div className="flex items-center gap-2"><Mono className={r.is_disabled ? "text-muted-foreground" : undefined}>{r.username}</Mono><RobotStatus robot={r} /></div>{r.display_name && <div className="text-xs text-muted-foreground">{r.display_name}</div>}</div></div></TableCell>
                    <TableCell className="text-muted-foreground">{o.teams.filter((t) => t.members.some((m) => m.id === r.id)).map((t) => t.name).join(", ") || "None"}</TableCell>
                    <TableCell className="whitespace-normal"><RepoAccessList org={o.name} grants={r.repositories} /></TableCell>
                    <TableCell className="whitespace-nowrap pr-0 text-right"><Button variant="ghost" size="sm" onClick={() => setKeyless({ id: r.id, name: r.username })}>Keyless</Button><Button variant="ghost" size="sm" onClick={() => rotateRobot.mutate(r.id)}>Rotate</Button><Button variant="ghost" size="sm" disabled={toggleRobot.isPending} onClick={() => toggleRobot.mutate(r)}>{r.is_disabled ? "Enable" : "Disable"}</Button><Button variant="ghost" size="sm" className="text-destructive hover:text-destructive" onClick={() => { if (confirm(`Delete ${r.username}?`)) deleteRobot.mutate(r.id) }}>Delete</Button></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TabsContent>
        )}

        {o.is_admin && <TabsContent value="settings"><OrgSettings name={o.name} displayName={o.display_name ?? ""} description={o.description} timeMachine={o.time_machine_secs} defaultTimeMachine={o.default_time_machine_secs} /></TabsContent>}
      </Tabs>

      <Dialog open={!!draft} onOpenChange={(v) => { if (!v) { setDraft(null); saveTeam.reset() } }}>
        <DialogContent className="sm:max-w-2xl">
          {draft && (
            <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); saveTeam.mutate() }}>
              <DialogHeader>
                <DialogTitle>{draft.isNew ? "New team" : `Edit ${draft.name}`}</DialogTitle>
                <DialogDescription>Teams group people and robots. Their role sets what they can do in the organization; repository access comes from the base permission and per-repository grants.</DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2"><Label htmlFor="tname">Name</Label><Input id="tname" autoFocus={draft.isNew} value={draft.name} disabled={!draft.isNew} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="developers" /></div>
                <div className="space-y-2"><Label htmlFor="tdesc">Description</Label><Input id="tdesc" value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} placeholder="Backend engineers" /></div>
              </div>
              <div className="space-y-2">
                <Label>Role</Label>
                <div className="grid gap-2 sm:grid-cols-3">
                  {(Object.keys(TEAM_ROLES) as TeamRole[]).map((role) => (
                    <button key={role} type="button" onClick={() => setDraft({ ...draft, role })} aria-pressed={draft.role === role}
                      className={cn("rounded-lg border p-3 text-left transition-colors", draft.role === role ? "border-foreground/40 bg-foreground/5" : "hover:border-ring")}>
                      <span className="flex items-center gap-2 text-sm font-medium"><span className={cn("size-3.5 rounded-full border", draft.role === role && "border-4 border-foreground")} />{TEAM_ROLES[role].label}</span>
                      <span className="mt-1 block text-xs text-muted-foreground">{TEAM_ROLES[role].description}</span>
                    </button>
                  ))}
                </div>
              </div>
              {draft.role !== "admin" && (
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3">
                  <div className="min-w-0">
                    <p className="text-sm font-medium">Base permission</p>
                    <p className="text-xs text-muted-foreground">Access to every repository in <Mono className="text-foreground">{o.name}/</Mono>. Grant more on individual repositories from their Permissions tab.</p>
                  </div>
                  <LevelSelect value={draft.base_permission} onChange={(base_permission) => setDraft({ ...draft, base_permission })} allowNone noneLabel="None" />
                </div>
              )}
              {saveTeam.error && <ErrorBox error={saveTeam.error} />}
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setDraft(null)}>Cancel</Button>
                <Button type="submit" disabled={saveTeam.isPending || !draft.name.trim()}>{saveTeam.isPending ? "Saving..." : draft.isNew ? "Create team" : "Save changes"}</Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={showRobotForm} onOpenChange={(v) => { setShowRobotForm(v); if (!v) { robotForm.reset(); setRobotTeams([]); createRobot.reset() } }}>
        <DialogContent className="sm:max-w-lg">
          <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); robotForm.handleSubmit().catch(() => {}) }}>
            <DialogHeader>
              <DialogTitle>New robot account</DialogTitle>
              <DialogDescription>You'll get a credential to use as the password for <Mono className="text-foreground">docker login</Mono>, shown once. Robots have no access until you add them to a team or grant them access on a repository.</DialogDescription>
            </DialogHeader>
            <robotForm.Field name="name" validators={{ onChange: ({ value }) => (/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(value) ? undefined : "letters, digits, . _ -") }} children={(f) => (
              <div className="space-y-2"><Label htmlFor="rname">Name</Label>
                <div className="relative"><span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 font-mono text-sm text-muted-foreground">{o.name}+</span><Input id="rname" autoFocus className="font-mono" style={{ paddingLeft: `calc(${o.name.length + 1}ch + 0.75rem + 1px)` }} placeholder="ci" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} /></div>
              </div>
            )} />
            <robotForm.Field name="description" children={(f) => (<div className="space-y-2"><Label htmlFor="rdesc">Description</Label><Input id="rdesc" placeholder="GitHub Actions deploy" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} /></div>)} />
            <div className="space-y-2"><Label>Credential</Label><ExpirySelect value={robotExpiry} onChange={setRobotExpiry} /></div>
            <div className="space-y-2">
              <Label>Teams</Label>
              <p className="text-xs text-muted-foreground">The robot gets the access of every team it joins.</p>
              <div className="flex flex-wrap gap-1.5">
                {o.teams.map((t) => {
                  const on = robotTeams.includes(t.name)
                  return <button key={t.id} type="button" aria-pressed={on} onClick={() => setRobotTeams(on ? robotTeams.filter((x) => x !== t.name) : [...robotTeams, t.name])}
                    className={`inline-flex h-7 items-center rounded-full border px-2.5 text-xs font-medium transition-colors ${on ? "border-foreground/30 bg-foreground/10 text-foreground" : "text-muted-foreground hover:border-ring/70 hover:text-foreground"}`}>{t.name}</button>
                })}
              </div>
            </div>
            {createRobot.error && <ErrorBox error={createRobot.error} />}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowRobotForm(false)}>Cancel</Button>
              <robotForm.Subscribe selector={(st) => [st.canSubmit, st.isSubmitting] as const} children={([ok, busy]) => <Button type="submit" disabled={!ok || busy}>{busy ? "Creating..." : "Create robot"}</Button>} />
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  )
}

const TIME_MACHINE: [string, string][] = [["default", "Instance default"], ...[0, 1, 7, 14, 30, 90].map((d) => [String(d * 86400), formatWindow(d * 86400)] as [string, string])]

/** How long deleted or moved tags in the organization can be restored. */
function TimeMachineSection({ name, value, instance }: { name: string; value: number | null; instance: number }) {
  const qc = useQueryClient()
  const save = useMutation({
    meta: { success: "Saved" },
    mutationFn: (v: string) => endpoints.updateOrg(name, { time_machine_secs: v === "default" ? null : Number(v) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["org", name] }),
  })
  const current = value === null ? "default" : String(value)
  const options = TIME_MACHINE.map(([k, l]) => [k, k === "default" ? `${l} (${formatWindow(instance)})` : l] as [string, string])
  if (value !== null && !TIME_MACHINE.some(([k]) => k === current)) options.push([current, formatWindow(value)])
  return (
    <FormSection title="Time Machine" description="How long a deleted or moved tag can be restored from a repository's History. Garbage collection keeps those images until then.">
      <div className="space-y-2">
        <LabeledSelect label="Keep" value={current} onChange={(v) => save.mutate(v)} options={options} className="w-full sm:w-72" />
        {save.error && <ErrorBox error={save.error} />}
      </div>
    </FormSection>
  )
}

function OrgSettings({ name, displayName, description, timeMachine, defaultTimeMachine }: { name: string; displayName: string; description: string; timeMachine: number | null; defaultTimeMachine: number }) {
  const qc = useQueryClient()
  const { me } = useSession()
  // Deleting an organization is an instance-level action, not an org-admin one.
  const canDelete = !!me?.globals.includes("users:write") || !!me?.globals.includes("system")
  const navigate = useNavigate()
  const { scope, setScope } = useScope()
  const [draft, setDraft] = useState({ display_name: displayName, description })
  const dirty = draft.display_name !== displayName || draft.description !== description
  const save = useMutation({
    meta: { success: "Organization saved" },
    mutationFn: () => endpoints.updateOrg(name, draft),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["org", name] }); qc.invalidateQueries({ queryKey: ["orgs"] }) },
  })
  const del = useMutation({
    meta: { success: "Organization deleted" },
    mutationFn: () => endpoints.deleteOrg(name),
    onSuccess: () => { setScope({ kind: "personal" }); qc.invalidateQueries({ queryKey: ["orgs"] }); navigate("/orgs") },
  })
  const { section } = useParams()
  const base = `/orgs/${name}/settings`
  const canSetQuota = !!me?.globals.includes("users:write") || !!me?.globals.includes("system")
  // Plain `/settings` links land on the first section, so the side nav shows where you are.
  if (!section) return <Navigate to={`${base}/general`} replace />
  return (
    <div className="grid items-start gap-8 lg:grid-cols-[13rem_minmax(0,1fr)]">
      <SideNav className="lg:sticky lg:top-30" items={[
        { label: "General", to: `${base}/general`, icon: <SettingsIcon /> },
        { label: "Sign-in", to: `${base}/sign-in`, icon: <KeyRoundIcon /> },
        { label: "Storage", to: `${base}/storage`, icon: <HardDriveIcon /> },
        { label: "Pull policy", to: `${base}/policy`, icon: <ShieldAlertIcon /> },
        { label: "Webhooks", to: `${base}/webhooks`, icon: <WebhookIcon /> },
        ...(me?.builds ? [{ label: "Runners", to: `${base}/runners`, icon: <ServerIcon /> }] : []),
      ]} />
      <div className="flex min-w-0 flex-col gap-8">
        <StackedSections>
        {section === "sign-in" ? <OrgSsoSection org={name} />
        : section === "storage" ? <>
            <TimeMachineSection name={name} value={timeMachine} instance={defaultTimeMachine} />
            <NamespaceStorageSections namespace={name} canManage canSetQuota={canSetQuota} />
          </>
        : section === "policy" ? <>
            <FormSection title="Pull policy" description="Keep vulnerable, unscanned or unsigned images in this organization from being pulled.">
              <SecurityPolicyForm namespace={name} />
            </FormSection>
            <FormSection title="CVE allowlist" description="Vulnerabilities your team assessed as acceptable. They don't count towards blocking.">
              <CveAllowlist namespace={name} />
            </FormSection>
          </>
        : section === "webhooks" ? <WebhooksPanel namespace={name} />
        : section === "runners" ? <RunnersSection namespace={name} />
        : <>
            <FormSection title="General" description="How the organization appears to members and on Explore.">
              <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); if (dirty) save.mutate() }}>
                <div className="space-y-2"><Label htmlFor="odisplay">Display name</Label><Input id="odisplay" maxLength={100} placeholder={name} value={draft.display_name} onChange={(e) => setDraft({ ...draft, display_name: e.target.value })} /></div>
                <div className="space-y-2"><Label htmlFor="odesc">Description</Label><Textarea id="odesc" rows={3} maxLength={500} value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} /></div>
                {save.error && <ErrorBox error={save.error} />}
                <div className="flex items-center gap-2">
                  <Button type="submit" disabled={!dirty || save.isPending}>{save.isPending ? "Saving..." : "Save"}</Button>
                  <Button type="button" variant="outline" disabled={!dirty} onClick={() => setDraft({ display_name: displayName, description })}>Cancel</Button>
                </div>
              </form>
            </FormSection>
            <FormSection title="Namespace" description="The name in every image address. Renaming moves all of the organization's repositories.">
              <RenameNamespace current={name} what="organization"
                onRename={(next) => endpoints.updateOrg(name, { name: next })}
                onDone={(next) => {
                  if (scope.kind === "org" && scope.name === name) setScope({ kind: "org", name: next })
                  qc.invalidateQueries({ queryKey: ["orgs"] }); qc.invalidateQueries({ queryKey: ["repositories"] })
                  navigate(`/orgs/${next}/settings/general`, { replace: true })
                }} />
            </FormSection>
            {canDelete && (
              <FormSection title="Danger zone" description="Irreversible actions.">
                <DangerRow title="Delete this organization" description={<>Removes its teams, memberships and robot accounts. Repositories under <Mono>{name}/</Mono> are kept.</>}
                  action={<Button variant="destructive" disabled={del.isPending} onClick={() => { if (confirm(`Delete organization ${name}?`)) del.mutate() }}>Delete organization</Button>} />
                {del.error && <div className="mt-3"><ErrorBox error={del.error} /></div>}
              </FormSection>
            )}
          </>}
        </StackedSections>
      </div>
    </div>
  )
}

/** Explicit repository grants, as small links to each repository's Permissions tab. */
export function RepoAccessList({ org, grants }: { org?: string; grants: { repository: string; level: Level }[] }) {
  if (grants.length === 0) return <span className="text-sm text-muted-foreground">None</span>
  return (
    <span className="flex flex-wrap gap-1.5">
      {grants.map((g) => (
        <Link key={g.repository} to={`/r/${g.repository}?tab=permissions`} className="flex items-center gap-1 rounded-md border px-1.5 py-0.5 hover:border-ring">
          <span className="font-mono text-xs">{org ? g.repository.slice(org.length + 1) : g.repository}</span><LevelBadge level={g.level} className="px-1 py-0 leading-4" />
        </Link>
      ))}
    </span>
  )
}

function TeamCard({ org, team, admin, onEdit, onDelete, onAdd, onRemove }: { org: string; team: Team; admin: boolean; onEdit: () => void; onDelete: () => void; onAdd: (u: string) => void; onRemove: (u: string) => void }) {
  const [user, setUser] = useState("")
  const [syncing, setSyncing] = useState(false)
  const synced = !!team.sync
  return (
    <Panel>
      <div className="space-y-3 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{team.name}</span>
          <span className="chip" title={TEAM_ROLES[team.role].description}>{TEAM_ROLES[team.role].label}</span>
          {synced && <span className="chip" title="Members come from this group"><RefreshCwIcon className="size-3" />{syncLabel(team)}</span>}
          {team.description && <span className="text-sm text-muted-foreground">{team.description}</span>}
          <span className="flex-1" />
          {admin && <><Button variant="ghost" size="sm" onClick={() => setSyncing(true)}>{synced ? "Sync settings" : "Sync with group"}</Button><Button variant="ghost" size="sm" onClick={onEdit}>Edit</Button><Button variant="ghost" size="sm" className="text-destructive hover:text-destructive" onClick={onDelete}>Delete</Button></>}
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-sm text-muted-foreground">
          {team.role === "admin"
            ? <span>Admin on every repository in <Mono className="text-foreground">{org}/</Mono></span>
            : <>
                {team.base_permission ? <span className="flex items-center gap-1.5"><LevelBadge level={team.base_permission} /> on every repository</span> : team.repositories.length === 0 && <span>No repository access yet. Grant it from a repository's Permissions tab.</span>}
                {team.repositories.map((g) => (
                  <Link key={g.repository} to={`/r/${g.repository}?tab=permissions`} className="flex items-center gap-1 rounded-md border px-1.5 py-0.5 hover:border-ring">
                    <span className="font-mono text-xs text-foreground">{g.repository.slice(org.length + 1)}</span><LevelBadge level={g.level} className="px-1 py-0 leading-4" />
                  </Link>
                ))}
              </>}
          {team.role === "creator" && <span>· can create repositories</span>}
        </div>
        <div className="flex flex-wrap gap-1 items-center">
          {team.members.map((m) => (
            <Badge key={m.id} variant={m.is_robot ? "secondary" : "outline"} className="gap-1">{m.username}{admin && (!synced || m.is_robot) && <button type="button" className="ml-1 opacity-60 hover:opacity-100" title="remove" onClick={() => onRemove(m.username)}>×</button>}</Badge>
          ))}
          {team.members.length === 0 && <span className="text-xs text-muted-foreground">no members</span>}
          {admin && synced && <span className="ml-2 text-xs text-muted-foreground">Members follow the group; robots can still be added.</span>}
          {admin && (
            <form className="ml-2 flex gap-1" onSubmit={(e) => { e.preventDefault(); if (user.trim()) { onAdd(user.trim()); setUser("") } }}>
              <PrincipalPicker kinds={synced ? ["robot"] : ["user", "robot"]} namespace={org} size="sm" className="w-60"
                placeholder={synced ? "Add a robot" : "Add a person or robot"} value={user} onChange={setUser}
                onPick={(u) => { onAdd(u); setUser("") }} exclude={team.members.map((m) => m.username)} />
            </form>
          )}
        </div>
      </div>
      {syncing && <TeamSyncDialog org={org} team={team} onClose={() => setSyncing(false)} />}
    </Panel>
  )
}
