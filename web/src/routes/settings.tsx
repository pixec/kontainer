import { toast } from "sonner"
import { useForm } from "@tanstack/react-form"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState, type ReactNode } from "react"
import { useParams, useSearchParams } from "react-router"
import { BotIcon, FingerprintIcon, HardDriveIcon, KeyRoundIcon, MonitorIcon, ShieldCheckIcon, UserIcon, PlusIcon, SmartphoneIcon, TerminalIcon, WebhookIcon, ShieldAlertIcon, ServerIcon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { endpoints, type Profile } from "@/lib/api"
import { formatDate, relativeTime } from "@/lib/time"
import { useSession } from "@/lib/session"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { Avatar, CopyField, Empty, FormSection, PageHeader, Panel, Secret, SideNav, StackedSections } from "@/components/page"
import { describeRules } from "@/components/token-scope"
import { RepoAccessList } from "@/routes/orgs"
import { RobotFederationDialog } from "@/components/robot-federation"
import { OrgSignInLinks } from "@/components/org-sso"
import { RenameNamespace } from "@/components/rename-namespace"
import { NamespaceStorageSections } from "@/components/storage"
import { WebhooksPanel } from "@/components/webhooks"
import { ExpirySelect, RobotStatus } from "@/components/robots"
import { CveAllowlist, SecurityPolicyForm } from "@/components/security-policy"
import { RunnersSection } from "@/components/runners"
import { PasskeysSection } from "@/components/passkeys"

const SECTION_TITLES: Record<string, string> = { runners: "Runners", profile: "Profile", tokens: "Access tokens", robots: "Robot accounts", security: "Security", sessions: "Sessions", storage: "Storage", webhooks: "Webhooks", policy: "Pull policy" }

export function SettingsPage() {
  const { me } = useSession()
  const { section = "profile" } = useParams()
  if (!me?.username) return null
  return (
    <div className="grid items-start gap-8 lg:grid-cols-[13rem_minmax(0,1fr)]">
      <SideNav className="lg:sticky lg:top-30" items={[
        { label: "Profile", to: "/settings/profile", icon: <UserIcon /> },
        { label: "Access tokens", to: "/settings/tokens", icon: <KeyRoundIcon /> },
        { label: "Robot accounts", to: "/settings/robots", icon: <BotIcon /> },
        { label: "Security", to: "/settings/security", icon: <ShieldCheckIcon /> },
        { label: "Sessions", to: "/settings/sessions", icon: <MonitorIcon /> },
        { label: "Storage", to: "/settings/storage", icon: <HardDriveIcon /> },
        { label: "Webhooks", to: "/settings/webhooks", icon: <WebhookIcon /> },
        { label: "Pull policy", to: "/settings/policy", icon: <ShieldAlertIcon /> },
        ...(me.builds ? [{ label: "Runners", to: "/settings/runners", icon: <ServerIcon /> }] : []),
      ]} />
      <div className="flex min-w-0 flex-col gap-8">
        <StackedSections>
        {section === "runners" ? <RunnerSettings /> : section === "storage" ? <StorageSettings /> : section === "webhooks" ? <WebhookSettings /> : section === "policy" ? <PolicySettings /> : section === "profile" ? <ProfileSettings /> : section === "robots" ? <Robots /> : section === "security" ? <Security /> : section === "sessions" ? <Sessions /> : <Tokens />}
        </StackedSections>
      </div>
    </div>
  )
}

/** Page header for a settings section; actions sit top-right like every other page. */
function StorageSettings() {
  const { me } = useSession()
  const admin = !!me?.globals.includes("users:write") || !!me?.globals.includes("system")
  return (
    <>
      <SettingsHeader description={<>Space used by your personal repositories under <Mono className="text-foreground">{me?.username}/</Mono>, and rules for cleaning up old tags.</>} />
      <div><NamespaceStorageSections namespace={me!.username!} canManage canSetQuota={admin} /></div>
    </>
  )
}

function RunnerSettings() {
  const { me } = useSession()
  return (
    <>
      <SettingsHeader description={<>What builds your personal repositories under <Mono className="text-foreground">{me?.username}/</Mono> from Git.</>} />
      <div><RunnersSection namespace={me!.username!} /></div>
    </>
  )
}

function PolicySettings() {
  const { me } = useSession()
  return (
    <>
      <SettingsHeader description={<>What your personal repositories under <Mono className="text-foreground">{me?.username}/</Mono> refuse to serve.</>} />
      <div>
        <FormSection title="Pull policy" description="Keep vulnerable, unscanned or unsigned images from being pulled."><SecurityPolicyForm namespace={me!.username!} /></FormSection>
        <FormSection title="CVE allowlist" description="Vulnerabilities you've assessed as acceptable. They don't count towards blocking."><CveAllowlist namespace={me!.username!} /></FormSection>
      </div>
    </>
  )
}

function WebhookSettings() {
  const { me } = useSession()
  return (
    <>
      <SettingsHeader description={<>Notify other services about your personal repositories under <Mono className="text-foreground">{me?.username}/</Mono>.</>} />
      <WebhooksPanel namespace={me!.username!} />
    </>
  )
}

function SettingsHeader({ description, actions }: { description: ReactNode; actions?: ReactNode }) {
  const { section = "profile" } = useParams()
  return <PageHeader title={SECTION_TITLES[section] ?? "Settings"} description={description} actions={actions} />
}

const PROFILE_FIELDS = [
  { key: "display_name", label: "Full name", placeholder: "Jane Doe", max: 100 },
  { key: "company", label: "Company", placeholder: "Acme Inc.", max: 100 },
  { key: "location", label: "Location", placeholder: "Kuala Lumpur, Malaysia", max: 100 },
  { key: "website", label: "Website", placeholder: "https://example.com", max: 255, type: "url" },
] as const

type ProfileForm = Record<keyof Profile, string>
const toForm = (p?: Profile): ProfileForm => ({
  display_name: p?.display_name ?? "", company: p?.company ?? "", location: p?.location ?? "", website: p?.website ?? "", gravatar_email: p?.gravatar_email ?? "",
})

function ProfileSettings() {
  const qc = useQueryClient()
  const { me, refresh } = useSession()
  const q = useQuery({ queryKey: ["profile"], queryFn: endpoints.profile })
  const saved = toForm(q.data)
  const [draft, setDraft] = useState<ProfileForm | null>(null)
  const form = draft ?? saved
  const dirty = draft !== null && (Object.keys(saved) as (keyof Profile)[]).some((k) => draft[k] !== saved[k])
  const save = useMutation({
    meta: { success: "Profile saved" },
    mutationFn: () => endpoints.updateProfile(Object.fromEntries(Object.entries(form).map(([k, v]) => [k, v.trim() || null])) as unknown as Profile),
    onSuccess: (p) => { qc.setQueryData(["profile"], p); setDraft(null); refresh() },
  })
  const set = (k: keyof Profile, v: string) => setDraft({ ...form, [k]: v })
  if (q.isLoading) return <Loading rows={5} />
  if (q.error) return <ErrorBox error={q.error} />
  return (
    <>
    <SettingsHeader description="How you appear across the registry." />
    {!me?.is_managed && (
      <FormSection title="Username" description="Your personal namespace. Renaming moves your repositories and robots.">
        <RenameNamespace current={me!.username!} what="account"
          onRename={(next) => endpoints.changeUsername(next)}
          onDone={() => { refresh(); qc.invalidateQueries({ queryKey: ["repositories"] }); qc.invalidateQueries({ queryKey: ["robots"] }) }} />
      </FormSection>
    )}
    <FormSection title="Personal details" description="Details about you. Your Gravatar is used as your avatar.">
      <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); if (dirty) save.mutate() }}>
        {PROFILE_FIELDS.map((f) => (
          <div key={f.key} className="space-y-2">
            <Label htmlFor={f.key}>{f.label}</Label>
            <Input id={f.key} type={"type" in f ? f.type : "text"} maxLength={f.max} placeholder={f.placeholder} value={form[f.key]} onChange={(e) => set(f.key, e.target.value)} />
          </div>
        ))}
        <div className="space-y-2">
          <Label htmlFor="gravatar_email">Gravatar email</Label>
          <div className="flex items-center gap-3">
            <Avatar name={me?.username ?? "?"} src={me?.avatar_url} className="size-10" />
            <Input id="gravatar_email" type="email" maxLength={255} placeholder="you@example.com" value={form.gravatar_email} onChange={(e) => set("gravatar_email", e.target.value)} />
          </div>
          <p className="text-xs text-muted-foreground">Only used to display your avatar. Manage it at <a href="https://gravatar.com" target="_blank" rel="noopener noreferrer" className="text-foreground underline">gravatar.com</a>.</p>
        </div>
        {save.error && <ErrorBox error={save.error} />}
        <div className="flex items-center gap-2 pt-1">
          <Button type="submit" disabled={!dirty || save.isPending}>{save.isPending ? "Saving..." : "Save"}</Button>
          <Button type="button" variant="outline" disabled={!dirty || save.isPending} onClick={() => { setDraft(null); save.reset() }}>Cancel</Button>
        </div>
      </form>
    </FormSection>
    </>
  )
}

function Tokens() {
  const qc = useQueryClient()
  const { me } = useSession()
  const q = useQuery({ queryKey: ["tokens"], queryFn: endpoints.tokens })
  const [open, setOpen] = useState(false)
  const [created, setCreated] = useState<string | null>(null)
  const create = useMutation({
    mutationFn: (v: { name: string; expires: string }) => endpoints.createToken(v.name, v.expires ? Number(v.expires) : undefined),
    onSuccess: (r) => { setCreated(r.token); setOpen(false); qc.invalidateQueries({ queryKey: ["tokens"] }) },
  })
  const del = useMutation({ meta: { success: "Token deleted", error: "Couldn't delete the token" }, mutationFn: endpoints.deleteToken, onSuccess: () => qc.invalidateQueries({ queryKey: ["tokens"] }) })
  const form = useForm({ defaultValues: { name: "", expires: "90" }, onSubmit: async ({ value, formApi }) => { await create.mutateAsync(value); formApi.reset() } })
  return (
    <>
    <SettingsHeader
      description={me?.is_mfa_enabled ? "Your account uses two-factor authentication, so tokens are the only way to sign in from the command line." : "Use a token as the password for docker login, CI and other tools. Tokens act as you."}
      actions={<Button size="lg" onClick={() => setOpen(true)}><PlusIcon />New token</Button>}
    />
    <div className="space-y-4">
      {created && <Secret label="New access token" value={created} hint={`docker login ${location.host} -u ${me?.username} -p <token> · it will not be shown again`} />}
      <div>
        {q.isLoading && <Loading rows={2} />}
        {q.data && q.data.length === 0 && <div className="rounded-lg border border-dashed"><Empty>No tokens yet.</Empty></div>}
        {q.data && q.data.length > 0 && (
          <Table>
            <TableHeader><TableRow><TableHead className="pl-0">Name</TableHead><TableHead>Token</TableHead><TableHead className="hidden md:table-cell">Scope</TableHead><TableHead className="hidden md:table-cell">Last used</TableHead><TableHead>Expires</TableHead><TableHead /></TableRow></TableHeader>
            <TableBody>
              {q.data.map((t) => (
                <TableRow key={t.id}>
                  <TableCell className="py-3.5 pl-0 font-medium"><span className="inline-flex items-center gap-2"><KeyRoundIcon className="size-3.5 text-muted-foreground" />{t.name}</span></TableCell>
                  <TableCell><Mono className="text-muted-foreground">{t.hint}...</Mono></TableCell>
                  <TableCell className="hidden md:table-cell text-xs text-muted-foreground">{t.scopes ? <span title="Created before scopes were removed; still limited to this">{describeRules(t.scopes)}</span> : "Acts as you"}</TableCell>
                  <TableCell className="hidden md:table-cell text-xs text-muted-foreground">{formatDate(t.last_used_at) || "never"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatDate(t.expires_at) || "never"}</TableCell>
                  <TableCell className="pr-0 text-right"><Button variant="ghost" size="sm" className="text-muted-foreground hover:text-destructive" onClick={() => del.mutate(t.id)}>Revoke</Button></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-2xl">
          <form onSubmit={(e) => { e.preventDefault(); form.handleSubmit() }} className="space-y-5">
            <DialogHeader><DialogTitle>New access token</DialogTitle><DialogDescription>Tokens act as your account, limited to what you choose here.</DialogDescription></DialogHeader>
            <div className="grid grid-cols-[1fr_140px] gap-3">
              <form.Field name="name" validators={{ onChange: ({ value }) => (value.trim() ? undefined : "required") }} children={(f) => (
                <div className="space-y-1.5"><Label htmlFor="tname">Name</Label><Input id="tname" placeholder="laptop, github-actions..." autoFocus value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} /></div>
              )} />
              <form.Field name="expires" children={(f) => (
                <div className="space-y-1.5"><Label htmlFor="texp">Expires in (days)</Label><Input id="texp" type="number" min={0} placeholder="never" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} /></div>
              )} />
            </div>
            <p className="text-sm text-muted-foreground">The token can do everything you can. For narrower access, create a robot account and grant it specific repositories.</p>
            {create.error && <ErrorBox error={create.error} />}
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
              <form.Subscribe selector={(s) => [s.canSubmit, s.isSubmitting] as const} children={([ok, busy]) => <Button type="submit" disabled={!ok || busy}>Create token</Button>} />
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
    </>
  )
}

function Robots() {
  const qc = useQueryClient()
  const { me } = useSession()
  const q = useQuery({ queryKey: ["robots"], queryFn: endpoints.robots })
  const [open, setOpen] = useState(false)
  const [created, setCreated] = useState<{ username: string; token: string } | null>(null)
  const [expiry, setExpiry] = useState<number | undefined>(undefined)
  const create = useMutation({
    mutationFn: (v: { name: string; description: string }) => endpoints.createRobot(v.name, v.description || undefined, expiry),
    onSuccess: (r) => { setCreated(r); setOpen(false); qc.invalidateQueries({ queryKey: ["robots"] }) },
  })
  const del = useMutation({ meta: { success: "Robot account deleted", error: "Couldn't delete the robot account" }, mutationFn: endpoints.deleteRobot, onSuccess: () => qc.invalidateQueries({ queryKey: ["robots"] }) })
  const rotate = useMutation({ mutationFn: endpoints.rotateRobot, onSuccess: (r) => { setCreated(r); qc.invalidateQueries({ queryKey: ["robots"] }) } })
  const toggle = useMutation({
    meta: { error: "Couldn't change the robot account" },
    mutationFn: (r: { id: number; is_disabled: boolean }) => endpoints.updateRobot(r.id, { is_disabled: !r.is_disabled }),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ["robots"] }); toast.success(r.is_disabled ? `${r.username} disabled` : `${r.username} enabled`) },
  })
  const [keyless, setKeyless] = useState<{ id: number; name: string } | null>(null)
  const form = useForm({ defaultValues: { name: "", description: "" }, onSubmit: async ({ value, formApi }) => { await create.mutateAsync(value); formApi.reset() } })
  return (
    <>
    <SettingsHeader
      description={<>Machine credentials for CI and deployments, named <Mono className="text-foreground">{me?.username}+name</Mono>. A robot only has the repository access you grant it.</>}
      actions={<Button size="lg" onClick={() => setOpen(true)}><PlusIcon />New robot</Button>}
    />
    <div className="space-y-4">
      {created && <Secret label={`Credential for ${created.username}`} value={created.token} hint={`docker login ${location.host} -u ${created.username} -p <credential> · it will not be shown again`} />}
      {rotate.error && <ErrorBox error={rotate.error} />}
      {keyless && <RobotFederationDialog robotId={keyless.id} robot={keyless.name} onClose={() => setKeyless(null)} />}
      <div>
        {q.isLoading && <Loading rows={2} />}
        {q.data && q.data.length === 0 && <div className="rounded-lg border border-dashed"><Empty>No robot accounts yet.</Empty></div>}
        {q.data && q.data.length > 0 && (
          <Table>
            <TableHeader><TableRow><TableHead className="pl-0">Robot</TableHead><TableHead>Repository access</TableHead><TableHead className="hidden md:table-cell">Last used</TableHead><TableHead /></TableRow></TableHeader>
            <TableBody>
              {q.data.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="py-3.5 pl-0"><span className="inline-flex items-center gap-2 font-medium"><BotIcon className="size-3.5 text-muted-foreground" /><Mono className={r.is_disabled ? "text-muted-foreground" : undefined}>{r.username}</Mono><RobotStatus robot={r} /></span>{r.display_name && <div className="text-xs text-muted-foreground">{r.display_name}</div>}</TableCell>
                  <TableCell className="whitespace-normal"><RepoAccessList grants={r.repositories} /></TableCell>
                  <TableCell className="hidden md:table-cell text-xs text-muted-foreground">{r.last_used_at ? relativeTime(r.last_used_at) : formatDate(r.last_login_at) || "never"}</TableCell>
                  <TableCell className="whitespace-nowrap pr-0 text-right">
                    <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={() => setKeyless({ id: r.id, name: r.username })}>Keyless</Button>
                    <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={() => rotate.mutate(r.id)}>Rotate</Button>
                    <Button variant="ghost" size="sm" className="text-muted-foreground" disabled={toggle.isPending} onClick={() => toggle.mutate(r)}>{r.is_disabled ? "Enable" : "Disable"}</Button>
                    <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-destructive" onClick={() => { if (confirm(`Delete ${r.username}?`)) del.mutate(r.id) }}>Delete</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-2xl">
          <form onSubmit={(e) => { e.preventDefault(); form.handleSubmit() }} className="space-y-5">
            <DialogHeader><DialogTitle>New robot account</DialogTitle><DialogDescription>You'll get a credential to use as the password for <Mono>docker login</Mono>.</DialogDescription></DialogHeader>
            <div className="grid grid-cols-[1fr_1fr] gap-3">
              <form.Field name="name" validators={{ onChange: ({ value }) => (/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(value) ? undefined : "letters, digits, . _ -") }} children={(f) => (
                <div className="space-y-1.5"><Label htmlFor="rname">Name</Label><div className="flex items-center gap-1"><span className="text-sm text-muted-foreground">{me?.username}+</span><Input id="rname" autoFocus placeholder="ci" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} /></div></div>
              )} />
              <form.Field name="description" children={(f) => (<div className="space-y-1.5"><Label htmlFor="rdesc">Description</Label><Input id="rdesc" placeholder="GitHub Actions deploys" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} /></div>)} />
            </div>
            <div className="space-y-1.5 sm:max-w-[50%]"><Label>Credential</Label><ExpirySelect value={expiry} onChange={setExpiry} /></div>
            <p className="text-sm text-muted-foreground">Robots start with no access. Grant one access from a repository's <span className="text-foreground">Permissions</span> tab; personal robots can only be granted repositories under <Mono className="text-foreground">{me?.username}/</Mono>.</p>
            {create.error && <ErrorBox error={create.error} />}
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
              <form.Subscribe selector={(s) => [s.canSubmit, s.isSubmitting] as const} children={([ok, busy]) => <Button type="submit" disabled={!ok || busy}>Create robot</Button>} />
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
    </>
  )
}

function Security() {
  const { me, refresh } = useSession()
  const [enroll, setEnroll] = useState<{ secret: string; otpauth_url: string; qr_svg: string } | null>(null)
  const [recovery, setRecovery] = useState<string[] | null>(null)
  const setup = useMutation({ mutationFn: endpoints.mfaSetup, onSuccess: setEnroll })
  const enable = useMutation({ meta: { success: "Two-factor authentication is on" }, mutationFn: endpoints.mfaEnable, onSuccess: (r) => { setRecovery(r.recovery_codes); setEnroll(null); refresh() } })
  const disable = useMutation({ meta: { success: "Two-factor authentication is off" }, mutationFn: (code: string) => endpoints.mfaDisable(code), onSuccess: () => refresh() })
  const regen = useMutation({ mutationFn: endpoints.mfaRecoveryCodes, onSuccess: (r) => setRecovery(r.recovery_codes) })
  const codeForm = useForm({ defaultValues: { code: "" }, onSubmit: async ({ value }) => { await enable.mutateAsync(value.code) } })
  const disableForm = useForm({ defaultValues: { code: "" }, onSubmit: async ({ value }) => { await disable.mutateAsync(value.code) } })
  const regenForm = useForm({ defaultValues: { code: "" }, onSubmit: async ({ value }) => { await regen.mutateAsync(value.code) } })
  const pw = useMutation({ meta: { success: "Password updated" }, mutationFn: (v: { current: string; next: string }) => endpoints.changePassword(v.current, v.next) })
  const pwForm = useForm({
    defaultValues: { current: "", next: "", confirm: "" },
    onSubmit: async ({ value, formApi }) => { await pw.mutateAsync({ current: value.current, next: value.next }); formApi.reset() },
  })
  const [params, setParams] = useSearchParams()
  const tab = me?.is_managed ? "2fa" : params.get("tab") ?? "password"
  return (
    <>
    <SettingsHeader description={me?.is_managed ? "This account is defined in the configuration file, so its password is managed there." : "Your password, a second factor and passkeys for signing in."} />
    <Tabs value={tab} onValueChange={(v) => setParams({ tab: v }, { replace: true })} className="gap-6">
      <TabsList>
        {!me?.is_managed && <TabsTrigger value="password"><KeyRoundIcon className="size-4" />Password</TabsTrigger>}
        <TabsTrigger value="2fa"><ShieldCheckIcon className="size-4" />Two-factor authentication{me?.is_mfa_enabled && <Badge variant="outline" className="ml-0.5 h-[18px] px-1.5 font-normal text-muted-foreground">On</Badge>}</TabsTrigger>
        <TabsTrigger value="passkeys"><FingerprintIcon className="size-4" />Passkeys</TabsTrigger>
      </TabsList>

      <TabsContent value="passkeys"><PasskeysSection available={!!me?.passkeys} /></TabsContent>

      {!me?.is_managed && (
        <TabsContent value="password">
          <FormSection title="Change password" description="Use at least 8 characters. Changing your password signs out every other session.">
            <form className="max-w-md space-y-5" onSubmit={(e) => { e.preventDefault(); pwForm.handleSubmit() }}>
              <pwForm.Field name="current" children={(f) => (<div className="space-y-2"><Label htmlFor="pwc">Current password</Label><Input id="pwc" type="password" autoComplete="current-password" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} /></div>)} />
              <pwForm.Field name="next" validators={{ onChange: ({ value }) => (value.length >= 8 ? undefined : "At least 8 characters.") }} children={(f) => (<div className="space-y-2"><Label htmlFor="pwn">New password</Label><Input id="pwn" type="password" autoComplete="new-password" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />{f.state.meta.isTouched && f.state.meta.errors[0] ? <p className="text-xs text-destructive">{String(f.state.meta.errors[0])}</p> : <p className="text-xs text-muted-foreground">At least 8 characters.</p>}</div>)} />
              <pwForm.Field name="confirm" validators={{ onChangeListenTo: ["next"], onChange: ({ value, fieldApi }) => (value === fieldApi.form.getFieldValue("next") ? undefined : "Passwords do not match.") }} children={(f) => (<div className="space-y-2"><Label htmlFor="pwr">Confirm new password</Label><Input id="pwr" type="password" autoComplete="new-password" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />{f.state.meta.isTouched && f.state.meta.errors[0] && <p className="text-xs text-destructive">{String(f.state.meta.errors[0])}</p>}</div>)} />
              {pw.error && <ErrorBox error={pw.error} />}
              <div className="flex items-center gap-3">
                <pwForm.Subscribe selector={(st) => [st.canSubmit, st.isSubmitting] as const} children={([ok, busy]) => <Button type="submit" disabled={!ok || busy}>{busy ? "Updating..." : "Update password"}</Button>} />
              </div>
            </form>
          </FormSection>
        </TabsContent>
      )}

      <TabsContent value="2fa" className="space-y-4">
        <Panel
          title="Authenticator app"
          description="Time-based one-time codes from an app like 1Password or Google Authenticator. Once enabled, command-line tools must use access tokens."
          actions={!me?.is_mfa_enabled && !enroll ? <Button size="sm" onClick={() => setup.mutate()} disabled={setup.isPending}>Set up</Button> : <Badge variant="outline" className="font-medium text-muted-foreground">{me?.is_mfa_enabled ? "Enabled" : "Setting up"}</Badge>}
        >
          <div className="space-y-4 p-4">
            {setup.error && <ErrorBox error={setup.error} />}
            {!me?.is_mfa_enabled && !enroll && !recovery && <p className="text-sm text-muted-foreground">Not enabled. Anyone with your password can sign in.</p>}
            {enroll && (
              <div className="grid items-start gap-6 sm:grid-cols-[180px_1fr]">
                <div className="rounded-lg bg-white p-2 [&_svg]:h-auto [&_svg]:w-full" dangerouslySetInnerHTML={{ __html: enroll.qr_svg }} />
                <div className="space-y-4 text-sm">
                  <div className="space-y-2">
                    <p>Scan the code with your authenticator app, or enter this secret:</p>
                    <CopyField value={enroll.secret} />
                  </div>
                  <form className="flex max-w-sm items-end gap-2" onSubmit={(e) => { e.preventDefault(); codeForm.handleSubmit() }}>
                    <codeForm.Field name="code" children={(f) => (<div className="flex-1 space-y-2"><Label htmlFor="mfacode">Code from the app</Label><Input id="mfacode" inputMode="numeric" autoComplete="one-time-code" className="font-mono tracking-widest" placeholder="123456" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} /></div>)} />
                    <Button type="submit" disabled={enable.isPending}>Enable</Button>
                  </form>
                  {enable.error && <ErrorBox error={enable.error} />}
                </div>
              </div>
            )}
            {recovery && (
              <div className="space-y-2 rounded-lg border border-warning/30 bg-warning/10 p-4 text-sm">
                <p className="font-medium">Recovery codes</p>
                <p className="text-xs text-muted-foreground">Each works once if you lose your authenticator. Store them somewhere safe; they will not be shown again.</p>
                <pre className="grid grid-cols-2 gap-x-6 font-mono text-xs sm:grid-cols-4">{recovery.map((c) => <span key={c}>{c}</span>)}</pre>
              </div>
            )}
            {me?.is_mfa_enabled && !recovery && <p className="text-sm text-muted-foreground">You'll be asked for a code from your app each time you sign in.</p>}
          </div>
        </Panel>
        {me?.is_mfa_enabled && (
          <div className="grid gap-4 md:grid-cols-2">
            <Panel title="Recovery codes" description="Replace your codes if you've used or lost them.">
              <form className="flex items-end gap-2 p-4" onSubmit={(e) => { e.preventDefault(); regenForm.handleSubmit() }}>
                <regenForm.Field name="code" children={(f) => <div className="flex-1 space-y-2"><Label htmlFor="regen">Current code</Label><Input id="regen" inputMode="numeric" className="font-mono tracking-widest" placeholder="123456" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} /></div>} />
                <Button type="submit" variant="outline" disabled={regen.isPending}>Regenerate</Button>
              </form>
              {regen.error && <div className="px-4 pb-4"><ErrorBox error={regen.error} /></div>}
            </Panel>
            <Panel title="Turn off" description="Signing in will need only your password." className="border-destructive/40">
              <form className="flex items-end gap-2 p-4" onSubmit={(e) => { e.preventDefault(); disableForm.handleSubmit() }}>
                <disableForm.Field name="code" children={(f) => <div className="flex-1 space-y-2"><Label htmlFor="disable">Current code</Label><Input id="disable" inputMode="numeric" className="font-mono tracking-widest" placeholder="123456" value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} /></div>} />
                <Button type="submit" variant="destructive" disabled={disable.isPending}>Disable</Button>
              </form>
              {disable.error && <div className="px-4 pb-4"><ErrorBox error={disable.error} /></div>}
            </Panel>
          </div>
        )}
      </TabsContent>
    </Tabs>
    <OrgSignInLinks />
    </>
  )
}

/** Turn a user agent into "Firefox on macOS" / "curl 8.7.1", plus an icon kind. */
function describeAgent(ua: string | null): { label: string; kind: "desktop" | "mobile" | "cli" } {
  if (!ua) return { label: "Unknown device", kind: "desktop" }
  const cli = ua.match(/^(curl|Wget|docker|containerd|podman|skopeo|crane|python-requests|Go-http-client)\/([\w.]+)/i)
  if (cli) return { label: `${cli[1]} ${cli[2]}`, kind: "cli" }
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser"
  const os = /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X|Macintosh/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : null
  return { label: os ? `${browser} on ${os}` : browser, kind: /Mobile|iPhone|Android/.test(ua) ? "mobile" : "desktop" }
}

function agentIcon(kind: "desktop" | "mobile" | "cli") {
  return kind === "cli" ? TerminalIcon : kind === "mobile" ? SmartphoneIcon : MonitorIcon
}

function Sessions() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["sessions"], queryFn: endpoints.sessions })
  const del = useMutation({ meta: { success: "Signed out of that session", error: "Couldn't end the session" }, mutationFn: endpoints.deleteSession, onSuccess: () => qc.invalidateQueries({ queryKey: ["sessions"] }) })
  if (q.isLoading) return <Loading />
  if (q.error) return <ErrorBox error={q.error} />
  const sessions = [...(q.data ?? [])].sort((a, b) => Number(b.is_current) - Number(a.is_current))
  const others = sessions.filter((s) => !s.is_current).length
  return (
    <>
      <SettingsHeader
        description="Where you're signed in. Revoke any session you don't recognise."
        actions={others > 0 && <Button size="lg" variant="outline" disabled={del.isPending} onClick={() => { if (confirm(`Sign out ${others} other ${others === 1 ? "session" : "sessions"}?`)) del.mutate("others") }}>Sign out other sessions</Button>}
      />
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="pl-0">Device</TableHead>
            <TableHead className="hidden w-40 md:table-cell">IP address</TableHead>
            <TableHead className="w-40">Signed in</TableHead>
            <TableHead className="hidden w-36 sm:table-cell">Expires</TableHead>
            <TableHead className="w-24 pr-0" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {sessions.map((s) => {
            const agent = describeAgent(s.user_agent)
            const Icon = agentIcon(agent.kind)
            return (
              <TableRow key={s.id}>
                <TableCell className="py-3.5 pl-0">
                  <span className="flex items-center gap-3" title={s.user_agent ?? undefined}>
                    <Icon className="size-4 shrink-0 text-muted-foreground" />
                    <span className="font-medium">{agent.label}</span>
                    {s.is_current && <span className="text-xs text-muted-foreground">Current</span>}
                  </span>
                </TableCell>
                <TableCell className="hidden font-mono text-xs text-muted-foreground md:table-cell">{s.ip ?? "—"}</TableCell>
                <TableCell className="text-muted-foreground" title={formatDate(s.created_at)}>{relativeTime(s.created_at)}</TableCell>
                <TableCell className="hidden text-muted-foreground sm:table-cell" title={formatDate(s.expires_at)}>{relativeTime(s.expires_at)}</TableCell>
                <TableCell className="pr-0 text-right">
                  {!s.is_current && <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-destructive" disabled={del.isPending} onClick={() => del.mutate(s.id)}>Revoke</Button>}
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </>
  )
}
