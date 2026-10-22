import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { RefreshCwIcon } from "lucide-react"
import { CopyField, FormSection, LabeledSelect } from "@/components/page"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { api, endpoints, type Team } from "@/lib/api"

/** Organization settings: the org's own OIDC provider. */
export function OrgSsoSection({ org }: { org: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["org-sso", org], queryFn: () => endpoints.orgSso(org) })
  const p = q.data?.provider
  const [v, setV] = useState<{ issuer: string; client_id: string; client_secret: string; display_name: string; groups_claim: string } | null>(null)
  const form = v ?? { issuer: p?.issuer ?? "", client_id: p?.client_id ?? "", client_secret: "", display_name: p?.display_name ?? "", groups_claim: p?.groups_claim ?? "groups" }
  const set = (patch: Partial<typeof form>) => setV({ ...form, ...patch })
  const done = () => { qc.invalidateQueries({ queryKey: ["org-sso", org] }); qc.invalidateQueries({ queryKey: ["org", org] }); qc.invalidateQueries({ queryKey: ["orgs"] }); setV(null) }
  const save = useMutation({ meta: { success: "Single sign-on saved" }, mutationFn: () => endpoints.setOrgSso(org, { ...form, client_secret: form.client_secret || undefined }), onSuccess: done })
  const remove = useMutation({ meta: { success: "Single sign-on removed" }, mutationFn: () => endpoints.deleteOrgSso(org), onSuccess: done })
  return (
    <FormSection title="Single sign-on" description="Let members sign in with your own identity provider (Okta, Entra ID, Google Workspace, Keycloak...). Its groups can fill teams.">
      {q.isLoading ? <Loading rows={2} /> : q.data && (
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
          <div className="space-y-1.5">
            <Label>Redirect URI to register with the provider</Label>
            <CopyField value={q.data.callback_url} />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5 sm:col-span-2"><Label htmlFor="sso-iss">Issuer</Label><Input id="sso-iss" value={form.issuer} onChange={(e) => set({ issuer: e.target.value })} placeholder="https://acme.okta.com" /></div>
            <div className="space-y-1.5"><Label htmlFor="sso-cid">Client ID</Label><Input id="sso-cid" value={form.client_id} onChange={(e) => set({ client_id: e.target.value })} /></div>
            <div className="space-y-1.5"><Label htmlFor="sso-sec">Client secret</Label><Input id="sso-sec" type="password" autoComplete="new-password" value={form.client_secret} onChange={(e) => set({ client_secret: e.target.value })} placeholder={p ? "unchanged" : ""} /></div>
            <div className="space-y-1.5"><Label htmlFor="sso-name">Button label</Label><Input id="sso-name" value={form.display_name} onChange={(e) => set({ display_name: e.target.value })} placeholder="Acme SSO" /></div>
            <div className="space-y-1.5"><Label htmlFor="sso-groups">Groups claim</Label><Input id="sso-groups" value={form.groups_claim} onChange={(e) => set({ groups_claim: e.target.value })} placeholder="groups" /></div>
          </div>
          <p className="text-xs text-muted-foreground">
            People who sign in this way get their own account; the provider can never sign in as an existing account. Members link an existing account from Settings → Security.
          </p>
          {p && <div className="space-y-1.5"><Label>Sign-in link to share</Label><CopyField value={q.data.login_url} /></div>}
          {(save.error || remove.error) && <ErrorBox error={save.error ?? remove.error} />}
          <div className="flex items-center gap-2">
            <Button type="submit" disabled={!v || !form.issuer || !form.client_id || save.isPending}>{p ? "Save" : "Enable single sign-on"}</Button>
            {v && <Button type="button" variant="outline" onClick={() => setV(null)}>Cancel</Button>}
            {p && <Button type="button" variant="ghost" className="ml-auto text-destructive hover:text-destructive" disabled={remove.isPending} onClick={() => { if (confirm("Turn off single sign-on? Teams synced from it stop syncing.")) remove.mutate() }}>Turn off</Button>}
          </div>
        </form>
      )}
    </FormSection>
  )
}

const SOURCE_LABEL: Record<string, string> = { ldap: "LDAP", oidc: "SSO", "org-oidc": "Org SSO" }
export const syncLabel = (t: Team) => t.sync && `${SOURCE_LABEL[t.sync.source] ?? t.sync.source}: ${t.sync.group_name}`

/** Point a team at a directory group: membership then follows sign-ins. */
export function TeamSyncDialog({ org, team, onClose }: { org: string; team: Team; onClose: () => void }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["org-sso", org], queryFn: () => endpoints.orgSso(org) })
  const sources = q.data?.sync_sources ?? []
  const [source, setSource] = useState<string>(team.sync?.source ?? "")
  const [group, setGroup] = useState(team.sync?.group_name ?? "")
  const src = source || sources[0]?.id || ""
  const done = () => { qc.invalidateQueries({ queryKey: ["org", org] }); onClose() }
  const save = useMutation({ meta: { success: "Team sync saved" }, mutationFn: () => endpoints.setTeamSync(org, team.name, src, group), onSuccess: done })
  const clear = useMutation({ meta: { success: "Team sync turned off" }, mutationFn: () => endpoints.clearTeamSync(org, team.name), onSuccess: done })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
          <DialogHeader>
            <DialogTitle>Sync {team.name} with a group</DialogTitle>
            <DialogDescription>Members are added or removed every time someone signs in through the source, to match the group. Robots stay as you set them.</DialogDescription>
          </DialogHeader>
          {q.isLoading && <Loading rows={2} />}
          {q.data && sources.length === 0 && (
            <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">No group source is available. Set up single sign-on with a groups claim in this organization's settings, or ask an administrator to configure LDAP.</p>
          )}
          {sources.length > 0 && (
            <>
              <LabeledSelect label="Source" value={src} onChange={setSource} options={sources.map((s) => [s.id, s.label] as [string, string])} className="w-full" />
              <div className="space-y-1.5">
                <Label htmlFor="sync-group">Group</Label>
                <Input id="sync-group" autoFocus value={group} onChange={(e) => setGroup(e.target.value)} placeholder={src === "ldap" ? "engineering (the group's cn)" : "engineering"} />
                <p className="text-xs text-muted-foreground">Exact group name as the source reports it; case does not matter.</p>
              </div>
            </>
          )}
          {(save.error || clear.error) && <ErrorBox error={save.error ?? clear.error} />}
          <DialogFooter>
            {team.sync && <Button type="button" variant="ghost" className="mr-auto" disabled={clear.isPending} onClick={() => clear.mutate()}>Stop syncing</Button>}
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={!src || !group.trim() || save.isPending}><RefreshCwIcon />Sync</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Settings → Security: link this account to organizations' sign-in providers. */
export function OrgSignInLinks() {
  const orgs = useQuery({ queryKey: ["orgs"], queryFn: endpoints.orgs })
  // Linking starts with a signed-in JSON POST (a cross-site page cannot forge one); the server
  // answers with the provider URL to go to.
  const link = useMutation({
    mutationFn: (org: string) => api<{ url: string }>(`/api/v1/auth/oidc/orgs/${encodeURIComponent(org)}/link`, { method: "POST", body: JSON.stringify({ redirect: "/settings/security" }) }),
    onSuccess: (r) => { location.href = r.url },
  })
  const list = (orgs.data ?? []).filter((o) => o.sso && o.is_member)
  if (list.length === 0) return null
  return (
    <FormSection title="Organization sign-in" description="Sign in with an organization's identity provider as this account.">
      <ul className="divide-y rounded-lg border">
        {list.map((o) => (
          <li key={o.id} className="flex items-center justify-between gap-3 px-4 py-3 text-sm">
            <span><span className="font-medium">{o.display_name || o.name}</span> <span className="text-muted-foreground">via {o.sso}</span></span>
            <Button variant="outline" size="sm" disabled={link.isPending} onClick={() => link.mutate(o.name)}>Link account</Button>
          </li>
        ))}
      </ul>
      <p className="mt-2 text-xs text-muted-foreground">Linking is one-time: afterwards that provider's sign-in opens <Mono>this</Mono> account.</p>
    </FormSection>
  )
}
