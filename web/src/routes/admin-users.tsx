import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { BotIcon, EllipsisIcon, KeyRoundIcon, PlusIcon, ShieldCheckIcon, ShieldOffIcon, Trash2Icon, UserIcon, UserRoundCheckIcon, UserRoundXIcon } from "lucide-react"
import { Avatar, Empty, Panel, SearchInput, Secret } from "@/components/page"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { endpoints, type Role, type UserInfo } from "@/lib/api"
import { formatDate, relativeTime } from "@/lib/time"
import { useSession } from "@/lib/session"
import { cn } from "@/lib/utils"

/** Roles as selectable rows with their descriptions, so admins know what they grant. */
function RoleChoices({ roles, value, onChange }: { roles: Role[]; value: string[]; onChange: (v: string[]) => void }) {
  if (roles.length === 0) return <p className="text-sm text-muted-foreground">No roles defined yet. Create them under Roles.</p>
  return (
    <div className="max-h-64 divide-y overflow-y-auto rounded-lg border">
      {roles.map((r) => {
        const on = value.includes(r.name)
        return (
          <label key={r.name} className={cn("flex cursor-pointer items-start gap-3 px-3 py-2.5 transition-colors hover:bg-accent/40", on && "bg-accent/30")}>
            <Checkbox className="mt-0.5" checked={on} onCheckedChange={(c) => onChange(c ? [...value, r.name] : value.filter((x) => x !== r.name))} />
            <span className="min-w-0">
              <span className="block text-sm font-medium">{r.name}</span>
              {r.description && <span className="block text-xs text-muted-foreground">{r.description}</span>}
            </span>
          </label>
        )
      })}
    </div>
  )
}

function CreateAccountDialog({ roles, onClose }: { roles: Role[]; onClose: () => void }) {
  const qc = useQueryClient()
  const [kind, setKind] = useState<"person" | "robot">("person")
  const [v, setV] = useState({ username: "", email: "", password: "" })
  const [picked, setPicked] = useState<string[]>([])
  const create = useMutation({
    meta: { success: "User created" },
    mutationFn: () => endpoints.createUser({ username: v.username.trim(), email: v.email.trim() || undefined, password: kind === "person" ? v.password : undefined, roles: picked, is_robot: kind === "robot" }),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ["users"] }); if (!r.token) onClose() },
  })
  const nameOk = /^[a-zA-Z0-9][a-zA-Z0-9._-]*(\+[a-zA-Z0-9][a-zA-Z0-9._-]*)?$/.test(v.username)
  const ok = nameOk && (kind === "robot" || v.password.length >= 8)
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-lg">
        {create.data?.token ? (
          <div className="space-y-4">
            <DialogHeader>
              <DialogTitle>Robot account created</DialogTitle>
              <DialogDescription>{create.data.username} signs in with this credential, e.g. <Mono>docker login -u {create.data.username}</Mono>.</DialogDescription>
            </DialogHeader>
            <Secret label="Credential" value={create.data.token} />
            <DialogFooter><Button onClick={onClose}>Done</Button></DialogFooter>
          </div>
        ) : (
          <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (ok) create.mutate() }}>
            <DialogHeader>
              <DialogTitle>Create account</DialogTitle>
              <DialogDescription>People sign in with a password; robots get a credential for CI and scripts.</DialogDescription>
            </DialogHeader>
            <div className="grid grid-cols-2 gap-2">
              {([["person", UserIcon, "Person", "Signs in to the UI and CLI"], ["robot", BotIcon, "Robot", "Credential for automation"]] as const).map(([k, Icon, title, hint]) => (
                <button key={k} type="button" onClick={() => setKind(k)}
                  className={cn("flex items-start gap-3 rounded-lg p-3 text-left ring-1 transition-colors", kind === k ? "bg-foreground/5 ring-foreground/30" : "ring-border hover:bg-foreground/[0.03]")}>
                  <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                  <span><span className="block text-sm font-medium">{title}</span><span className="block text-xs text-muted-foreground">{hint}</span></span>
                </button>
              ))}
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="new-user">Username</Label>
                <Input id="new-user" autoFocus autoComplete="off" value={v.username} onChange={(e) => setV({ ...v, username: e.target.value })} placeholder={kind === "robot" ? "zack+ci" : "jane"} aria-invalid={!!v.username && !nameOk} />
                {kind === "robot" && <p className="text-xs text-muted-foreground"><Mono>owner+name</Mono> ties it to an account</p>}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="new-email">Email <span className="font-normal text-muted-foreground">(optional)</span></Label>
                <Input id="new-email" type="email" value={v.email} onChange={(e) => setV({ ...v, email: e.target.value })} placeholder="jane@example.com" />
              </div>
            </div>
            {kind === "person" && (
              <div className="space-y-1.5">
                <Label htmlFor="new-pass">Initial password</Label>
                <Input id="new-pass" type="password" autoComplete="new-password" value={v.password} onChange={(e) => setV({ ...v, password: e.target.value })} />
                <p className="text-xs text-muted-foreground">At least 8 characters. They can change it under Settings → Security.</p>
              </div>
            )}
            <div className="space-y-1.5">
              <Label>Roles</Label>
              <RoleChoices roles={roles} value={picked} onChange={setPicked} />
            </div>
            {create.error && <ErrorBox error={create.error} />}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
              <Button type="submit" disabled={!ok || create.isPending}>Create account</Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

function RolesDialog({ user, roles, onClose }: { user: UserInfo; roles: Role[]; onClose: () => void }) {
  const qc = useQueryClient()
  const [picked, setPicked] = useState(user.roles)
  const save = useMutation({ meta: { success: "Roles updated" }, mutationFn: () => endpoints.updateUser(user.id, { roles: picked }), onSuccess: () => { qc.invalidateQueries({ queryKey: ["users"] }); onClose() } })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader><DialogTitle>Roles for {user.username}</DialogTitle><DialogDescription>Instance-wide roles. Organization access is managed from each organization.</DialogDescription></DialogHeader>
        <RoleChoices roles={roles} value={picked} onChange={setPicked} />
        {save.error && <ErrorBox error={save.error} />}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending}>Save roles</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function PasswordDialog({ user, onClose }: { user: UserInfo; onClose: () => void }) {
  const [pw, setPw] = useState("")
  const save = useMutation({ meta: { success: "Password reset" }, mutationFn: () => endpoints.resetPassword(user.id, pw), onSuccess: onClose })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (pw.length >= 8) save.mutate() }}>
          <DialogHeader><DialogTitle>Set password for {user.username}</DialogTitle><DialogDescription>This signs them out everywhere. Share the new password with them securely.</DialogDescription></DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="reset-pw">New password</Label>
            <Input id="reset-pw" type="password" autoFocus autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
            <p className="text-xs text-muted-foreground">At least 8 characters.</p>
          </div>
          {save.error && <ErrorBox error={save.error} />}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={pw.length < 8 || save.isPending}>Set password</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function ConfirmDialog({ title, description, action, destructive, onConfirm, onClose, pending, error }: {
  title: string; description: React.ReactNode; action: string; destructive?: boolean; onConfirm: () => void; onClose: () => void; pending?: boolean; error?: unknown
}) {
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader><DialogTitle>{title}</DialogTitle><DialogDescription>{description}</DialogDescription></DialogHeader>
        {!!error && <ErrorBox error={error} />}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant={destructive ? "destructive" : "default"} onClick={onConfirm} disabled={pending}>{action}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

type Filter = "all" | "people" | "robots" | "disabled"
type Modal = { kind: "create" } | { kind: "roles" | "password" | "delete" | "disable" | "mfa"; user: UserInfo } | null

export function UsersPage() {
  const qc = useQueryClient()
  const { me } = useSession()
  const canWrite = !!me?.globals.includes("users:write") || !!me?.globals.includes("system")
  const users = useQuery({ queryKey: ["users"], queryFn: endpoints.users })
  const roles = useQuery({ queryKey: ["roles"], queryFn: endpoints.roles })
  const [search, setSearch] = useState("")
  const [filter, setFilter] = useState<Filter>("all")
  const [modal, setModal] = useState<Modal>(null)
  const close = () => setModal(null)
  const done = () => { qc.invalidateQueries({ queryKey: ["users"] }); close() }
  const update = useMutation({ meta: { success: "User updated" }, mutationFn: (v: { id: number; is_disabled: boolean }) => endpoints.updateUser(v.id, v), onSuccess: done })
  const del = useMutation({ meta: { success: "User deleted" }, mutationFn: endpoints.deleteUser, onSuccess: done })
  const resetMfa = useMutation({ meta: { success: "Two-factor authentication reset" }, mutationFn: endpoints.resetMfa, onSuccess: done })

  if (users.isLoading) return <Loading />
  if (users.error) return <ErrorBox error={users.error} />
  const all = users.data ?? []
  const counts: Record<Filter, number> = { all: all.length, people: all.filter((u) => !u.is_robot).length, robots: all.filter((u) => u.is_robot).length, disabled: all.filter((u) => u.is_disabled).length }
  const term = search.trim().toLowerCase()
  const list = all
    .filter((u) => filter === "all" || (filter === "people" ? !u.is_robot : filter === "robots" ? u.is_robot : u.is_disabled))
    .filter((u) => !term || [u.username, u.email, u.display_name, ...u.roles].some((s) => s?.toLowerCase().includes(term)))

  return (
    <>
      <div className="flex flex-wrap items-center gap-3">
        <SearchInput className="w-full sm:w-72" placeholder="Search name, email or role..." value={search} onChange={setSearch} />
        <div className="flex gap-1 text-sm">
          {(["all", "people", "robots", "disabled"] as const).map((f) => (
            <button key={f} type="button" onClick={() => setFilter(f)}
              className={cn("rounded-md px-2.5 py-1.5 capitalize transition-colors", filter === f ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground")}>
              {f} <span className="tabular-nums text-muted-foreground">{counts[f]}</span>
            </button>
          ))}
        </div>
        {canWrite && <Button className="sm:ml-auto" onClick={() => setModal({ kind: "create" })}><PlusIcon />Create account</Button>}
      </div>

      <Panel>
        <Table>
          <TableHeader><TableRow><TableHead className="pl-4">Account</TableHead><TableHead>Roles</TableHead><TableHead className="hidden md:table-cell">Status</TableHead><TableHead className="hidden lg:table-cell">Last sign-in</TableHead><TableHead className="w-12 pr-4" /></TableRow></TableHeader>
          <TableBody>
            {list.length === 0 && <TableRow className="hover:bg-transparent"><TableCell colSpan={5}><Empty>{term || filter !== "all" ? "No accounts match." : "No accounts yet."}</Empty></TableCell></TableRow>}
            {list.map((u) => {
              const self = u.id === me?.user_id
              const editable = canWrite && !u.is_managed
              return (
                <TableRow key={u.id} className={cn(u.is_disabled && "opacity-60")}>
                  <TableCell className="pl-4">
                    <div className="flex items-center gap-3">
                      <Avatar name={u.username} className={cn(u.is_robot && "rounded-md")} />
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-1.5 font-medium">
                          {u.display_name || u.username}
                          {self && <span className="text-xs font-normal text-muted-foreground">(you)</span>}
                          {u.is_robot && <Badge variant="outline" className="gap-1 font-normal"><BotIcon className="size-3" />robot</Badge>}
                          {u.is_managed && <Badge variant="outline" className="font-normal" title="Defined in the config file; change it there">config</Badge>}
                        </div>
                        <div className="truncate text-xs text-muted-foreground">
                          {[u.display_name ? u.username : null, u.email, u.owner ? `owned by ${u.owner}` : null, u.identities.length ? "SSO" : null].filter(Boolean).join(" · ") || " "}
                        </div>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <span className="flex flex-wrap gap-1">
                      {u.roles.map((r) => <Badge key={r} variant="secondary" className="font-normal">{r}</Badge>)}
                      {u.roles.length === 0 && <span className="text-xs text-muted-foreground">No roles</span>}
                    </span>
                  </TableCell>
                  <TableCell className="hidden md:table-cell">
                    <span className="flex items-center gap-3 text-sm">
                      <span className="flex items-center gap-1.5"><span className={cn("size-1.5 rounded-full", u.is_disabled ? "bg-muted-foreground" : "bg-emerald-500")} />{u.is_disabled ? "Disabled" : "Active"}</span>
                      {u.is_mfa_enabled && <span className="flex items-center gap-1 text-xs text-muted-foreground" title="Two-factor authentication on"><ShieldCheckIcon className="size-3.5" />2FA</span>}
                    </span>
                  </TableCell>
                  <TableCell className="hidden text-sm text-muted-foreground lg:table-cell">
                    {u.is_robot ? "—" : u.last_login_at ? <span title={formatDate(u.last_login_at)}>{relativeTime(u.last_login_at)}</span> : "Never"}
                  </TableCell>
                  <TableCell className="pr-4 text-right">
                    {editable && (
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <button type="button" className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground data-[state=open]:bg-accent" aria-label={`Manage ${u.username}`}><EllipsisIcon className="size-4" /></button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-48">
                          <DropdownMenuItem onClick={() => setModal({ kind: "roles", user: u })}><ShieldCheckIcon />Edit roles</DropdownMenuItem>
                          {!u.is_robot && <DropdownMenuItem onClick={() => setModal({ kind: "password", user: u })}><KeyRoundIcon />Set password</DropdownMenuItem>}
                          {u.is_mfa_enabled && <DropdownMenuItem onClick={() => setModal({ kind: "mfa", user: u })}><ShieldOffIcon />Reset 2FA</DropdownMenuItem>}
                          {!self && <>
                            <DropdownMenuSeparator />
                            {u.is_disabled
                              ? <DropdownMenuItem onClick={() => update.mutate({ id: u.id, is_disabled: false })}><UserRoundCheckIcon />Enable</DropdownMenuItem>
                              : <DropdownMenuItem onClick={() => setModal({ kind: "disable", user: u })}><UserRoundXIcon />Disable</DropdownMenuItem>}
                            <DropdownMenuItem variant="destructive" onClick={() => setModal({ kind: "delete", user: u })}><Trash2Icon />Delete</DropdownMenuItem>
                          </>}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    )}
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </Panel>
      {update.error && !modal && <ErrorBox error={update.error} />}

      {modal?.kind === "create" && <CreateAccountDialog roles={roles.data ?? []} onClose={close} />}
      {modal?.kind === "roles" && <RolesDialog user={modal.user} roles={roles.data ?? []} onClose={close} />}
      {modal?.kind === "password" && <PasswordDialog user={modal.user} onClose={close} />}
      {modal?.kind === "disable" && (
        <ConfirmDialog title={`Disable ${modal.user.username}?`} description="They are signed out and can't sign in, push or pull until enabled again. Nothing is deleted."
          action="Disable account" destructive onConfirm={() => update.mutate({ id: modal.user.id, is_disabled: true })} onClose={close} pending={update.isPending} error={update.error} />
      )}
      {modal?.kind === "mfa" && (
        <ConfirmDialog title={`Reset 2FA for ${modal.user.username}?`} description="Their authenticator and recovery codes stop working. They can sign in with just their password and set up 2FA again."
          action="Reset 2FA" destructive onConfirm={() => resetMfa.mutate(modal.user.id)} onClose={close} pending={resetMfa.isPending} error={resetMfa.error} />
      )}
      {modal?.kind === "delete" && (
        <ConfirmDialog title={`Delete ${modal.user.username}?`} description={<>The account, its tokens{modal.user.is_robot ? "" : " and robots"} are removed. Repositories under <Mono>{modal.user.username}/</Mono> stay. This can't be undone.</>}
          action="Delete account" destructive onConfirm={() => del.mutate(modal.user.id)} onClose={close} pending={del.isPending} error={del.error} />
      )}
    </>
  )
}
