import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { Link } from "react-router"
import { BotIcon, PlusIcon, UserIcon, UsersIcon, XIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { PrincipalPicker } from "@/components/principal-picker"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { endpoints, type Level, type RepoGrant } from "@/lib/api"
import { useSession } from "@/lib/session"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { Empty, FormSection } from "@/components/page"
import { LevelBadge, LevelSelect } from "@/components/access"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { cn } from "@/lib/utils"

type Kind = "user" | "robot" | "team"
const KIND_ICON = { user: UserIcon, robot: BotIcon, team: UsersIcon }
const KIND_LABEL: Record<Kind, string> = { user: "Person", robot: "Robot", team: "Team" }

/** Repository permissions: explicit grants plus org-wide access shown read-only. */
export function RepoPermissions({ name }: { name: string }) {
  const qc = useQueryClient()
  const { me } = useSession()
  const ns = name.split("/")[0]
  const q = useQuery({ queryKey: ["repo-permissions", name], queryFn: () => endpoints.repoPermissions(name) })
  const org = q.data?.org ?? null
  const set = useMutation({
    meta: { success: "Permissions updated" },
    mutationFn: (v: { kind: Kind; name: string; level: Level | null }) => endpoints.setRepoPermission(name, v.kind === "team" ? "team" : "user", v.name, v.level),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["repo-permissions", name] }); qc.invalidateQueries({ queryKey: ["org"] }); qc.invalidateQueries({ queryKey: ["robots"] }) },
  })
  const [kind, setKind] = useState<Kind>("user")
  const [who, setWho] = useState("")
  const [level, setLevel] = useState<Level>("read")
  if (q.isLoading) return <Loading rows={3} />
  if (q.error) return <ErrorBox error={q.error} />
  const kinds: Kind[] = org ? ["user", "robot", "team"] : ["user", "robot"]
  const add = () => { if (who.trim()) set.mutate({ kind, name: who.trim(), level }, { onSuccess: () => setWho("") }) }

  return (
    <div>
      <FormSection title="Add access" description={<>Give {org ? "a person, robot or team" : "a person or robot"} access to this repository.</>}>
        <form className="space-y-2" onSubmit={(e) => { e.preventDefault(); add() }}>
          <div className="grid grid-cols-[auto_minmax(0,1fr)] gap-2 sm:flex">
            <Select value={kind} onValueChange={(k) => { setKind(k as Kind); setWho("") }}>
              <SelectTrigger className="w-32" aria-label="Kind"><SelectValue /></SelectTrigger>
              <SelectContent>
                {kinds.map((k) => {
                  const Icon = KIND_ICON[k]
                  return <SelectItem key={k} value={k}><Icon className="text-muted-foreground" />{KIND_LABEL[k]}</SelectItem>
                })}
              </SelectContent>
            </Select>
            <PrincipalPicker kinds={[kind]} namespace={org ?? ns} value={who} onChange={setWho} onPick={() => {}} className="sm:flex-1"
              exclude={q.data!.grants.filter((g) => (g.kind === "team") === (kind === "team")).map((g) => g.name)} />
            <LevelSelect value={level} onChange={(l) => l && setLevel(l)} allowCustom className="w-full sm:w-36" />
            <Button type="submit" size="lg" disabled={!who.trim() || set.isPending}><PlusIcon />Add</Button>
          </div>
          {kind === "robot" && <p className="text-xs text-muted-foreground">Robots can only be granted repositories in their own namespace, <Mono className="text-foreground">{ns}/</Mono>.</p>}
          {set.error && <ErrorBox error={set.error} />}
        </form>
      </FormSection>

      <FormSection title="Granted" description="Explicit access to this repository.">
        {q.data!.grants.length === 0 ? <div className="rounded-lg border border-dashed"><Empty>No one has been granted access yet.</Empty></div> : (
          <Table>
            <TableHeader><TableRow><TableHead className="pl-0">Who</TableHead><TableHead className="w-40">Access</TableHead><TableHead className="w-10 pr-0" /></TableRow></TableHeader>
            <TableBody>
              {q.data!.grants.map((g) => <GrantRow key={`${g.kind}:${g.name}`} g={g} disabled={set.isPending}
                onChange={(l) => set.mutate({ kind: g.kind, name: g.name, level: l })} />)}
            </TableBody>
          </Table>
        )}
      </FormSection>

      {(org || ns === me?.username) && (
        <FormSection title="Also has access" description={org ? <>Organization-wide access, managed in <Link to={`/orgs/${org}/teams`} className="text-foreground underline-offset-4 hover:underline">Teams</Link>.</> : "You own this namespace."}>
          <ul className="divide-y rounded-lg border">
            {!org && <li className="flex items-center gap-3 px-4 py-3 text-sm"><UserIcon className="size-4 text-muted-foreground" /><span className="flex-1">{me?.username}</span><span className="text-xs text-muted-foreground">Namespace owner</span><LevelBadge level="admin" /></li>}
            {q.data!.inherited.map((i) => (
              <li key={i.team} className="flex items-center gap-3 px-4 py-3 text-sm">
                <UsersIcon className="size-4 text-muted-foreground" /><span className="flex-1">{i.team}</span>
                <span className="text-xs text-muted-foreground">{i.source}</span><LevelBadge level={i.level} />
              </li>
            ))}
            {org && q.data!.inherited.length === 0 && <li className="px-4 py-3 text-sm text-muted-foreground">No org-wide access.</li>}
          </ul>
        </FormSection>
      )}
    </div>
  )
}

function GrantRow({ g, onChange, disabled }: { g: RepoGrant; onChange: (l: Level | null) => void; disabled: boolean }) {
  const Icon = KIND_ICON[g.kind]
  return (
    <TableRow>
      <TableCell className="py-2.5 pl-0">
        <span className="flex items-center gap-3">
          <Icon className="size-4 shrink-0 text-muted-foreground" />
          <span className="min-w-0">
            <span className={cn("block truncate", g.kind === "robot" && "font-mono text-[13px]")}>{g.name}</span>
            {g.display_name && <span className="block truncate text-xs text-muted-foreground">{g.display_name}</span>}
          </span>
          <span className="chip">{KIND_LABEL[g.kind]}</span>
        </span>
      </TableCell>
      <TableCell><LevelSelect value={g.level} onChange={(l) => l && l !== g.level && onChange(l)} allowCustom className="h-8 w-32" /></TableCell>
      <TableCell className="pr-0 text-right">
        <button type="button" disabled={disabled} onClick={() => onChange(null)} title="Remove access" aria-label={`Remove ${g.name}`}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-destructive"><XIcon className="size-4" /></button>
      </TableCell>
    </TableRow>
  )
}
