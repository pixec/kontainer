import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { ChevronRightIcon, PlusIcon, ShieldCheckIcon, Trash2Icon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { LabeledSelect } from "@/components/page"
import { CodeBlock } from "@/components/use-snippets"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { endpoints, type FederationRule } from "@/lib/api"

const ISSUERS = {
  github: { label: "GitHub Actions", issuer: "https://token.actions.githubusercontent.com", subject: "repo::ref:refs/heads/main", repoLabel: "Repository" },
  gitlab: { label: "GitLab.com", issuer: "https://gitlab.com", subject: "project_path::ref_type:branch:ref:main", repoLabel: "Project" },
  custom: { label: "Other OIDC issuer", issuer: "", subject: "", repoLabel: "" },
} as const
type Preset = keyof typeof ISSUERS
const presetOf = (issuer: string): Preset => (Object.keys(ISSUERS) as Preset[]).find((k) => k !== "custom" && ISSUERS[k].issuer === issuer) ?? "custom"

/** Which runs of a repository may sign in; turned into the token subject pattern. */
type Kind = "branch" | "anyBranch" | "tag" | "anyTag" | "pr" | "environment" | "anything"
const KINDS: Record<Kind, { label: string; name?: { label: string; placeholder: string } }> = {
  branch: { label: "One branch", name: { label: "Branch", placeholder: "main" } },
  anyBranch: { label: "Any branch" },
  tag: { label: "Tags named", name: { label: "Tag", placeholder: "v*" } },
  anyTag: { label: "Any tag" },
  pr: { label: "Pull requests" },
  environment: { label: "A deployment environment", name: { label: "Environment", placeholder: "production" } },
  anything: { label: "Any run" },
}
// `*` stops at `/`; branch and tag names may contain `/`, so "any" uses `**`.
const PATTERNS: Record<"github" | "gitlab", { prefix: string; kinds: Partial<Record<Kind, string>> }> = {
  github: { prefix: "repo", kinds: { branch: "ref:refs/heads/{}", anyBranch: "ref:refs/heads/**", tag: "ref:refs/tags/{}", anyTag: "ref:refs/tags/**", pr: "pull_request", environment: "environment:{}", anything: "**" } },
  gitlab: { prefix: "project_path", kinds: { branch: "ref_type:branch:ref:{}", anyBranch: "ref_type:branch:ref:**", tag: "ref_type:tag:ref:{}", anyTag: "ref_type:tag:ref:**", anything: "**" } },
}
type Picked = { repo: string; kind: Kind; name: string }

function buildSubject(preset: "github" | "gitlab", { repo, kind, name }: Picked) {
  const { prefix, kinds } = PATTERNS[preset]
  return `${prefix}:${repo.trim()}:${(kinds[kind] ?? "**").replace("{}", name.trim())}`
}

/** The picker's view of a subject, or null when it was written by hand in some other shape. */
function parseSubject(preset: "github" | "gitlab", subject: string): Picked | null {
  const { prefix, kinds } = PATTERNS[preset]
  const m = subject.match(new RegExp(`^${prefix}:([^:]*):(.*)$`))
  if (!m) return null
  const [, repo, rest] = m
  for (const [kind, pat] of Object.entries(kinds) as [Kind, string][]) {
    if (!pat.includes("{}")) { if (rest === pat) return { repo, kind, name: "" }; continue }
    const [before, after] = pat.split("{}")
    if (rest.startsWith(before) && rest.endsWith(after)) {
      const name = rest.slice(before.length, rest.length - after.length)
      // Leave "any" patterns to their own kind.
      if (name && name !== "**") return { repo, kind, name }
    }
  }
  return null
}

/** Choose which jobs may sign in: pickers for known CI providers, a raw pattern otherwise. */
function SubjectEditor({ id, preset, subject, onChange }: { id: string; preset: Preset; subject: string; onChange: (s: string) => void }) {
  const picked = preset === "custom" ? null : parseSubject(preset, subject)
  const [manual, setManual] = useState(false)
  if (preset === "custom" || manual || !picked) {
    return (
      <div className="space-y-1.5">
        <Label htmlFor={id}>Which jobs</Label>
        <Input id={id} className="font-mono text-xs" value={subject} onChange={(e) => onChange(e.target.value)} placeholder="repo:acme/app:ref:refs/heads/main" />
        <p className="text-xs text-muted-foreground">
          Matched against the token's <Mono>sub</Mono> claim. <Mono>*</Mono> matches anything except <Mono>/</Mono>; <Mono>**</Mono> matches anything.
          {preset !== "custom" && <> <button type="button" className="text-foreground hover:underline" onClick={() => { setManual(false); if (!picked) onChange(ISSUERS[preset].subject) }}>{picked ? "Use the picker" : "Start over with the picker"}</button></>}
        </p>
      </div>
    )
  }
  const set = (patch: Partial<Picked>) => onChange(buildSubject(preset, { ...picked, ...patch }))
  const kinds = (Object.keys(PATTERNS[preset].kinds) as Kind[]).map((k) => [k, KINDS[k].label] as [Kind, string])
  const name = KINDS[picked.kind].name
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor={id}>{ISSUERS[preset].repoLabel}</Label>
          <Input id={id} value={picked.repo} onChange={(e) => set({ repo: e.target.value.replace(/:/g, "") })} placeholder="acme/app" />
        </div>
        <div className="space-y-1.5">
          <Label>Allow</Label>
          <LabeledSelect label="Runs from" value={picked.kind} className="w-full" options={kinds}
            onChange={(kind) => set({ kind, name: KINDS[kind].name ? picked.name || KINDS[kind].name!.placeholder : "" })} />
        </div>
      </div>
      {name && (
        <div className="space-y-1.5">
          <Label htmlFor={`${id}-name`}>{name.label}</Label>
          <Input id={`${id}-name`} value={picked.name} onChange={(e) => set({ name: e.target.value.replace(/:/g, "") })} placeholder={name.placeholder} />
          {picked.kind === "tag" && <p className="text-xs text-muted-foreground"><Mono>*</Mono> is a wildcard: <Mono>v*</Mono> covers <Mono>v1.0</Mono>, <Mono>v2.3.1</Mono> and so on.</p>}
        </div>
      )}
      <p className="text-xs text-muted-foreground">
        {picked.repo.trim() ? <>Matches <Mono className="break-all">{subject}</Mono>. </> : <>Enter the {ISSUERS[preset].repoLabel.toLowerCase()} these jobs run in. </>}
        <button type="button" className="text-foreground hover:underline" onClick={() => setManual(true)}>Edit the pattern by hand</button>
      </p>
    </div>
  )
}

/** Plain-language walkthrough, open until the robot trusts its first issuer. */
function HowItWorks({ robot, provider, defaultOpen }: { robot: string; provider: string; defaultOpen: boolean }) {
  const steps = [
    <>Your job asks {provider} for a sign-in token: a one-time pass that says <q>I'm a job in this repository, on this branch</q>. It expires within minutes.</>,
    <>The job uses that token as the password for <Mono>docker login</Mono>. The workflow snippet below does this for you.</>,
    <>Kontainer checks that {provider} really issued the token and that it matches one of your rules. If it does, the job is signed in as <Mono>{robot}</Mono> and can do whatever {robot} is allowed to do, nothing more.</>,
  ]
  return (
    <details open={defaultOpen} className="group rounded-lg border bg-muted/30 [&_summary::-webkit-details-marker]:hidden">
      <summary className="flex cursor-pointer select-none items-center gap-2 px-3 py-2.5 text-sm font-medium">
        <ChevronRightIcon className="size-4 text-muted-foreground transition-transform group-open:rotate-90" />
        How does this work?
      </summary>
      <div className="space-y-3 px-3 pb-3 text-sm text-muted-foreground">
        <ol className="space-y-2">
          {steps.map((s, i) => (
            <li key={i} className="flex gap-3">
              <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-foreground/10 text-xs font-medium text-foreground">{i + 1}</span>
              <span>{s}</span>
            </li>
          ))}
        </ol>
        <p className="flex gap-2 rounded-md bg-background/60 p-2.5">
          <ShieldCheckIcon className="mt-0.5 size-4 shrink-0 text-emerald-500" />
          <span>There's no password to store in your CI or to rotate later, and a leaked token stops working in minutes.</span>
        </p>
      </div>
    </details>
  )
}

function snippet(preset: Preset, robot: string, audience: string) {
  const host = location.host
  if (preset === "gitlab") {
    return `push:\n  id_tokens:\n    REGISTRY_ID_TOKEN:\n      aud: ${audience || "kontainer"}\n  script:\n    - echo "$REGISTRY_ID_TOKEN" | docker login ${host} -u ${robot} --password-stdin`
  }
  return `permissions:\n  id-token: write\n  contents: read\nsteps:\n  - run: |\n      TOKEN=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \\\n        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=${audience || "kontainer"}" | jq -r .value)\n      echo "$TOKEN" | docker login ${host} -u ${robot} --password-stdin`
}

/** A robot's trusted OIDC issuers: CI jobs sign in with their own short-lived token. */
export function RobotFederationDialog({ robotId, robot, onClose }: { robotId: number; robot: string; onClose: () => void }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["robot-federation", robotId], queryFn: () => endpoints.robotFederation(robotId) })
  const [draft, setDraft] = useState<FederationRule[] | null>(null)
  const rules = draft ?? q.data ?? []
  const save = useMutation({
    meta: { success: "Keyless sign-in rules saved" },
    mutationFn: () => endpoints.setRobotFederation(robotId, rules),
    onSuccess: (r) => { qc.setQueryData(["robot-federation", robotId], r); setDraft(null) },
  })
  const update = (i: number, patch: Partial<FederationRule>) => setDraft(rules.map((r, j) => (j === i ? { ...r, ...patch } : r)))
  // A picked rule needs its repository; an empty one would never match anything.
  const incomplete = rules.some((r) => {
    const preset = presetOf(r.issuer)
    if (preset === "custom") return !r.issuer.trim() || !r.subject.trim()
    const picked = parseSubject(preset, r.subject)
    return picked ? !picked.repo.trim() || (!!KINDS[picked.kind].name && !picked.name.trim()) : !r.subject.trim()
  })
  const add = () => setDraft([...rules, { issuer: ISSUERS.github.issuer, subject: ISSUERS.github.subject, audience: "kontainer" }])
  const first = rules[0]
  const provider = first && presetOf(first.issuer) !== "custom" ? ISSUERS[presetOf(first.issuer)].label : "your CI provider"
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Keyless sign-in for {robot}</DialogTitle>
          <DialogDescription>
            Let your CI jobs push and pull as {robot} without saving a password anywhere. Each job proves who it is with a short-lived token from your CI provider, and Kontainer checks it.
          </DialogDescription>
        </DialogHeader>
        <HowItWorks key={q.data ? "loaded" : "loading"} robot={robot} provider={provider} defaultOpen={!!q.data && q.data.length === 0} />
        {q.isLoading && <Loading rows={2} />}
        {q.error && <ErrorBox error={q.error} />}
        <div className="space-y-3">
          {rules.length === 0 && q.data && <p className="rounded-lg border border-dashed p-4 text-center text-sm text-muted-foreground">No trusted CI providers yet, so {robot} can only sign in with its credential. Add one to get started.</p>}
          {rules.map((r, i) => {
            const preset = presetOf(r.issuer)
            return (
              <div key={i} className="space-y-3 rounded-lg border p-3">
                <div className="flex items-center gap-2">
                  <LabeledSelect label="Issuer" value={preset} className="flex-1"
                    onChange={(p) => update(i, p === "custom" ? { issuer: "" } : { issuer: ISSUERS[p].issuer, subject: ISSUERS[p].subject })}
                    options={(Object.keys(ISSUERS) as Preset[]).map((k) => [k, ISSUERS[k].label] as [Preset, string])} />
                  <Button variant="ghost" size="icon" aria-label="Remove this provider" onClick={() => setDraft(rules.filter((_, j) => j !== i))}><Trash2Icon /></Button>
                </div>
                {preset === "custom" && (
                  <div className="space-y-1.5"><Label htmlFor={`iss-${i}`}>Issuer URL</Label><Input id={`iss-${i}`} value={r.issuer} onChange={(e) => update(i, { issuer: e.target.value })} placeholder="https://issuer.example.com" /></div>
                )}
                <SubjectEditor key={preset} id={`sub-${i}`} preset={preset} subject={r.subject} onChange={(subject) => update(i, { subject })} />
                <div className="space-y-1.5 sm:max-w-[50%] sm:pr-1.5">
                  <Label htmlFor={`aud-${i}`}>Audience</Label>
                  <Input id={`aud-${i}`} value={r.audience ?? ""} onChange={(e) => update(i, { audience: e.target.value || null })} placeholder="any" />
                  <p className="text-xs text-muted-foreground">Optional. The job must ask for a token with this name.</p>
                </div>
              </div>
            )
          })}
          <Button variant="outline" onClick={add}><PlusIcon />Add a CI provider</Button>
        </div>
        {first && presetOf(first.issuer) !== "custom" && (
          <div className="space-y-1.5">
            <div className="text-sm font-medium">Add this to your {ISSUERS[presetOf(first.issuer)].label} workflow</div>
            <p className="text-xs text-muted-foreground">It fetches a token for the job and signs in with it. Save your rules first.</p>
            <CodeBlock code={snippet(presetOf(first.issuer), robot, first.audience ?? "")} />
          </div>
        )}
        {save.error && <ErrorBox error={save.error} />}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Close</Button>
          <Button onClick={() => save.mutate()} disabled={!draft || incomplete || save.isPending}>Save rules</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
