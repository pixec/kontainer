import { useState } from "react"
import { CheckIcon, PlusIcon, Trash2Icon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import type { Action, Permissions, Rule } from "@/lib/api"
import { cn } from "@/lib/utils"

export const ACTION_LABELS: Record<Action, string> = {
  pull: "Pull (read)",
  push: "Push (write)",
  delete: "Delete tags & images",
  delete_repository: "Delete repository",
  scan: "Run scans",
  logs: "View activity",
  metadata: "Edit description & README",
  visibility: "Change visibility",
  permissions: "Manage access",
  state: "Freeze (read-only)",
  builds: "Manage builds",
  mirror: "Manage mirrors",
  admin: "Admin (everything)",
}

const parse = (text: string) => text.split(",").map((s) => s.trim()).filter(Boolean)

/** Edits a list of repository rules: glob patterns plus the actions they grant. `prefix` is shown
 *  before the pattern when rules are relative to a namespace (e.g. an organization). */
export function RuleEditor({ rules, onChange, perms, prefix }: { rules: Rule[]; onChange: (r: Rule[]) => void; perms: Permissions; prefix?: string }) {
  const update = (i: number, r: Rule) => onChange(rules.map((x, j) => (j === i ? r : x)))
  return (
    <div className="space-y-3">
      {rules.map((r, i) => (
        <div key={i} className="space-y-3 rounded-lg border bg-muted/40 p-3">
          <div className="flex items-center gap-2">
            <Patterns value={r.repositories} prefix={prefix} onChange={(repositories) => update(i, { ...r, repositories })} />
            <Button type="button" variant="ghost" size="icon" className="shrink-0 text-muted-foreground hover:text-destructive" title="Remove rule" onClick={() => onChange(rules.filter((_, j) => j !== i))}><Trash2Icon /></Button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {perms.actions.map((a) => {
              const on = r.actions.includes(a.name)
              return (
                <button key={a.name} type="button" title={a.description} aria-pressed={on}
                  onClick={() => update(i, { ...r, actions: on ? r.actions.filter((x) => x !== a.name) : [...r.actions, a.name as Action] })}
                  className={cn("inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-xs font-medium transition-colors",
                    on ? "border-foreground/30 bg-foreground/10 text-foreground" : "text-muted-foreground hover:border-ring/70 hover:text-foreground")}>
                  {on && <CheckIcon className="size-3" />}{ACTION_LABELS[a.name] ?? a.name}
                </button>
              )
            })}
          </div>
        </div>
      ))}
      <Button type="button" variant="ghost" size="sm" onClick={() => onChange([...rules, { repositories: ["**"], actions: ["pull"] }])}><PlusIcon />Add rule</Button>
    </div>
  )
}

/** Comma-separated patterns. Keeps the raw text locally so commas and spaces can be typed. */
function Patterns({ value, prefix, onChange }: { value: string[]; prefix?: string; onChange: (v: string[]) => void }) {
  const [text, setText] = useState(value.join(", "))
  if (parse(text).join(",") !== value.join(",")) setText(value.join(", "))
  return (
    <div className="relative min-w-0 flex-1">
      {prefix && <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 font-mono text-sm text-muted-foreground">{prefix}</span>}
      <Input className="font-mono" style={prefix ? { paddingLeft: `calc(${prefix.length}ch + 0.75rem + 1px)` } : undefined}
        placeholder="** for all, api/* for one level, a, b for several"
        value={text} onChange={(e) => { setText(e.target.value); onChange(parse(e.target.value)) }} />
    </div>
  )
}
