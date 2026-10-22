import { useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select"
import { endpoints, isPreset, levelActions, PRESETS, type Action, type Level, type Preset, type TeamRole } from "@/lib/api"
import { ACTION_LABELS } from "@/components/rule-editor"
import { cn } from "@/lib/utils"

/** Repository access presets. */
export const LEVELS: Record<Preset, { label: string; description: string }> = {
  read: { label: "Read", description: "Pull images" },
  write: { label: "Write", description: "Pull, push, delete tags and run scans" },
  admin: { label: "Admin", description: "Everything, including settings, permissions and deleting the repository" },
}

export const TEAM_ROLES: Record<TeamRole, { label: string; description: string }> = {
  member: { label: "Member", description: "Access only through repository grants and the team's base permission." },
  creator: { label: "Creator", description: "Member, plus can create new repositories in the organization and administers what it creates." },
  admin: { label: "Admin", description: "Full access to every repository. Manages teams, members, robots and settings." },
}

const actionLabel = (a: Action) => ACTION_LABELS[a] ?? a

function levelLabel(l: Level) {
  if (isPreset(l)) return LEVELS[l].label
  const n = levelActions(l).length
  return `Custom (${n})`
}

function levelTitle(l: Level) {
  return isPreset(l) ? LEVELS[l].description : levelActions(l).map(actionLabel).join(", ")
}

export function LevelBadge({ level, className }: { level: Level; className?: string }) {
  return <span className={cn("chip", level === "admin" ? "bg-foreground/10 text-foreground" : level !== "read" && "text-foreground", className)} title={levelTitle(level)}>{levelLabel(level)}</span>
}

/** Pick any mix of repository actions. */
function CustomLevelDialog({ initial, onSave, onClose }: { initial: Action[]; onSave: (l: Level) => void; onClose: () => void }) {
  const perms = useQuery({ queryKey: ["permissions"], queryFn: endpoints.permissions, staleTime: Infinity })
  const [picked, setPicked] = useState<Action[]>(initial.filter((a) => a !== "admin"))
  // Admin covers everything, so it is offered only as the preset.
  const actions = (perms.data?.actions ?? []).filter((a) => a.name !== "admin")
  const toggle = (a: Action, on: boolean) => setPicked((p) => (on ? [...p, a] : p.filter((x) => x !== a)))
  const save = () => {
    const set = new Set(picked)
    const preset = (Object.keys(PRESETS) as Preset[]).find((k) => k !== "admin" && PRESETS[k].length === set.size && PRESETS[k].every((a) => set.has(a)))
    onSave(preset ?? actions.filter((a) => set.has(a.name)).map((a) => a.name).join(","))
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Custom access</DialogTitle>
          <DialogDescription>Choose exactly what is allowed. Docker logins get the matching pull, push and delete rights.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-1">
          {actions.map((a) => (
            <label key={a.name} className="flex cursor-pointer items-start gap-3 rounded-md px-2 py-1.5 hover:bg-accent/50">
              <Checkbox className="mt-0.5" checked={picked.includes(a.name)} onCheckedChange={(c) => toggle(a.name, !!c)} />
              <span className="text-sm">
                <span className="font-medium">{actionLabel(a.name)}</span>
                <span className="block text-muted-foreground">{a.description}</span>
              </span>
            </label>
          ))}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={picked.length === 0} onClick={save}>Save</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Level picker. `allowNone` adds a "No access" option (value null); `allowCustom` adds "Custom...". */
export function LevelSelect({ value, onChange, allowNone, allowCustom, noneLabel = "No access", className }: { value: Level | null; onChange: (v: Level | null) => void; allowNone?: boolean; allowCustom?: boolean; noneLabel?: string; className?: string }) {
  const [custom, setCustom] = useState(false)
  // A custom value never equals the "custom" item, so choosing it again reopens the editor.
  const current = value === null ? "none" : isPreset(value) ? value : "custom-current"
  return (
    <>
      <Select value={current} onValueChange={(v) => (v === "custom" ? setCustom(true) : onChange(v === "none" ? null : (v as Level)))}>
        <SelectTrigger className={cn("w-36", className)} title={value ? levelTitle(value) : undefined}>
          <SelectValue>{value === null ? noneLabel : levelLabel(value)}</SelectValue>
        </SelectTrigger>
        <SelectContent className="max-w-72">
          {allowNone && <SelectItem value="none">{noneLabel}</SelectItem>}
          {(Object.keys(LEVELS) as Preset[]).map((l) => (
            <SelectItem key={l} value={l}>
              <span className="flex flex-col">{LEVELS[l].label}<span className="text-xs text-muted-foreground">{LEVELS[l].description}</span></span>
            </SelectItem>
          ))}
          {allowCustom && <><SelectSeparator /><SelectItem value="custom">
            <span className="flex flex-col">{current === "custom-current" ? "Edit custom..." : "Custom..."}<span className="text-xs text-muted-foreground">Pick individual actions</span></span>
          </SelectItem></>}
        </SelectContent>
      </Select>
      {custom && <CustomLevelDialog initial={value ? levelActions(value) : ["pull"]} onClose={() => setCustom(false)} onSave={(l) => { setCustom(false); onChange(l) }} />}
    </>
  )
}
