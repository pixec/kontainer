import { keepPreviousData, useQueries, useQuery } from "@tanstack/react-query"
import { useEffect, useRef, useState } from "react"
import { BotIcon, SearchIcon, UsersIcon } from "lucide-react"
import { useDebounced } from "@/components/global-search"
import { Avatar } from "@/components/page"
import { endpoints, type DirectoryEntry } from "@/lib/api"
import { cn } from "@/lib/utils"

export type PrincipalKind = "user" | "robot" | "team"

type Hit = DirectoryEntry & { kind: PrincipalKind }

const PLACEHOLDER: Record<PrincipalKind, string> = { user: "Search people by username or name", robot: "Pick a robot", team: "Pick a team" }

/** Combobox for people, robots and teams (`kinds`: one or several, results are merged). People
 *  are searched on the server; robots and teams are the namespace's own, filtered as you type.
 *  `exclude` hides names that already have access. */
export function PrincipalPicker({ kinds, namespace, value, onChange, onPick, exclude = [], placeholder, size = "default", className }: {
  kinds: PrincipalKind[]
  namespace: string
  value: string
  onChange: (v: string) => void
  onPick: (v: string, kind: PrincipalKind) => void
  exclude?: string[]
  placeholder?: string
  size?: "default" | "sm"
  className?: string
}) {
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const box = useRef<HTMLDivElement>(null)
  const needle = useDebounced(value.trim(), 150)
  const lower = value.trim().toLowerCase()
  const wantsPeople = kinds.includes("user")
  const people = useQuery({
    queryKey: ["directory", "user", needle],
    queryFn: () => endpoints.directory("user", needle),
    enabled: open && wantsPeople && needle.length > 0,
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  })
  const others = useQueries({
    queries: kinds.filter((k) => k !== "user").map((k) => ({
      queryKey: ["directory", k, "", namespace],
      queryFn: () => endpoints.directory(k, "", namespace),
      enabled: open,
      staleTime: 30_000,
    })),
  })
  const local: Hit[] = kinds.filter((k) => k !== "user").flatMap((k, i) => (others[i]?.data ?? []).map((e) => ({ ...e, kind: k })))
    .filter((e) => !lower || e.name.toLowerCase().includes(lower) || e.display_name?.toLowerCase().includes(lower))
  const found: Hit[] = wantsPeople && needle ? (people.data ?? []).map((e) => ({ ...e, kind: "user" as const })) : []
  const hits = [...found, ...local].filter((e) => !exclude.includes(e.name))
  const loading = people.isFetching || others.some((o) => o.isLoading)

  useEffect(() => {
    const onClick = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false) }
    window.addEventListener("mousedown", onClick)
    return () => window.removeEventListener("mousedown", onClick)
  }, [])

  const pick = (e: Hit) => { onChange(e.name); onPick(e.name, e.kind); setOpen(false) }
  const empty = loading ? "Searching..."
    : wantsPeople && !needle && local.length === 0 ? "Type a username or name."
    : kinds.length === 1 && kinds[0] !== "user" && (others[0]?.data ?? []).length === 0 ? `No ${kinds[0]}s in ${namespace} yet.`
    : "No one matches."
  const sm = size === "sm"

  return (
    <div ref={box} className={cn("relative", className)}>
      <SearchIcon className={cn("pointer-events-none absolute top-1/2 -translate-y-1/2 text-muted-foreground", sm ? "left-2.5 size-3.5" : "left-3 size-4")} />
      <input value={value} role="combobox" aria-expanded={open} aria-controls="principal-picker" aria-autocomplete="list" autoComplete="off"
        placeholder={placeholder ?? (kinds.length === 1 ? PLACEHOLDER[kinds[0]] : "Search people or robots")}
        onChange={(e) => { onChange(e.target.value); setActive(0); setOpen(true) }}
        onFocus={() => setOpen(true)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive((a) => Math.min(a + 1, hits.length - 1)) }
          else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)) }
          else if (e.key === "Enter" && open && hits[active]) { e.preventDefault(); pick(hits[active]) }
          else if (e.key === "Escape") setOpen(false)
        }}
        className={cn("w-full rounded-lg border border-input bg-card pr-3 text-sm outline-none placeholder:text-muted-foreground hover:border-ring/70 focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/30", sm ? "h-8 pl-8" : "h-10 pl-9")} />
      {open && (
        <div id="principal-picker" role="listbox" className="absolute left-0 top-full z-50 mt-2 max-h-72 w-full min-w-64 origin-top overflow-y-auto rounded-lg bg-popover p-1 text-popover-foreground shadow-md ring-1 ring-foreground/10 duration-100 animate-in fade-in-0 zoom-in-95 slide-in-from-top-2">
          {hits.length === 0 && <p className="px-3 py-4 text-center text-sm text-muted-foreground">{empty}</p>}
          {hits.map((e, i) => {
            const Icon = e.kind === "team" ? UsersIcon : BotIcon
            return (
              <button key={`${e.kind}:${e.name}`} type="button" role="option" aria-selected={i === active} onMouseEnter={() => setActive(i)} onMouseDown={(ev) => ev.preventDefault()} onClick={() => pick(e)}
                className={cn("flex w-full items-center gap-3 rounded-md px-2.5 py-1.5 text-left", i === active && "bg-accent")}>
                {e.kind === "user"
                  ? <Avatar name={e.name} src={e.avatar_url} className="size-7" />
                  : <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-secondary text-muted-foreground"><Icon className="size-4" /></span>}
                <span className="min-w-0 flex-1">
                  <span className={cn("block truncate text-sm", e.kind === "robot" && "font-mono text-[13px]")}>{e.name}</span>
                  {e.display_name && <span className="block truncate text-xs text-muted-foreground">{e.display_name}</span>}
                </span>
                {kinds.length > 1 && e.kind !== "user" && <span className="chip capitalize">{e.kind}</span>}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
