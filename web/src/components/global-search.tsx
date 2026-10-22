import { keepPreviousData, useQuery } from "@tanstack/react-query"
import { useEffect, useMemo, useRef, useState } from "react"
import { useNavigate } from "react-router"
import { ArrowRightIcon, BoxIcon, SearchIcon } from "lucide-react"
import { endpoints } from "@/lib/api"
import { useSession } from "@/lib/session"
import { cn } from "@/lib/utils"

type Hit = { name: string; description: string; isPublic: boolean }

export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value)
  useEffect(() => { const t = setTimeout(() => setV(value), ms); return () => clearTimeout(t) }, [value, ms])
  return v
}

/** Navbar search over every repository the viewer can see: their own plus public ones.
 *  ⌘K / Ctrl+K focuses it; arrows move, Enter opens, Escape closes. */
export function GlobalSearch({ className, autoFocus, onNavigate }: { className?: string; autoFocus?: boolean; onNavigate?: () => void }) {
  const { me } = useSession()
  const navigate = useNavigate()
  const [q, setQ] = useState("")
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const input = useRef<HTMLInputElement>(null)
  const box = useRef<HTMLDivElement>(null)
  // Server-side, ranked full-text search (tantivy). Debounced so typing doesn't flood it.
  const needle = useDebounced(q.trim(), 150)
  const results = useQuery({ queryKey: ["search", needle], queryFn: () => endpoints.search(needle), enabled: open && !!needle, placeholderData: keepPreviousData })
  // With an empty box, offer the caller's own repositories.
  const mine = useQuery({ queryKey: ["repositories"], queryFn: endpoints.repositories, enabled: !!me?.username && open && !needle })
  const hits: Hit[] = useMemo(() => needle
    ? (results.data ?? []).map((r) => ({ name: r.name, description: r.description, isPublic: r.visibility === "public" }))
    : (mine.data ?? []).slice(0, 8).map((r) => ({ name: r.name, description: r.description, isPublic: r.visibility === "public" })),
  [needle, results.data, mine.data])
  // Results, then a final "search in Explore" row.
  const count = hits.length + (needle ? 1 : 0)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); input.current?.focus(); setOpen(true) }
    }
    const onClick = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false) }
    window.addEventListener("keydown", onKey)
    window.addEventListener("mousedown", onClick)
    return () => { window.removeEventListener("keydown", onKey); window.removeEventListener("mousedown", onClick) }
  }, [])
  useEffect(() => setActive(0), [q])

  const go = (i: number) => {
    const target = i < hits.length ? `/r/${hits[i].name}` : `/explore?q=${encodeURIComponent(q.trim())}`
    setOpen(false); setQ(""); input.current?.blur(); onNavigate?.()
    navigate(target)
  }
  const mac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform)

  return (
    <div ref={box} className={cn("relative", className)}>
      <SearchIcon className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
      <input ref={input} value={q} autoFocus={autoFocus} role="combobox" aria-expanded={open} aria-controls="global-search-results"
        placeholder={`Search repositories (${mac ? "⌘" : "Ctrl+"}K)`}
        onChange={(e) => { setQ(e.target.value); setOpen(true) }}
        onFocus={() => setOpen(true)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, count - 1)) }
          else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)) }
          else if (e.key === "Enter" && count > 0) { e.preventDefault(); go(active) }
          else if (e.key === "Escape") { setOpen(false); input.current?.blur() }
        }}
        className="h-9 w-full rounded-lg border border-input bg-card pl-9 pr-3 text-sm outline-none placeholder:text-muted-foreground hover:border-ring focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/30" />
      {open && (
        <div id="global-search-results" role="listbox" className="absolute right-0 top-full z-50 mt-2 w-full origin-top-right overflow-hidden rounded-lg bg-popover p-1 text-popover-foreground shadow-md ring-1 ring-foreground/10 duration-100 animate-in fade-in-0 zoom-in-95 slide-in-from-top-2 md:w-[max(100%,30rem)]">
          {hits.length === 0 && !needle && <p className="px-3 py-6 text-center text-sm text-muted-foreground">{mine.isLoading ? "Loading..." : "Type to search every repository you can see."}</p>}
          {hits.length === 0 && needle && !results.isFetching && <p className="px-3 pt-3 pb-1 text-xs text-muted-foreground">No repositories match.</p>}
          {hits.map((h, i) => (
            <button key={h.name} type="button" role="option" aria-selected={i === active} onMouseEnter={() => setActive(i)} onClick={() => go(i)}
              className={cn("flex w-full items-center gap-3 rounded-md px-2.5 py-2 text-left", i === active && "bg-accent")}>
              <BoxIcon className="size-4 shrink-0 text-muted-foreground" />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm">{h.name}</span>
                {h.description && <span className="block truncate text-xs text-muted-foreground">{h.description}</span>}
              </span>
              {h.isPublic && <span className="chip">Public</span>}
            </button>
          ))}
          {!needle && (
            <p className="mt-1 border-t px-2.5 pt-2 pb-1 text-xs text-muted-foreground">
              Try <span className="font-mono text-foreground">amd64 alpine</span>, <span className="font-mono text-foreground">arch:arm64</span>, <span className="font-mono text-foreground">kind:helm</span>, <span className="font-mono text-foreground">ns:acme</span> or <span className="font-mono text-foreground">is:public</span>
            </p>
          )}
          {needle && (
            <button type="button" role="option" aria-selected={active === hits.length} onMouseEnter={() => setActive(hits.length)} onClick={() => go(hits.length)}
              className={cn("mt-1 flex w-full items-center gap-3 rounded-md border-t px-2.5 py-2 text-left text-sm text-muted-foreground", active === hits.length && "bg-accent text-foreground")}>
              <SearchIcon className="size-4 shrink-0" />
              <span className="min-w-0 flex-1 truncate">Search public images for “{q.trim()}”</span>
              <ArrowRightIcon className="size-4" />
            </button>
          )}
        </div>
      )}
    </div>
  )
}
