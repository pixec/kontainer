import { CheckIcon, ChevronDownIcon, CopyIcon, SearchIcon } from "lucide-react"
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react"
import { NavLink } from "react-router"
import { cn } from "@/lib/utils"
import { ActiveBox, HoverPill } from "@/components/ui/sliding"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

export function PageHeader({ title, description, actions, badge, meta, icon, className }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; badge?: ReactNode; meta?: ReactNode; icon?: ReactNode; className?: string }) {
  return (
    <div className={cn("space-y-2", className)}>
      {/* Title and actions share one row so controls line up with the heading, not the subtitle. */}
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-3">
        <h1 className="flex min-w-0 flex-wrap items-center gap-2.5 text-2xl font-semibold leading-10 tracking-tight break-all">{icon && <span className="text-muted-foreground [&_svg]:size-5">{icon}</span>}{title}{badge}</h1>
        {actions && <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto sm:flex-nowrap">{actions}</div>}
      </div>
      {description && <p className="max-w-3xl text-[15px] leading-relaxed text-pretty text-muted-foreground">{description}</p>}
      {meta && <div className="text-xs text-muted-foreground">{meta}</div>}
    </div>
  )
}

/** GitHub "Box": bordered container with an optional subtle header. */
export function Panel({ children, className, padded, title, description, actions, icon, id }: { children: ReactNode; className?: string; padded?: boolean; title?: ReactNode; description?: ReactNode; actions?: ReactNode; icon?: ReactNode; id?: string }) {
  return (
    <section id={id} className={cn("overflow-hidden rounded-lg border bg-card", className)}>
      {(title || actions) && (
        <header className="flex min-h-12 flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
          <div className="space-y-0.5">
            <h2 className="flex items-center gap-2 text-sm font-semibold">{icon && <span className="text-muted-foreground [&_svg]:size-4">{icon}</span>}{title}</h2>
            {description && <p className="text-xs text-muted-foreground">{description}</p>}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn(padded && "p-4")}>{children}</div>
    </section>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="px-4 py-12 text-center text-sm text-muted-foreground">{children}</div>
}

/** Definition grid: muted label above value. */
export function Facts({ items, columns = 4, className }: { items: { label: string; value: ReactNode; mono?: boolean }[]; columns?: 2 | 3 | 4 | 6; className?: string }) {
  const cols = { 2: "sm:grid-cols-2", 3: "sm:grid-cols-3", 4: "sm:grid-cols-2 lg:grid-cols-4", 6: "sm:grid-cols-3 lg:grid-cols-6" }[columns]
  return (
    <dl className={cn("grid grid-cols-2 gap-x-6 gap-y-4", cols, className)}>
      {items.filter((i) => i.value !== undefined && i.value !== null && i.value !== "").map((i) => (
        <div key={i.label} className="min-w-0">
          <dt className="text-xs text-muted-foreground">{i.label}</dt>
          <dd className={cn("mt-0.5 truncate text-sm", i.mono && "font-mono text-xs")}>{i.value}</dd>
        </div>
      ))}
    </dl>
  )
}

export function CopyField({ value, label, wrap }: { value: string; label?: string; wrap?: boolean }) {
  const [done, setDone] = useState(false)
  const copy = async () => { try { await navigator.clipboard.writeText(value); setDone(true); setTimeout(() => setDone(false), 1500) } catch { /* ignore */ } }
  return (
    <div className="space-y-1">
      {label && <div className="text-xs text-muted-foreground">{label}</div>}
      <div className={cn("flex gap-1 rounded-lg border bg-muted pl-3 pr-1", wrap ? "items-start py-1" : "items-center")}>
        <code className={cn("min-w-0 flex-1 py-1.5 font-mono text-xs", wrap ? "break-all leading-5" : "truncate")}>{value}</code>
        <button type="button" onClick={copy} className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground" title="Copy">{done ? <CheckIcon className="size-3.5 text-success" /> : <CopyIcon className="size-3.5" />}</button>
      </div>
    </div>
  )
}

export function Secret({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-md border border-success/40 bg-success/10 p-3 text-sm space-y-2">
      <p className="font-medium">{label}</p>
      <CopyField value={value} />
      <p className="text-xs text-muted-foreground">{hint ?? "Copy it now; it will not be shown again."}</p>
    </div>
  )
}

/** GitHub settings-style left navigation inside a page. */
export function SideNav({ items, className }: { items: { label: string; to: string; exact?: boolean; icon?: ReactNode }[]; className?: string }) {
  const bar = useRef<HTMLElement>(null)
  return (
    // Icons sit on the content edge (pills hang into the margin, like the tab bars), and the first
    // label is level with the section heading beside it.
    <nav ref={bar} className={cn("relative w-full shrink-0 space-y-1 lg:-mt-1.5 lg:-ml-3 lg:w-56", className)}>
      <ActiveBox bar={bar} />
      <HoverPill bar={bar} />
      {items.map((it) => <SideNavLink key={it.to} {...it} />)}
    </nav>
  )
}

function SideNavLink({ label, to, exact, icon }: { label: string; to: string; exact?: boolean; icon?: ReactNode }) {
  return (
    <NavLink to={to} end={exact} data-tab-item="" className={({ isActive }) => cn(
      "group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors focus-visible:bg-accent",
      isActive ? "text-foreground" : "text-muted-foreground hover:text-foreground")}>
      {({ isActive }) => <>
        {icon && <span className={cn("[&_svg]:size-5", isActive ? "text-foreground" : "text-muted-foreground group-hover:text-foreground")}>{icon}</span>}{label}
      </>}
    </NavLink>
  )
}

/** Search box; pressing "/" anywhere on the page focuses it. */
/** `placeholder` may be rich (e.g. a namespace in mono); it is drawn over the empty input and
 *  `label` gives screen readers the plain text. */
export function SearchInput({ value, onChange, placeholder, label, className }: { value: string; onChange: (v: string) => void; placeholder?: ReactNode; label?: string; className?: string }) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement
      if (e.key !== "/" || t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName)) return
      e.preventDefault()
      ref.current?.focus()
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])
  return (
    <div className={cn("relative w-full sm:w-80", className)}>
      <SearchIcon className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input ref={ref} value={value} onChange={(e) => onChange(e.target.value)} aria-label={label ?? (typeof placeholder === "string" ? placeholder : undefined)}
        placeholder={typeof placeholder === "string" ? placeholder : undefined} className="pl-9" />
      {typeof placeholder !== "string" && placeholder && !value && (
        <span className="pointer-events-none absolute inset-y-0 left-9 right-3 flex items-center truncate text-sm text-muted-foreground">{placeholder}</span>
      )}
    </div>
  )
}

/** Gravatar when available (the URL 404s without one), otherwise the first letter. */
export function Avatar({ name, src, className }: { name: string; src?: string | null; className?: string }) {
  const [failed, setFailed] = useState<string | null>(null)
  return (
    <span className={cn("flex size-8 shrink-0 items-center justify-center overflow-hidden rounded-full border bg-secondary text-xs font-semibold uppercase", className)}>
      {src && failed !== src ? <img src={src} alt="" className="size-full object-cover" onError={() => setFailed(src)} /> : name[0]}
    </span>
  )
}

/** Initial on a tile whose hue is derived from the namespace, so each org is recognisable. */
export function OrgMark({ name, label, className }: { name: string; label: string; className?: string }) {
  let h = 0
  for (const c of name) h = (h * 31 + c.charCodeAt(0)) % 360
  return (
    <span className={cn("flex size-11 shrink-0 items-center justify-center rounded-lg text-base font-semibold uppercase text-white ring-1 ring-inset ring-white/10", className)}
      style={{ background: `linear-gradient(135deg, oklch(0.42 0.09 ${h}), oklch(0.24 0.05 ${(h + 50) % 360}))` }}>
      {label[0]}
    </span>
  )
}

/** Settings section, Tailwind UI style: heading and description on the left, fields on the right. */
const Stacked = createContext(false)

/** Next to a side nav there is no room for a heading column: sections inside stack instead. */
export function StackedSections({ children }: { children: ReactNode }) {
  return <Stacked.Provider value>{children}</Stacked.Provider>
}

export function FormSection({ title, description, children, className }: { title: ReactNode; description?: ReactNode; children: ReactNode; className?: string }) {
  const stacked = useContext(Stacked)
  return (
    <section className={cn(
      "grid gap-x-10 gap-y-5",
      // Stacked: the column spaces blocks out; a divider only between two sections, as wide as the content.
      stacked ? "max-w-2xl [section+&]:border-t [section+&]:pt-8" : "border-b py-8 first:pt-0 last:border-b-0 md:grid-cols-[minmax(0,18rem)_minmax(0,1fr)]",
      className,
    )}>
      <div>
        <h2 className={cn("font-semibold", stacked ? "text-base" : "text-sm/6")}>{title}</h2>
        {description && <p className="mt-1 text-sm/6 text-muted-foreground">{description}</p>}
      </div>
      <div className="min-w-0 max-w-2xl">{children}</div>
    </section>
  )
}

/** Save/cancel row under FormSections: lines up with the field column, not the page edge. */
export function FormActions({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("grid gap-x-10 border-b pb-8 md:grid-cols-[minmax(0,18rem)_minmax(0,1fr)]", className)}>
      <div className="flex max-w-2xl flex-wrap items-center justify-end gap-3 md:col-start-2">{children}</div>
    </div>
  )
}

/** Row inside a destructive FormSection: explanation and the action button. */
export function DangerRow({ title, description, action }: { title: ReactNode; description: ReactNode; action: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg p-4 ring-1 ring-destructive/30">
      <div className="min-w-0">
        <p className="text-sm font-medium">{title}</p>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      {action}
    </div>
  )
}

/** Menu button reading "Label: Value ▾" that opens a checked list, GitHub-style. */
export function LabeledSelect<T extends string>({ label, value, onChange, options, className }: { label: string; value: T; onChange: (v: T) => void; options: Record<T, string> | [T, string][]; className?: string }) {
  const entries = Array.isArray(options) ? options : (Object.entries(options) as [T, string][])
  const current = entries.find(([k]) => k === value)?.[1] ?? (value || "Choose...")
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="lg" className={cn("justify-between gap-2 font-normal data-[state=open]:bg-accent", className)}>
          <span className="truncate"><span className="text-muted-foreground">{label}:</span> <span className="font-medium">{current}</span></span>
          <ChevronDownIcon className="text-muted-foreground transition-transform in-data-[state=open]:rotate-180" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-52">
        <DropdownMenuLabel>{label}</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={value} onValueChange={(v) => onChange(v as T)}>
          {entries.map(([k, l]) => <DropdownMenuRadioItem key={k} value={k}>{l}</DropdownMenuRadioItem>)}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** Label/value list for sidebar Details cards. */
export function DetailList({ children }: { children: ReactNode }) {
  return <dl className="space-y-2.5 text-sm">{children}</dl>
}
export function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <dt className="shrink-0 text-muted-foreground">{label}</dt>
      <dd className="flex min-w-0 items-center justify-end gap-2 truncate">{children}</dd>
    </div>
  )
}

/** Short value with a copy button for the full one; for digests in Details rows. */
export function CopyInline({ value, display }: { value: string; display?: string }) {
  const [done, setDone] = useState(false)
  const copy = async () => { try { await navigator.clipboard.writeText(value); setDone(true); setTimeout(() => setDone(false), 1500) } catch { /* ignore */ } }
  return (
    <button type="button" onClick={copy} title={`Copy ${value}`} className="group inline-flex min-w-0 items-center gap-1.5 font-mono text-xs hover:text-foreground">
      <span className="truncate">{display ?? value}</span>
      {done ? <CheckIcon className="size-3.5 shrink-0 text-success" /> : <CopyIcon className="size-3.5 shrink-0 text-muted-foreground group-hover:text-foreground" />}
    </button>
  )
}

/** Header for a repository or organization: big mark, name, description, actions on the right. */
export function EntityHeader({ mark, title, aside, description, onAddDescription, actions }: {
  mark: ReactNode; title: ReactNode; aside?: ReactNode; description?: string | null; onAddDescription?: () => void; actions?: ReactNode
}) {
  return (
    <header className="flex flex-wrap items-start gap-4 sm:flex-nowrap sm:gap-5">
      {mark}
      <div className="min-w-0 flex-1 space-y-1.5">
        <h1 className="flex flex-wrap items-baseline gap-x-2 text-2xl font-semibold tracking-tight">
          <span className="break-all">{title}</span>
          {aside && <span className="font-mono text-sm font-normal text-muted-foreground">{aside}</span>}
        </h1>
        {description
          ? <p className="text-[15px] text-muted-foreground">{description}</p>
          : onAddDescription && <button type="button" onClick={onAddDescription} className="text-sm text-muted-foreground hover:text-foreground hover:underline">+ Add a description</button>}
      </div>
      {actions && <div className="shrink-0">{actions}</div>}
    </header>
  )
}
export const ENTITY_MARK = "size-14 rounded-lg text-xl sm:size-20 sm:text-2xl"
