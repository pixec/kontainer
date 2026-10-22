import { useQuery } from "@tanstack/react-query"
import { useEffect, useState, type ReactNode } from "react"
import { Link, useSearchParams } from "react-router"
import { ArrowRightIcon, CheckIcon, ContainerIcon, CopyIcon, DatabaseIcon, SearchIcon, StarIcon, TagIcon, UploadIcon } from "lucide-react"
import { NodeField } from "@/components/node-field"
import { useSession } from "@/lib/session"
import { endpoints, type ExploreEntry } from "@/lib/api"
import { formatDate, relativeTime } from "@/lib/time"
import { ErrorBox, Loading } from "@/components/ui-bits"
import { Empty, LabeledSelect, OrgMark } from "@/components/page"
import { cn } from "@/lib/utils"

type Sort = "stars" | "pushed" | "name"
const SORTS: Record<Sort, string> = { stars: "Most starred", pushed: "Recently pushed", name: "Name" }

/** `linux/arm64` → `arm64`; other OSes keep their prefix. */
const arch = (p: string) => (p.startsWith("linux/") ? p.slice(6) : p)
const pushed = (r: ExploreEntry) => r.latest.pushed_at ?? r.updated_at

export function ExplorePage() {
  const [params] = useSearchParams()
  const [q, setQ] = useState(() => params.get("q") ?? "")
  // The navbar search sends people here with ?q=; follow later changes too.
  useEffect(() => { const v = params.get("q"); if (v !== null) setQ(v) }, [params])
  const [topic, setTopic] = useState<string | null>(null)
  const [platform, setPlatform] = useState<string | null>(null)
  const [sort, setSort] = useState<Sort>("stars")
  const query = useQuery({ queryKey: ["explore", q, topic], queryFn: () => endpoints.explore(q, topic ?? undefined) })
  const all = query.data?.repositories ?? []
  const platforms = [...new Set(all.flatMap((r) => r.latest.platforms.map(arch)))].sort()
  const repos = all
    .filter((r) => !platform || r.latest.platforms.some((p) => arch(p) === platform))
    .sort((a, b) => sort === "stars" ? b.stars - a.stars || a.name.localeCompare(b.name) : sort === "pushed" ? pushed(b).localeCompare(pushed(a)) : a.name.localeCompare(b.name))
  const { me } = useSession()
  const [browse, setBrowse] = useState(() => params.has("all"))
  const filtering = !!(q || topic || platform)
  const showResults = filtering || browse
  // The landing columns use the unfiltered set (the query above is unfiltered when q/topic are empty).
  const byStars = [...all].sort((a, b) => b.stars - a.stars || a.name.localeCompare(b.name))
  const byPushed = [...all].sort((a, b) => pushed(b).localeCompare(pushed(a)))
  const byCreated = [...all].sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""))
  return (
    <>
      {showResults ? (
        <section className="mx-auto mb-8 flex max-w-5xl flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Explore</h1>
            <p className="text-sm text-muted-foreground">Public images anyone can pull without signing in.</p>
          </div>
          <div className="w-full sm:max-w-sm"><HeroSearch value={q} onChange={setQ} compact /></div>
        </section>
      ) : (
      <section className="relative -mx-4 -mt-6 overflow-hidden px-4 pt-16 pb-14 sm:-mx-6 sm:-mt-8 sm:px-6 sm:pt-24 sm:pb-16 lg:-mx-10 lg:-mt-10 lg:px-10">
        <NodeField className="pointer-events-none absolute inset-0 size-full opacity-50 [mask-image:radial-gradient(ellipse_at_center,transparent_25%,black_75%)]" />
        <div className="relative mx-auto flex max-w-2xl flex-col items-center text-center">
          <span className="flex size-14 items-center justify-center rounded-2xl border bg-card shadow-lg"><ContainerIcon className="size-7" /></span>
          <h1 className="mt-6 text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            <span className="text-muted-foreground">The</span> open-source <span className="text-muted-foreground">container registry</span>
          </h1>
          <p className="mt-4 max-w-xl text-pretty text-muted-foreground sm:text-lg">Browse public images. Anyone can pull them without signing in.</p>
          <HeroSearch value={q} onChange={setQ} />
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            {me?.username
              ? <Link to="/" className="inline-flex h-10 items-center gap-2 rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary/90"><DatabaseIcon className="size-4" />Your repositories</Link>
              : me?.auth_mode !== "none" && <Link to="/login" className="inline-flex h-10 items-center gap-2 rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary/90"><UploadIcon className="size-4" />Sign in to push</Link>}
            <CopyCommand value={`docker login ${location.host}`} />
          </div>
        </div>
      </section>
      )}

      {!showResults && all.length > 0 && (
        <section className="grid gap-6 md:grid-cols-3">
          <Column title="Most starred" repos={byStars} meta={(r) => <span className="flex items-center gap-1 tabular-nums"><StarIcon className="size-3.5" />{r.stars}</span>} />
          <Column title="Recently pushed" repos={byPushed} meta={(r) => r.latest.tag && <span className="chip font-mono text-foreground">{r.latest.tag}</span>} />
          <Column title="New" repos={byCreated} meta={(r) => r.created_at && <span>{relativeTime(r.created_at)}</span>} />
          <div className="flex justify-center md:col-span-3">
            <button type="button" onClick={() => setBrowse(true)} className="inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground">
              Browse all {all.length} {all.length === 1 ? "image" : "images"}<ArrowRightIcon className="size-4" />
            </button>
          </div>
        </section>
      )}
      {!showResults && query.data && all.length === 0 && (
        <div className="rounded-lg border border-dashed"><Empty>No public images yet. Repository admins can make one public in its settings.</Empty></div>
      )}

      {showResults && (
        <div id="explore-results" className="mx-auto min-w-0 max-w-5xl scroll-mt-32 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="mr-auto flex items-baseline gap-2 text-base font-semibold">
              {filtering ? "Results" : "All images"}
              {query.data && <span className="text-sm font-normal text-muted-foreground tabular-nums">{repos.length}</span>}
              {filtering && <button type="button" onClick={() => { setQ(""); setTopic(null); setPlatform(null) }} className="text-sm font-normal text-muted-foreground hover:text-foreground hover:underline">Clear filters</button>}
            </h2>
            {platforms.length > 1 && (
              <LabeledSelect label="Platform" value={platform ?? ""} onChange={(v) => setPlatform(v || null)} className="w-full sm:w-auto"
                options={[["", "Any"] as [string, string], ...platforms.map((p) => [p, p] as [string, string])]} />
            )}
            <LabeledSelect label="Sort" value={sort} onChange={setSort} options={SORTS} className="w-full sm:w-auto" />
          </div>
          {query.data && query.data.topics.length > 0 && (
            <div className="-mx-4 flex gap-1.5 overflow-x-auto px-4 pb-1 sm:mx-0 sm:flex-wrap sm:px-0">
              {query.data.topics.map((t) => <MobileChip key={t} active={topic === t} onClick={() => setTopic(topic === t ? null : t)}>{t}</MobileChip>)}
            </div>
          )}
          {query.isLoading && <Loading />}
          {query.error && <ErrorBox error={query.error} />}
          {query.data && repos.length === 0 && (
            <div className="rounded-lg border border-dashed"><Empty>{filtering ? "No public images match these filters." : "No public images yet. Repository admins can make one public in its settings."}</Empty></div>
          )}
          {repos.length > 0 && <div className="divide-y overflow-hidden rounded-lg border bg-card">{repos.map((r) => <ExploreRow key={r.name} repo={r} />)}</div>}
          {!filtering && (
            <button type="button" onClick={() => setBrowse(false)} className="text-sm text-muted-foreground hover:text-foreground hover:underline">← Back to highlights</button>
          )}
        </div>
      )}
    </>
  )
}

function HeroSearch({ value, onChange, compact }: { value: string; onChange: (v: string) => void; compact?: boolean }) {
  return (
    <form className={cn("w-full", !compact && "mt-8")} onSubmit={(e) => { e.preventDefault(); document.getElementById("explore-results")?.scrollIntoView({ behavior: "smooth" }) }}>
      <div className={cn("flex w-full items-center overflow-hidden border bg-card focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/30", compact ? "h-10 rounded-lg" : "h-12 rounded-xl shadow-lg")}>
        <SearchIcon className={cn("shrink-0 text-muted-foreground", compact ? "ml-3 size-4" : "ml-4 size-5")} />
        <input value={value} onChange={(e) => onChange(e.target.value)} placeholder="Search public images..." aria-label="Search public images"
          className={cn("h-full min-w-0 flex-1 bg-transparent px-3 outline-none placeholder:text-muted-foreground", compact ? "text-sm" : "text-base")} />
        {!compact && <button type="submit" className="mr-1.5 inline-flex h-9 items-center rounded-lg bg-secondary px-3 text-sm font-medium hover:bg-accent">Search</button>}
      </div>
    </form>
  )
}

function CopyCommand({ value }: { value: string }) {
  const [done, setDone] = useState(false)
  return (
    <button type="button" onClick={() => navigator.clipboard.writeText(value).then(() => { setDone(true); setTimeout(() => setDone(false), 1500) }).catch(() => {})}
      className="inline-flex h-10 items-center gap-2.5 rounded-lg border bg-card px-3.5 font-mono text-sm text-muted-foreground transition-colors hover:border-ring hover:text-foreground" title="Copy">
      <span className="text-muted-foreground/60">$</span>{value}{done ? <CheckIcon className="size-4 text-success" /> : <CopyIcon className="size-4" />}
    </button>
  )
}

/** Landing column: a titled stack of compact rows, JSR style. */
function Column({ title, repos, meta }: { title: string; repos: ExploreEntry[]; meta: (r: ExploreEntry) => ReactNode }) {
  return (
    <section className="min-w-0">
      <h2 className="mb-3 text-base font-semibold">{title}</h2>
      <div className="divide-y overflow-hidden rounded-lg border bg-card">
        {repos.slice(0, 5).map((r) => (
          <Link key={r.name} to={`/r/${r.name}`} className="flex items-center gap-3 px-4 py-3 transition-colors hover:bg-accent">
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-medium">{r.name}</span>
              <span className="block truncate text-xs text-muted-foreground">{r.description || `${r.tags} ${r.tags === 1 ? "tag" : "tags"}`}</span>
            </span>
            <span className="shrink-0 text-xs text-muted-foreground">{meta(r)}</span>
          </Link>
        ))}
      </div>
    </section>
  )
}

function MobileChip({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active}
      className={cn("inline-flex h-8 shrink-0 items-center gap-1 rounded-full border px-3 text-xs font-medium transition-colors",
        active ? "border-foreground/30 bg-foreground/10 text-foreground" : "text-muted-foreground")}>
      {active && <CheckIcon className="size-3" />}{children}
    </button>
  )
}

function ExploreRow({ repo: r }: { repo: ExploreEntry }) {
  const cut = r.name.lastIndexOf("/")
  const owner = cut > 0 ? r.name.slice(0, cut) : ""
  const short = r.name.slice(cut + 1)
  const plats = r.latest.platforms.map(arch)
  const SHOWN = 3
  return (
    <Link to={`/r/${r.name}`} className="group flex items-center gap-4 px-4 py-3.5 transition-colors hover:bg-accent/50">
      <OrgMark name={owner || short} label={short} className="size-10 shrink-0 rounded-lg text-sm" />
      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-baseline gap-1.5">
          {owner && <span className="truncate text-sm text-muted-foreground">{owner}/</span>}
          <span className="truncate font-medium group-hover:underline">{short}</span>
          {r.topics.slice(0, 2).map((t) => <span key={t} className="chip hidden shrink-0 md:inline-flex">{t}</span>)}
        </div>
        <div className="mt-0.5 flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
          {r.description
            ? <span className="truncate">{r.description}</span>
            : r.latest.tag ? <span className="shrink-0">Latest <span className="font-mono text-foreground">{r.latest.tag}</span></span> : <span>No tags yet</span>}
          {plats.length > 0 && (
            <span className="hidden min-w-0 truncate font-mono sm:inline" title={plats.join(", ")}>
              · {plats.slice(0, SHOWN).join(", ")}{plats.length > SHOWN && ` +${plats.length - SHOWN}`}
            </span>
          )}
        </div>
      </div>
      <div className="hidden shrink-0 items-center gap-4 text-xs text-muted-foreground sm:flex">
        <span className="flex items-center gap-1" title="Stars"><StarIcon className="size-3.5" /><span className="tabular-nums">{r.stars}</span></span>
        <span className="flex items-center gap-1" title="Tags"><TagIcon className="size-3.5" /><span className="tabular-nums">{r.tags}</span></span>
        <span className="w-24 text-right" title={formatDate(pushed(r))}>{relativeTime(pushed(r))}</span>
        <CopyPull name={r.name} tag={r.latest.tag} />
      </div>
    </Link>
  )
}

function CopyPull({ name, tag }: { name: string; tag: string | null }) {
  const [done, setDone] = useState(false)
  return (
    <button type="button" title="Copy pull command"
      onClick={(e) => {
        e.preventDefault(); e.stopPropagation()
        navigator.clipboard.writeText(`docker pull ${location.host}/${name}${tag ? `:${tag}` : ""}`).then(() => { setDone(true); setTimeout(() => setDone(false), 1500) }).catch(() => {})
      }}
      aria-label="Copy pull command"
      className={cn("inline-flex size-7 items-center justify-center rounded-md transition-colors hover:bg-accent hover:text-foreground", done ? "opacity-100" : "opacity-0 group-hover:opacity-100 focus-visible:opacity-100")}>
      {done ? <CheckIcon className="size-3.5 text-success" /> : <CopyIcon className="size-3.5" />}
    </button>
  )
}
