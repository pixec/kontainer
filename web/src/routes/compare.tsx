import { useQuery } from "@tanstack/react-query"
import { Link, useParams, useSearchParams } from "react-router"
import { ArrowRightIcon, GitCompareIcon, LayersIcon, SlidersHorizontalIcon, TagIcon } from "lucide-react"
import { cleanCommand, endpoints, formatBytes, shortDigest, type CompareSide } from "@/lib/api"
import { relativeTime } from "@/lib/time"
import { BackLink, ErrorBox, Loading } from "@/components/ui-bits"
import { Empty, LabeledSelect, PageHeader, Panel } from "@/components/page"
import { cn } from "@/lib/utils"

const LAYER_STYLE = {
  shared: { sign: " ", cls: "text-muted-foreground", label: "Shared" },
  changed: { sign: "~", cls: "text-warning", label: "Changed: same step, rebuilt with different content" },
  moved: { sign: "↕", cls: "text-warning", label: "Moved" },
  removed: { sign: "−", cls: "text-destructive", label: "Removed" },
  added: { sign: "+", cls: "text-success", label: "Added" },
} as const

function delta(n: number) {
  if (n === 0) return "no change"
  return `${n > 0 ? "+" : "−"}${formatBytes(Math.abs(n))}`
}

export function ComparePage() {
  const { "*": rest = "" } = useParams()
  const name = rest.replace(/\/compare$/, "")
  const [params, setParams] = useSearchParams()
  const a = params.get("a") ?? ""
  const b = params.get("b") ?? ""
  const platform = params.get("platform") ?? ""
  const tags = useQuery({ queryKey: ["tags", name], queryFn: () => endpoints.tags(name) })
  const q = useQuery({ queryKey: ["compare", name, a, b, platform], queryFn: () => endpoints.compare(name, a, b, platform || undefined), enabled: !!a && !!b })
  const set = (k: string, v: string) => { const next = new URLSearchParams(params); next.set(k, v); setParams(next, { replace: true }) }
  const choices = (tags.data ?? []).filter((t) => !t.attached_to && (t.artifact.kind === "image" || t.artifact.kind === "index"))
  const platforms = [...new Set(choices.find((t) => t.tag === a)?.platforms.map((p) => p.platform).filter((p): p is string => !!p) ?? [])]

  return (
    <>
      <BackLink to={`/r/${name}`} label={name} />
      <PageHeader icon={<GitCompareIcon />} title="Compare images" />
      <div className="flex flex-wrap items-center gap-2">
        <LabeledSelect label="Base" value={a} onChange={(v) => set("a", v)} options={choices.map((t) => [t.tag, t.tag] as [string, string])} />
        <ArrowRightIcon className="size-4 text-muted-foreground" />
        <LabeledSelect label="Compare" value={b} onChange={(v) => set("b", v)} options={choices.map((t) => [t.tag, t.tag] as [string, string])} />
        {platforms.length > 1 && (
          <LabeledSelect label="Platform" value={platform || q.data?.a.platform || ""} onChange={(v) => set("platform", v)} options={platforms.map((p) => [p, p] as [string, string])} />
        )}
      </div>
      {(!a || !b) && <Panel><Empty>Choose two tags to compare.</Empty></Panel>}
      {q.isLoading && <Loading />}
      {q.error && <ErrorBox error={q.error} />}
      {q.data && (
        <>
          <div className="grid gap-4 md:grid-cols-[1fr_auto_1fr]">
            <SideCard side={q.data.a} name={name} />
            <div className="flex flex-col items-center justify-center gap-1 px-2 text-center">
              <span className={cn("text-lg font-semibold tabular-nums", q.data.size_delta > 0 ? "text-warning" : q.data.size_delta < 0 && "text-success")}>{delta(q.data.size_delta)}</span>
              <span className="text-xs text-muted-foreground">{formatBytes(q.data.shared_bytes)} shared</span>
            </div>
            <SideCard side={q.data.b} name={name} />
          </div>

          <Panel icon={<SlidersHorizontalIcon />} title="Configuration" actions={<span className="text-xs text-muted-foreground">{q.data.changes.length === 0 ? "Identical" : `${q.data.changes.length} ${q.data.changes.length === 1 ? "difference" : "differences"}`}</span>}>
            {q.data.changes.length > 0 && (
              <ul className="divide-y">
                {q.data.changes.map((c) => (
                  <li key={c.field} className="grid gap-1 px-4 py-2.5 text-sm md:grid-cols-[14rem_1fr_1fr] md:gap-4">
                    <span className="font-medium">{c.field}</span>
                    <span className={cn("break-all font-mono text-xs", c.before ? "text-destructive" : "text-muted-foreground")}>{c.before ? `− ${c.before}` : "not set"}</span>
                    <span className={cn("break-all font-mono text-xs", c.after ? "text-success" : "text-muted-foreground")}>{c.after ? `+ ${c.after}` : "not set"}</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel icon={<LayersIcon />} title="Layers" actions={<span className="text-xs text-muted-foreground">{(["changed", "added", "removed", "moved", "shared"] as const).map((s) => [s, q.data.layers.filter((l) => l.status === s).length] as const).filter(([s, n]) => n > 0 || s === "shared").map(([s, n]) => `${n} ${s}`).join(" · ")}</span>}>
            <ul className="divide-y font-mono text-xs">
              {q.data.layers.map((l, i) => {
                const st = LAYER_STYLE[l.status]
                return (
                  <li key={`${l.digest}-${i}`} className={cn("flex items-center gap-3 px-4 py-2", l.status === "added" && "bg-success/5", l.status === "removed" && "bg-destructive/5", l.status === "changed" && "bg-warning/5")}>
                    <span className={cn("w-3 shrink-0 text-center font-bold", st.cls)} title={st.label}>{st.sign}</span>
                    <span className="min-w-0 flex-1 truncate" title={l.created_by ?? undefined}>{l.created_by ? cleanCommand(l.created_by) : <span className="text-muted-foreground">{shortDigest(l.digest)}</span>}</span>
                    <span className="shrink-0 text-muted-foreground tabular-nums">{l.previous_size !== undefined ? `${formatBytes(l.previous_size)} → ${formatBytes(l.size)}` : formatBytes(l.size)}</span>
                  </li>
                )
              })}
            </ul>
          </Panel>
        </>
      )}
    </>
  )
}

function SideCard({ side, name }: { side: CompareSide; name: string }) {
  return (
    <Panel icon={<TagIcon />} title={<Link to={`/r/${name}/m/${encodeURIComponent(side.reference)}`} className="hover:underline">{side.reference}</Link>}
      actions={<span className="font-mono text-xs text-muted-foreground">{shortDigest(side.digest)}{side.platform && ` · ${side.platform}`}</span>} padded>
      <dl className="grid grid-cols-3 gap-2 text-sm">
        <div><dt className="text-xs text-muted-foreground">Size</dt><dd className="tabular-nums">{formatBytes(side.size)}</dd></div>
        <div><dt className="text-xs text-muted-foreground">Layers</dt><dd className="tabular-nums">{side.layers}</dd></div>
        <div><dt className="text-xs text-muted-foreground">Built</dt><dd>{side.created ? relativeTime(side.created) : "—"}</dd></div>
      </dl>
    </Panel>
  )
}
