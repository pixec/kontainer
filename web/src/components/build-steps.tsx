import { useEffect, useMemo, useRef, useState } from "react"
import { CheckIcon, ChevronRightIcon, CircleDotIcon, GitCommitHorizontalIcon, LayersIcon, Loader2Icon, PackageIcon, XIcon, ZapIcon } from "lucide-react"
import { buildGraph, parseBuildLog, type BuildGraph, type GraphNode, type Step, type StepStatus } from "@/lib/build-log"
import { cn } from "@/lib/utils"

/**
 * A build as a graph, GitHub Actions style: Source → each Dockerfile stage (wired by
 * `COPY --from=`, so stages BuildKit runs in parallel sit side by side) → Publish. Click a box
 * to see its steps underneath; a running or failed box is selected unless you pick another.
 */
export function BuildSteps({ log, status }: { log: string; status: string }) {
  const parsed = useMemo(() => parseBuildLog(log, status), [log, status])
  const graph = useMemo(() => buildGraph(parsed, status), [parsed, status])
  const [raw, setRaw] = useState(false)
  const [picked, setPicked] = useState<string | null>(null)
  if (!log) return <p className="rounded-md border bg-background p-3 text-xs text-muted-foreground">{status === "queued" ? "Waiting for a free build agent..." : "No output yet."}</p>
  const attention = graph.nodes.find((n) => n.status === "running" || n.status === "failed")
  const selected = graph.nodes.find((n) => n.id === picked) ?? attention ?? graph.nodes.find((n) => n.kind === "stage") ?? graph.nodes[0]
  const showOutcome = !!parsed.outcome && (selected.kind === "publish" || (status !== "succeeded" && selected.id === attention?.id))
  return (
    <div className="space-y-3">
      <GraphCanvas graph={graph} selected={selected.id} onSelect={setPicked} />
      {raw ? <RawLog text={log} follow={status === "running"} /> : (
        <div className="rounded-md border bg-background">
          <div className="flex items-center justify-between border-b px-4 py-2 text-xs text-muted-foreground">
            <span>{selected.kind === "stage" ? `Stage ${selected.label}` : selected.kind === "source" ? "Source" : "Publish"}{selected.steps.length === 0 && (status === "running" ? ": not started yet" : ": didn't run")}</span>
            <button type="button" onClick={() => setRaw(true)} className="hover:text-foreground hover:underline">Raw log</button>
          </div>
          {(selected.steps.length > 0 || showOutcome) && (
            <ol className="py-2">
              {selected.steps.map((s, i) => <StepNode key={i} step={s} small={selected.kind === "stage" && s.stage !== undefined} last={i === selected.steps.length - 1 && !showOutcome} />)}
              {showOutcome && <Outcome text={parsed.outcome!} status={status} />}
            </ol>
          )}
        </div>
      )}
      {raw && <button type="button" onClick={() => setRaw(false)} className="text-xs text-muted-foreground hover:text-foreground hover:underline">Back to the graph</button>}
    </div>
  )
}

const CARD_W = 216
const CARD_H = 52
const COL_GAP = 64
const ROW_GAP = 16
const PAD = 20

const EDGE: Record<StepStatus, string> = { done: "stroke-emerald-500/50", cached: "stroke-emerald-500/50", running: "stroke-amber-500/70", failed: "stroke-destructive/60", pending: "stroke-border" }
const NODE_ICON = { source: GitCommitHorizontalIcon, stage: LayersIcon, publish: PackageIcon }

function GraphCanvas({ graph, selected, onSelect }: { graph: BuildGraph; selected: string; onSelect: (id: string) => void }) {
  const pos = (n: GraphNode) => ({ x: PAD + n.col * (CARD_W + COL_GAP), y: PAD + 24 + n.row * (CARD_H + ROW_GAP) })
  const byId = new Map(graph.nodes.map((n) => [n.id, n]))
  const width = PAD * 2 + graph.cols * CARD_W + (graph.cols - 1) * COL_GAP
  const height = PAD * 2 + 24 + graph.rows * CARD_H + (graph.rows - 1) * ROW_GAP
  return (
    <div className="overflow-x-auto rounded-lg border bg-[radial-gradient(var(--border)_1px,transparent_1px)] [background-size:14px_14px]">
      <div className="relative" style={{ width, height }}>
        {graph.title && <div className="absolute font-mono text-xs text-muted-foreground" style={{ left: PAD, top: PAD - 4 }}>{graph.title}</div>}
        <svg className="pointer-events-none absolute inset-0" width={width} height={height} aria-hidden>
          {graph.edges.map(([a, b]) => {
            const from = byId.get(a), to = byId.get(b)
            if (!from || !to) return null
            const s = pos(from), e = pos(to)
            const [sx, sy, ex, ey] = [s.x + CARD_W, s.y + CARD_H / 2, e.x, e.y + CARD_H / 2]
            const mx = sx + COL_GAP / 2
            const r = Math.min(8, Math.abs(ey - sy) / 2)
            const dir = ey > sy ? 1 : -1
            // An elbow: across, round the corner, down (or up), round again, across.
            const d = sy === ey ? `M${sx},${sy} H${ex}` : `M${sx},${sy} H${mx - r} Q${mx},${sy} ${mx},${sy + dir * r} V${ey - dir * r} Q${mx},${ey} ${mx + r},${ey} H${ex}`
            const status = to.status === "pending" ? "pending" : from.status
            return (
              <g key={`${a}-${b}`} className={cn("fill-none", EDGE[status], to.status === "running" && "animate-pulse")}>
                <path d={d} strokeWidth={1.5} strokeDasharray={status === "pending" ? "4 4" : undefined} />
                <circle cx={sx} cy={sy} r={2.5} className="fill-background" strokeWidth={1.5} />
                <circle cx={ex} cy={ey} r={2.5} className="fill-background" strokeWidth={1.5} />
              </g>
            )
          })}
        </svg>
        {graph.nodes.map((n) => {
          const { x, y } = pos(n)
          const Icon = NODE_ICON[n.kind]
          return (
            <button key={n.id} type="button" onClick={() => onSelect(n.id)} aria-pressed={selected === n.id} title={n.meta ? `${n.label} · ${n.meta}` : n.label}
              className={cn("absolute flex items-center gap-2 rounded-md border bg-card px-2.5 text-left shadow-sm transition-colors hover:border-ring",
                selected === n.id && "border-ring ring-2 ring-ring/30", n.status === "pending" && "border-dashed bg-background text-muted-foreground")}
              style={{ left: x, top: y, width: CARD_W, height: CARD_H }}>
              <StatusDot status={n.status} small />
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-1.5 text-sm font-medium"><Icon className="size-3.5 shrink-0 text-muted-foreground" /><span className="truncate">{n.label}</span></span>
                <span className="block truncate text-xs tabular-nums text-muted-foreground">{n.meta || (n.status === "pending" ? "Waiting" : "\u00a0")}</span>
              </span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

function StatusDot({ status, small }: { status: StepStatus; small?: boolean }) {
  const size = small ? "size-4" : "size-5"
  const icon = small ? "size-2.5" : "size-3"
  const ring = "flex shrink-0 items-center justify-center rounded-full"
  switch (status) {
    case "done": return <span className={cn(ring, size, "bg-emerald-500/15 text-emerald-500")}><CheckIcon className={icon} strokeWidth={3} /></span>
    case "cached": return <span className={cn(ring, size, "bg-foreground/10 text-muted-foreground")} title="Cached"><ZapIcon className={icon} /></span>
    case "running": return <span className={cn(ring, size, "bg-amber-500/15 text-amber-500")}><Loader2Icon className={cn(icon, "animate-spin")} /></span>
    case "failed": return <span className={cn(ring, size, "bg-destructive/15 text-destructive")}><XIcon className={icon} strokeWidth={3} /></span>
    default: return <span className={cn(ring, size, "text-muted-foreground")}><CircleDotIcon className={icon} /></span>
  }
}

/** One node of the graph: a dot on the line, a title, and its output when opened. */
function StepNode({ step, last, small }: { step: Step; last: boolean; small?: boolean }) {
  // Open what needs attention (running or failed) until the user says otherwise.
  const attention = step.status === "running" || step.status === "failed"
  const [chosen, setOpen] = useState<boolean | null>(null)
  const open = chosen ?? attention
  // Child steps (the Dockerfile's) are part of the graph and always shown; only output folds.
  const hasBody = step.lines.length > 0
  return (
    <li className={cn("relative", small ? "pl-9" : "pl-10")}>
      {/* The line to the next node. */}
      {!last && <span aria-hidden className={cn("absolute top-6 bottom-0 w-px bg-border", small ? "left-[1.47rem]" : "left-[1.53rem]")} />}
      <button type="button" disabled={!hasBody} onClick={() => setOpen(!open)}
        className={cn("group flex w-full items-center gap-2 py-1.5 pr-3 text-left", hasBody && "hover:text-foreground")}>
        <span className={cn("absolute", small ? "left-4" : "left-4")}><StatusDot status={step.status} small={small} /></span>
        <span className={cn("min-w-0 flex-1 truncate", small ? "font-mono text-xs" : "text-sm", step.status === "cached" && "text-muted-foreground")} title={step.title}>{step.title}</span>
        {step.seconds !== undefined && <span className="shrink-0 text-xs tabular-nums text-muted-foreground">{step.seconds.toFixed(1)}s</span>}
        {step.status === "cached" && <span className="shrink-0 text-xs text-muted-foreground">cached</span>}
        {hasBody && <ChevronRightIcon className={cn("size-3.5 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")} />}
      </button>
      {open && hasBody && <div className="pb-1"><RawLog text={step.lines.join("\n")} follow={step.status === "running"} compact /></div>}
      {step.children.length > 0 && (
        <ol className="-ml-6 pb-1">
          {step.children.map((c, i) => <StepNode key={i} step={c} last={i === step.children.length - 1} small />)}
        </ol>
      )}
    </li>
  )
}

function Outcome({ text, status }: { text: string; status: string }) {
  const ok = status === "succeeded"
  return (
    <li className="relative pl-10">
      <span className="absolute left-4 top-1.5"><StatusDot status={ok ? "done" : status === "cancelled" ? "pending" : "failed"} /></span>
      <p className={cn("py-1.5 pr-3 text-sm font-medium", ok ? "text-emerald-500" : status === "cancelled" ? "text-muted-foreground" : "text-destructive")}>{text}</p>
    </li>
  )
}

function RawLog({ text, follow, compact }: { text: string; follow?: boolean; compact?: boolean }) {
  const pre = useRef<HTMLPreElement>(null)
  useEffect(() => { if (follow && pre.current) pre.current.scrollTop = pre.current.scrollHeight }, [text, follow])
  return (
    <pre ref={pre} className={cn("overflow-auto whitespace-pre-wrap break-all font-mono text-xs leading-5 text-muted-foreground", compact ? "mr-3 mb-1 max-h-64 rounded bg-muted/40 px-3 py-2" : "max-h-96 rounded-md border bg-background p-3")}>{text}</pre>
  )
}
