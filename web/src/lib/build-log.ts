/**
 * Turns a build log into steps for display. The log has our own phases (`==> Fetching ...`)
 * and, inside "Building", the builder's output: classic Docker (`Step 2/4 : RUN ...`) or
 * BuildKit's plain progress (`#5 [2/3] RUN ...`, `#5 DONE 0.3s`).
 */

export type StepStatus = "done" | "running" | "failed" | "cached" | "pending"

export interface Step {
  title: string
  lines: string[]
  status: StepStatus
  /** From BuildKit's `DONE 1.2s`. */
  seconds?: number
  /** The Dockerfile stage a builder step belongs to (`builder`, or "" for an unnamed one). */
  stage?: string
  children: Step[]
}

export interface ParsedLog {
  steps: Step[]
  /** The final `==> ...` line: the build's outcome (summary or error). */
  outcome: string | null
}

const PHASE = /^==> (.*)$/
const DOCKER_STEP = /^Step (\d+)\/(\d+) : (.*)$/
const BK_LINE = /^#(\d+) (.*)$/
const BK_TITLE = /^\[(.+?)\] (.*)$/

/** `buildStatus` is the build's status, to tell a running last step from a failed one. */
export function parseBuildLog(log: string, buildStatus: string): ParsedLog {
  const lines = log.replace(/\n$/, "").split("\n")
  const finished = !["queued", "running"].includes(buildStatus)
  // The last `==>` line of a finished build is its outcome, not a step.
  let outcomeAt = -1
  if (finished) {
    for (let i = lines.length - 1; i >= 0; i--) {
      if (PHASE.test(lines[i])) { outcomeAt = i; break }
      if (lines[i].trim()) break
    }
  }
  const steps: Step[] = []
  const preamble: string[] = []
  let phase: Step | null = null
  let dockerStep: Step | null = null
  // Classic Docker output names no stages: each `FROM` starts one.
  let dockerStage = ""
  let dockerStages = 0
  const bk = new Map<string, Step>()

  lines.forEach((line, i) => {
    // BuildKit separates steps with blank lines; the graph shows the separation instead.
    if (i === outcomeAt || !line.trim()) return
    const p = line.match(PHASE)
    if (p) {
      phase = { title: p[1], lines: [], status: "done", children: [] }
      steps.push(phase)
      dockerStep = null
      bk.clear()
      return
    }
    if (!phase) { if (line.trim()) preamble.push(line); return }
    const d = line.match(DOCKER_STEP)
    if (d) {
      const from = d[3].match(/^FROM\s+\S+(?:\s+AS\s+(\S+))?/i)
      if (from) dockerStage = from[1] ?? (dockerStages++ === 0 ? "" : `stage-${dockerStages - 1}`)
      dockerStep = { title: d[3], lines: [], status: "done", stage: dockerStage, children: [] }
      phase.children.push(dockerStep)
      return
    }
    const b = line.match(BK_LINE)
    if (b) {
      const [, id, rest] = b
      let s = bk.get(id)
      if (!s) {
        const t = rest.match(BK_TITLE)
        // BuildKit's housekeeping steps (`[internal] load ...`) are noise.
        // `[builder 2/4]` → stage "builder"; `[2/4]` → the unnamed stage; `[internal]` → none.
        const where = t?.[1].match(/^(?:(.+?)\s+)?\d+\/\d+$/)
        s = { title: t ? (t[1] === "internal" ? rest : t[2]) : rest, lines: [], status: "running", stage: where ? (where[1] ?? "") : undefined, children: [] }
        if (t?.[1] === "internal" || rest.startsWith("[auth]")) s.title = `· ${s.title}`
        bk.set(id, s)
        phase.children.push(s)
        return
      }
      if (/^DONE\b/.test(rest)) { s.status = "done"; s.seconds = Number(rest.split(/\s+/)[1]?.replace(/s$/, "")) || undefined; return }
      if (rest === "CACHED") { s.status = "cached"; return }
      if (/^ERROR\b/.test(rest)) { s.status = "failed"; s.lines.push(rest); return }
      // `#5 0.123 output`: drop BuildKit's elapsed-time column.
      s.lines.push(rest.replace(/^\d+\.\d+ /, ""))
      return
    }
    ;(dockerStep ?? phase).lines.push(line)
  })

  // Docker's legacy-builder warning and similar chatter before the first phase.
  if (preamble.length && steps[0]) steps[0].lines.unshift(...preamble)

  // The last step is still going, or is where the build stopped.
  const last = steps.at(-1)
  if (last) {
    const lastChild = last.children.at(-1)
    if (!finished) {
      last.status = "running"
      if (lastChild && lastChild.status !== "cached") lastChild.status = lastChild.status === "done" && lastChild.seconds !== undefined ? "done" : "running"
    } else if (buildStatus !== "succeeded") {
      last.status = "failed"
      // Where it stopped: the step BuildKit reported an error for, else the last real one.
      if (!last.children.some((c) => c.status === "failed")) {
        const at = last.children.findLast((c) => c.status !== "cached")
        if (at) at.status = "failed"
      }
    }
  }
  // BuildKit steps never seen to finish, in a build that succeeded, did finish.
  if (buildStatus === "succeeded") for (const s of steps) for (const c of s.children) if (c.status === "running") c.status = "done"
  return { steps, outcome: outcomeAt >= 0 ? lines[outcomeAt].replace(PHASE, "$1") : null }
}

export type StageKey = "source" | "build" | "publish"

/** One box of the pipeline: a group of phases. */
export interface Stage {
  key: StageKey
  label: string
  status: StepStatus
  /** One line under the label: the commit, the step count, the tags. */
  summary: string
  steps: Step[]
}

const STAGE_OF: [RegExp, StageKey][] = [
  [/^(Fetching|Fetched|Commit\b|Tags\b|The image (will|won't) be tagged)/, "source"],
  [/^(Building|Waiting for BuildKit)/, "build"],
  [/^(Importing|Uploading|Pushed)/, "publish"],
]

/** Group a parsed log into Source → Build → Publish, with a status and summary for each. */
export function stagesOf(parsed: ParsedLog, buildStatus: string): Stage[] {
  const stages: Stage[] = [
    { key: "source", label: "Source", status: "pending", summary: "", steps: [] },
    { key: "build", label: "Build", status: "pending", summary: "", steps: [] },
    { key: "publish", label: "Publish", status: "pending", summary: "", steps: [] },
  ]
  let at = 0
  for (const step of parsed.steps) {
    const match = STAGE_OF.find(([re]) => re.test(step.title))
    // Anything unrecognised belongs with what came before it.
    if (match) at = stages.findIndex((s) => s.key === match[1])
    stages[at].steps.push(step)
  }
  const finished = !["queued", "running"].includes(buildStatus)
  const lastWithSteps = stages.reduce((n, s, i) => (s.steps.length ? i : n), -1)
  stages.forEach((s, i) => {
    if (s.steps.some((x) => x.status === "failed")) s.status = "failed"
    else if (s.steps.some((x) => x.status === "running")) s.status = "running"
    else if (s.steps.length) s.status = "done"
    // A finished build that didn't succeed stopped in its last stage with output.
    if (finished && buildStatus !== "succeeded" && i === lastWithSteps && s.status !== "failed") s.status = buildStatus === "cancelled" ? "pending" : "failed"
    if (finished && buildStatus === "succeeded") s.status = "done"
  })

  const source = stages[0]
  const fetched = source.steps.map((s) => s.title.match(/^Fetched commit (\w+)(?::\s*(.*))?$/) ?? s.title.match(/^Commit (\w{7})\w*$/)).find(Boolean)
  const tagged = source.steps.map((s) => s.title.match(/^(?:The image will be tagged|Tags) (.+)$/)).find(Boolean)
  source.summary = fetched ? [fetched[1].slice(0, 7), fetched[2]].filter(Boolean).join(" · ") : source.status === "running" ? "Fetching..." : ""
  const build = stages[1]
  const children = build.steps.flatMap((s) => s.children).filter((c) => !c.title.startsWith("·"))
  const seconds = children.reduce((sum, c) => sum + (c.seconds ?? 0), 0)
  const cached = children.filter((c) => c.status === "cached").length
  build.summary = children.length
    ? [`${children.length} ${children.length === 1 ? "step" : "steps"}`, cached && `${cached} cached`, seconds >= 0.1 && `${seconds.toFixed(1)}s`].filter(Boolean).join(" · ")
    : build.status === "running" ? "Starting..." : ""
  const publish = stages[2]
  const untagged = source.steps.some((s) => s.title.startsWith("The image won't be tagged"))
  publish.summary = buildStatus === "succeeded" ? (tagged ? tagged[1] : untagged ? "Untagged · by digest" : "Pushed") : publish.status === "running" ? "Uploading..." : ""
  return stages
}


/** A box in the build graph. */
export interface GraphNode {
  id: string
  label: string
  status: StepStatus
  /** Right-aligned, muted: a duration or a count. */
  meta: string
  col: number
  row: number
  /** What to show when the box is selected. */
  steps: Step[]
  kind: "source" | "stage" | "publish"
}

export interface BuildGraph {
  nodes: GraphNode[]
  edges: [string, string][]
  cols: number
  rows: number
  /** e.g. `docker/Dockerfile · BuildKit`. */
  title: string
}

const statusOf = (steps: Step[], fallback: StepStatus): StepStatus =>
  steps.some((s) => s.status === "failed") ? "failed"
  : steps.some((s) => s.status === "running") ? "running"
  : steps.length && steps.every((s) => s.status === "cached") ? "cached"
  : steps.length ? "done" : fallback

/**
 * Lay the build out as a graph: Source → the Dockerfile's stages (wired by `COPY --from=` and
 * `FROM <stage>`, so independent stages sit side by side) → Publish.
 */
export function buildGraph(parsed: ParsedLog, buildStatus: string): BuildGraph {
  const [source, build, publish] = stagesOf(parsed, buildStatus)
  const steps = build.steps.flatMap((s) => s.children).filter((c) => c.stage !== undefined)
  // Stages in the order they first appear; the last is what gets built.
  const names: string[] = []
  for (const s of steps) if (!names.includes(s.stage!)) names.push(s.stage!)
  const deps = new Map<string, Set<string>>(names.map((n) => [n, new Set()]))
  for (const s of steps) {
    const from = s.title.match(/--from=(\S+)/i)?.[1] ?? s.title.match(/^FROM\s+(\S+)/i)?.[1]
    if (from && from !== s.stage && deps.has(from)) deps.get(s.stage!)!.add(from)
  }
  const col = new Map<string, number>()
  const depth = (n: string, seen = new Set<string>()): number => {
    if (col.has(n)) return col.get(n)!
    if (seen.has(n)) return 1
    seen.add(n)
    const d = 1 + Math.max(0, ...[...deps.get(n)!].map((x) => depth(x, seen)))
    col.set(n, d)
    return d
  }
  names.forEach((n) => depth(n))
  const nodes: GraphNode[] = []
  const perCol = new Map<number, number>()
  const place = (c: number) => { const r = perCol.get(c) ?? 0; perCol.set(c, r + 1); return r }
  const fmt = (secs: number) => (secs >= 60 ? `${Math.floor(secs / 60)}m ${Math.round(secs % 60)}s` : `${secs.toFixed(1)}s`)
  nodes.push({ id: "source", label: "Source", status: source.status, meta: source.summary, col: 0, row: place(0), steps: source.steps, kind: "source" })
  for (const n of names) {
    const mine = steps.filter((s) => s.stage === n)
    const secs = mine.reduce((sum, s) => sum + (s.seconds ?? 0), 0)
    const c = col.get(n)!
    nodes.push({
      id: `stage:${n}`, label: n || (names.length > 1 ? "stage-0" : "Dockerfile"), status: statusOf(mine, build.status),
      meta: secs >= 0.1 ? fmt(secs) : `${mine.length} ${mine.length === 1 ? "step" : "steps"}`, col: c, row: place(c), steps: mine, kind: "stage",
    })
  }
  if (!names.length) nodes.push({ id: "stage:", label: "Build", status: build.status, meta: build.summary, col: 1, row: place(1), steps: build.steps, kind: "stage" })
  const last = Math.max(1, ...nodes.map((n) => n.col)) + 1
  nodes.push({ id: "publish", label: "Publish", status: publish.status, meta: publish.summary, col: last, row: place(last), steps: publish.steps, kind: "publish" })

  const edges: [string, string][] = []
  const stageIds = names.length ? names : [""]
  for (const n of stageIds) {
    const d = deps.get(n)
    if (!d || d.size === 0) edges.push(["source", `stage:${n}`])
    else for (const x of d) edges.push([`stage:${x}`, `stage:${n}`])
  }
  edges.push([`stage:${stageIds[stageIds.length - 1]}`, "publish"])
  const building = build.steps.map((s) => s.title.match(/^Building (.+?) with (.+)$/)).find(Boolean)
  return { nodes, edges, cols: last + 1, rows: Math.max(...perCol.values()), title: building ? `${building[1]} · ${building[2]}` : "" }
}
