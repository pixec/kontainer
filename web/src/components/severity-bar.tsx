import { Link } from "react-router"
import type { ScanBrief, Severity } from "@/lib/api"
import { cn } from "@/lib/utils"

const ORDER: Severity[] = ["critical", "high", "medium", "low", "unknown"]
const COLOR: Record<Severity, string> = {
  critical: "bg-red-800 text-white",
  high: "bg-red-600 text-white",
  medium: "bg-orange-500 text-black",
  low: "bg-amber-300 text-black",
  negligible: "bg-neutral-500 text-white",
  unknown: "bg-[repeating-linear-gradient(45deg,oklch(0.35_0_0),oklch(0.35_0_0)_4px,oklch(0.28_0_0)_4px,oklch(0.28_0_0)_8px)] text-white",
}

/** Docker Hub-style segmented severity counts. */
export function SeverityBar({ scan, to, className }: { scan?: ScanBrief | null; to?: string; className?: string }) {
  if (!scan) return <span className={cn("text-xs text-muted-foreground", className)}>not scanned</span>
  if (scan.status !== "done") return <span className={cn("text-xs text-muted-foreground capitalize", className)}>{scan.status}...</span>
  const counts = ORDER.map((s) => [s, (scan.summary[s] ?? 0) + (s === "unknown" ? scan.summary.negligible ?? 0 : 0)] as const).filter(([, n]) => n > 0)
  if (counts.length === 0) return <span className={cn("inline-flex items-center rounded-sm bg-success/15 px-2 py-0.5 text-xs font-medium text-success", className)}>No vulnerabilities</span>
  const bar = (
    <span className={cn("inline-flex overflow-hidden rounded-sm text-xs font-semibold tabular-nums", className)}>
      {counts.map(([s, n]) => <span key={s} title={s} className={cn("px-2.5 py-0.5", COLOR[s])}>{n}</span>)}
    </span>
  )
  return to ? <Link to={to} className="hover:opacity-90">{bar}</Link> : bar
}
