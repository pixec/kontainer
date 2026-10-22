import { Badge } from "@/components/ui/badge"
import { SEVERITIES, type ScanBrief, type Severity } from "@/lib/api"
import { cn } from "@/lib/utils"

const COLORS: Record<Severity, string> = {
  critical: "bg-red-700 text-white border-transparent",
  high: "bg-orange-600 text-white border-transparent",
  medium: "bg-yellow-500 text-black border-transparent",
  low: "bg-blue-600 text-white border-transparent",
  negligible: "bg-neutral-500 text-white border-transparent",
  unknown: "bg-neutral-400 text-white border-transparent",
}

export function SeverityBadge({ severity, count, className }: { severity: Severity; count?: number; className?: string }) {
  return (
    <Badge className={cn(COLORS[severity], className)} title={severity}>
      {count !== undefined ? `${count} ` : ""}{count !== undefined ? severity[0].toUpperCase() : severity}
    </Badge>
  )
}

export function ScanSummary({ scan }: { scan?: ScanBrief }) {
  if (!scan) return <span className="text-muted-foreground text-sm">not scanned</span>
  if (scan.status !== "done") return <Badge variant={scan.status === "failed" ? "destructive" : "secondary"}>{scan.status}</Badge>
  if (!scan.total) return <Badge variant="success">clean</Badge>
  return (
    <span className="flex flex-wrap gap-1">
      {SEVERITIES.filter((s) => scan.summary[s]).map((s) => (
        <SeverityBadge key={s} severity={s} count={scan.summary[s]} />
      ))}
    </span>
  )
}
