import { Link } from "react-router"
import { ArrowLeftIcon } from "lucide-react"
import { Fragment, type ReactNode } from "react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError } from "@/lib/api"

/** "← Parent" above a detail page's header: one step up, where a breadcrumb would repeat the title. */
export function BackLink({ to, label }: { to: string; label: ReactNode }) {
  return (
    <Link to={to} className="group -mb-4 inline-flex w-fit max-w-full items-center gap-1.5 text-[13px] text-muted-foreground transition-colors hover:text-foreground">
      <ArrowLeftIcon className="size-3.5 shrink-0 transition-transform group-hover:-translate-x-0.5" />
      <span className="truncate">{label}</span>
    </Link>
  )
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error)
  const status = error instanceof ApiError ? error.status : undefined
  return (
    <Alert variant="destructive">
      <AlertTitle>{status ? `Error ${status}` : "Error"}</AlertTitle>
      <AlertDescription>{msg}</AlertDescription>
    </Alert>
  )
}

/** Varied widths, so placeholder rows read as text rather than bars. */
const WIDTHS = ["w-[38%]", "w-[52%]", "w-[30%]", "w-[45%]", "w-[34%]", "w-[48%]"]
const SUB_WIDTHS = ["w-[24%]", "w-[18%]", "w-[30%]", "w-[22%]", "w-[27%]", "w-[16%]"]

/** Placeholder list rows in the shape of the app's lists: an icon, a title, a detail line and a
 *  meta value on the right. Shows only once loading has taken a moment. */
export function Loading({ rows = 4 }: { rows?: number }) {
  return (
    <div role="status" aria-label="Loading" className="placeholder-in divide-y divide-border/60">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-3 py-3 first:pt-1 last:pb-1">
          <Skeleton className="size-8 shrink-0 rounded-md" />
          <div className="min-w-0 flex-1 space-y-2">
            <Skeleton className={`h-3.5 ${WIDTHS[i % WIDTHS.length]}`} />
            <Skeleton className={`h-3 opacity-60 ${SUB_WIDTHS[i % SUB_WIDTHS.length]}`} />
          </div>
          <Skeleton className="h-3 w-14 shrink-0 opacity-60" />
        </div>
      ))}
    </div>
  )
}


export function KV({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
      {items.filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => (
        <Fragment key={k}>
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="break-all">{v}</dd>
        </Fragment>
      ))}
    </dl>
  )
}

export const Mono = ({ children, className = "" }: { children: ReactNode; className?: string }) => (
  <span className={`font-mono text-xs ${className}`}>{children}</span>
)
