import { Link } from "react-router"
import { CheckCircle2Icon, CircleAlertIcon, CopyIcon, DatabaseZapIcon, FileArchiveIcon, ImportIcon } from "lucide-react"
import { type RepoOrigin } from "@/lib/api"
import { formatDate, relativeTime } from "@/lib/time"
import { Mono } from "@/components/ui-bits"

const host = (u: string | null) => (u ?? "").replace(/^https?:\/\//, "").replace(/\/$/, "")
/** `docker.io/library/busybox`, or the registry name when the URL is unknown. */
export const upstreamRef = (o: RepoOrigin) => `${host(o.registry_url) || o.registry || "?"}/${o.source}`

export function originLabel(o: RepoOrigin) {
  if (o.kind === "mirror") return { icon: CopyIcon, verb: "Mirror of", what: upstreamRef(o) }
  if (o.kind === "cache") return { icon: DatabaseZapIcon, verb: "Cached from", what: upstreamRef(o) }
  if (o.via === "archive") return { icon: FileArchiveIcon, verb: "Imported from", what: o.source }
  return { icon: ImportIcon, verb: "Imported from", what: upstreamRef(o) }
}

/** Side card body with sync state. */
export function OriginDetails({ origin: o, canManage }: { origin: RepoOrigin; canManage: boolean }) {
  const { icon: Icon, verb, what } = originLabel(o)
  return (
    <div className="space-y-2.5 text-sm">
      <div className="flex items-start gap-2">
        <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        <div className="min-w-0">
          <div className="text-muted-foreground">{verb}</div>
          <Mono className="break-all text-foreground">{what}</Mono>
        </div>
      </div>
      {o.kind === "mirror" && (
        o.at ? (
          <p className="flex items-start gap-2 text-xs text-muted-foreground" title={o.message ?? undefined}>
            {o.status === "error" ? <CircleAlertIcon className="mt-px size-3.5 shrink-0 text-destructive" /> : <CheckCircle2Icon className="mt-px size-3.5 shrink-0 text-emerald-500" />}
            <span>Synced <span title={formatDate(o.at)}>{relativeTime(o.at)}</span>{o.status === "error" && <span className="text-destructive">: {o.message}</span>}</span>
          </p>
        ) : <p className="text-xs text-muted-foreground">Not synced yet</p>
      )}
      {o.kind === "cache" && <p className="text-xs text-muted-foreground">Pulled from upstream on first use; {o.message}. Pushes are refused.</p>}
      {o.kind === "import" && o.at && <p className="text-xs text-muted-foreground">By {o.actor} <span title={formatDate(o.at)}>{relativeTime(o.at)}</span>. Later pushes don't change this.</p>}
      {o.kind === "mirror" && canManage && <Link to="/admin/mirrors" className="inline-block text-xs text-muted-foreground hover:text-foreground hover:underline">Manage mirror →</Link>}
    </div>
  )
}
