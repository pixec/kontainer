import { useQuery } from "@tanstack/react-query"
import { BookOpenIcon, ContainerIcon, CodeIcon, GlobeIcon, ScaleIcon, ServerIcon } from "lucide-react"
import { Facts, Panel } from "@/components/page"
import { ErrorBox, Loading } from "@/components/ui-bits"
import { endpoints } from "@/lib/api"
import { formatDate, relativeTime, formatSeconds } from "@/lib/time"

const useAbout = () => useQuery({ queryKey: ["about"], queryFn: endpoints.about, staleTime: Infinity })

function LinkCard({ href, icon, title, detail }: { href: string; icon: React.ReactNode; title: string; detail: string }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className="group flex items-center gap-3 rounded-lg border bg-card p-4 transition-colors hover:border-foreground/20 hover:bg-accent/40 [&_svg]:size-5 [&_svg]:shrink-0 [&_svg]:text-muted-foreground">
      {icon}
      <div className="min-w-0">
        <div className="text-sm font-medium">{title}</div>
        <div className="truncate text-xs text-muted-foreground">{detail}</div>
      </div>
    </a>
  )
}

export function AboutPage() {
  const q = useAbout()
  if (q.isLoading) return <Loading />
  if (q.error) return <ErrorBox error={q.error} />
  const a = q.data!
  const host = (u: string) => u.replace(/^https?:\/\//, "")
  return (
    <>
      <div className="flex flex-wrap items-center gap-4 rounded-lg border bg-card p-5">
        <div className="grid size-12 shrink-0 place-items-center rounded-xl border bg-background"><ContainerIcon className="size-6" /></div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <h2 className="text-lg font-semibold tracking-tight">Kontainer</h2>
            <span className="font-mono text-sm text-muted-foreground">v{a.version}{a.commit && <> · {a.commit}</>}</span>
          </div>
          <p className="text-sm text-muted-foreground">Open-source, self-hosted OCI container registry</p>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        {a.homepage && <LinkCard href={a.homepage} icon={<GlobeIcon />} title="Website" detail={host(a.homepage)} />}
        {a.repository && <LinkCard href={a.repository} icon={<CodeIcon />} title="Source code" detail={host(a.repository)} />}
        {a.repository && <LinkCard href={`${a.repository}/tree/main/docs`} icon={<BookOpenIcon />} title="Documentation" detail="Operations, backups, API" />}
      </div>

      <Panel padded title="Build" icon={<ContainerIcon />}>
        <Facts columns={4} items={[
          { label: "Version", value: a.version, mono: true },
          { label: "Commit", value: a.commit ?? "unknown", mono: true },
          { label: "Built", value: a.built_at ? <span title={formatDate(a.built_at)}>{relativeTime(a.built_at)}</span> : "unknown" },
          { label: "Compiler", value: a.rustc?.replace(/^rustc /, "").split(" ")[0], mono: true },
        ]} />
      </Panel>

      <Panel padded title="This server" icon={<ServerIcon />}>
        <Facts columns={3} items={[
          { label: "Platform", value: `${a.runtime.os}/${a.runtime.arch}`, mono: true },
          { label: "Uptime", value: formatSeconds(a.runtime.uptime_seconds) },
          { label: "Storage", value: a.runtime.storage },
          { label: "Authentication", value: a.runtime.auth },
          { label: "Scanner", value: a.runtime.scanner ?? "none" },
          { label: "Metrics", value: a.runtime.metrics === "on" ? "/metrics" : a.runtime.metrics === "off" ? "off" : "on, but no token set", mono: a.runtime.metrics === "on" },
        ]} />
      </Panel>

      <Panel title={a.license === "AGPL-3.0-only" ? "GNU Affero General Public License v3.0" : `${a.license} License`} icon={<ScaleIcon />} description="Kontainer is free software: you can use, study, share and modify it. If you run a modified version for others over a network, you must offer them its source code.">
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap px-5 py-4 font-mono text-xs leading-relaxed text-muted-foreground">{a.license_text.trim()}</pre>
      </Panel>
    </>
  )
}
