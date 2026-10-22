import { useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { useParams } from "react-router"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { endpoints, SEVERITIES, shortDigest, type Severity } from "@/lib/api"
import { BackLink, ErrorBox, KV, Loading, Mono } from "@/components/ui-bits"
import { SeverityBadge } from "@/components/severity"
import { PageHeader, Panel, SearchInput } from "@/components/page"

export function ScanPage() {
  const { "*": rest = "" } = useParams()
  const idx = rest.lastIndexOf("/s/")
  const name = rest.slice(0, idx)
  const digest = rest.slice(idx + 3)
  const [filter, setFilter] = useState("")
  const [sev, setSev] = useState<Severity | null>(null)
  const q = useQuery({ queryKey: ["scan", name, digest], queryFn: () => endpoints.scan(name, digest) })
  if (q.isLoading) return <Loading />
  if (q.error) return <ErrorBox error={q.error} />
  const r = q.data!
  const vulns = r.vulnerabilities.filter((v) => (!sev || v.severity === sev) && (!filter || `${v.id} ${v.package} ${v.title ?? ""}`.toLowerCase().includes(filter.toLowerCase())))
  return (
    <>
      <BackLink to={`/r/${name}/m/${digest}`} label={<>{name}<span className="text-muted-foreground/60">@</span>{shortDigest(digest)}</>} />
      <PageHeader title="Vulnerability report" description={`${name} @ ${shortDigest(digest)}`} actions={r.vulnerabilities.length > 0 && <SearchInput placeholder="Filter by CVE, package, title..." value={filter} onChange={setFilter} />} />
      <Panel padded>
          <KV items={[
            ["Scanner", `${r.scanner} ${r.scanner_version ?? ""}`],
            ["Status", <span className="flex items-center gap-2"><Badge variant={r.status === "failed" ? "destructive" : "secondary"}>{r.status}</Badge>{r.error && <span className="text-destructive text-xs">{r.error}</span>}</span>],
            ["Finished", r.finished_at],
            ["Summary", r.total === 0 && r.status === "done"
              ? <Badge className="bg-green-700 text-white border-transparent">no vulnerabilities</Badge>
              : <span className="flex flex-wrap gap-1">{SEVERITIES.filter((s) => r.summary[s]).map((s) => (
                  <button key={s} type="button" onClick={() => setSev(sev === s ? null : s)} className={sev && sev !== s ? "opacity-40" : ""}>
                    <SeverityBadge severity={s} count={r.summary[s]} />
                  </button>))}</span>],
          ]} />
      </Panel>
      {r.vulnerabilities.length > 0 && (
        <Panel title={`${vulns.length} of ${r.total} vulnerabilities`}>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead><TableHead>ID</TableHead><TableHead>Package</TableHead>
                <TableHead className="hidden md:table-cell">Installed</TableHead><TableHead className="hidden md:table-cell">Fixed</TableHead><TableHead className="hidden lg:table-cell">Title</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vulns.map((v, i) => (
                <TableRow key={v.id + v.package + i}>
                  <TableCell><SeverityBadge severity={v.severity} /></TableCell>
                  <TableCell>
                    {v.url ? <a href={v.url} target="_blank" rel="noopener noreferrer" className="font-mono text-xs hover:underline">{v.id}</a> : <Mono>{v.id}</Mono>}
                    {r.allowlisted?.includes(v.id) && <span className="chip ml-2" title="Allowlisted: doesn't count towards this namespace's pull policy">Allowlisted</span>}
                  </TableCell>
                  <TableCell><Mono>{v.package}</Mono></TableCell>
                  <TableCell className="hidden md:table-cell"><Mono>{v.installed_version}</Mono></TableCell>
                  <TableCell className="hidden md:table-cell"><Mono>{v.fixed_version ?? <span className="text-muted-foreground">—</span>}</Mono></TableCell>
                  <TableCell className="hidden lg:table-cell text-xs">{v.title}{v.layer && <span className="text-muted-foreground font-mono"> ({shortDigest(v.layer)})</span>}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      )}
    </>
  )
}
