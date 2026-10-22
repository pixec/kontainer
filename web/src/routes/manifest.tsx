import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useEffect, useMemo, useState } from "react"
import { Link, useNavigate, useParams } from "react-router"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ScrollArea } from "@/components/ui/scroll-area"
import { cleanCommand, endpoints, formatBytes, shortDigest, type LayerInfo, type ManifestDetail, type ScanReport } from "@/lib/api"
import { formatDate, relativeTime } from "@/lib/time"
import { useSession } from "@/lib/session"
import { BackLink, ErrorBox, KV, Loading, Mono } from "@/components/ui-bits"
import { CopyInline, DetailList, DetailRow, Empty, Facts, LabeledSelect, PageHeader, Panel, SearchInput } from "@/components/page"
import { SeverityBar } from "@/components/severity-bar"
import { SeverityBadge } from "@/components/severity"
import { BracesIcon, DownloadIcon, FileCodeIcon, FileIcon, LayersIcon, InfoIcon, ListIcon, PackageIcon, ScanSearchIcon, StickyNoteIcon, TagIcon, TerminalIcon, Trash2Icon } from "lucide-react"
import { SbomTable, SupplyChain } from "@/components/supply-chain"
import { UseSnippets } from "@/components/use-snippets"
import { ExpirationDialog, TagHistoryPanel } from "@/components/tag-history"
import { DeleteDialog } from "@/components/delete-dialog"

export function ManifestPage() {
  const { "*": rest = "" } = useParams()
  const idx = rest.lastIndexOf("/m/")
  const name = idx >= 0 ? rest.slice(0, idx) : rest
  const ref = idx >= 0 ? decodeURIComponent(rest.slice(idx + 3)) : ""
  const isTag = !ref.includes(":")
  const { me } = useSession()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const q = useQuery({
    queryKey: ["manifest", name, ref],
    queryFn: () => endpoints.manifest(name, ref),
    refetchInterval: (query) => (query.state.data?.scan && ["pending", "running"].includes(query.state.data.scan.status) ? 3000 : false),
  })
  const repos = useQuery({ queryKey: ["repositories"], queryFn: endpoints.repositories })
  const tagList = useQuery({ queryKey: ["tags", name], queryFn: () => endpoints.tags(name), enabled: isTag })
  const tagInfo = tagList.data?.find((t) => t.tag === ref)
  const [expiring, setExpiring] = useState(false)
  const actions = repos.data?.find((r) => r.name === name)?.actions ?? []
  const scan = useMutation({
    meta: { success: "Scan queued" },
    mutationFn: () => endpoints.triggerScan(name, ref),
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ["manifest"] }), 800),
  })
  // A tag is deleted after its preview and the repository name typed back.
  const [deletingTag, setDeletingTag] = useState(false)
  const del = useMutation({
    meta: { success: "Deleted" },
    mutationFn: () => endpoints.deleteManifest(name, ref),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["tags", name] }); navigate(`/r/${name}`) },
  })

  // For an index, the page shows one platform image at a time.
  const [platform, setPlatform] = useState<string | null>(null)
  const platforms = q.data?.platforms ?? []
  const selected = platform ?? platforms[0]?.digest ?? null
  const child = useQuery({
    queryKey: ["manifest", name, selected],
    queryFn: () => endpoints.manifest(name, selected!),
    enabled: !!q.data && q.data.kind === "index" && !!selected,
  })
  useEffect(() => { setPlatform(null) }, [ref])

  if (q.isLoading) return <Loading />
  if (q.error) return <ErrorBox error={q.error} />
  const m = q.data!
  const image: ManifestDetail | undefined = m.kind === "image" ? m : child.data
  const imageRow = m.kind === "index" ? platforms.find((p) => p.digest === selected) : m.platforms[0]
  const aliases = m.tags.filter((t) => t !== ref)
  const isArtifact = m.artifact.kind !== "image" && m.artifact.kind !== "index"

  return (
    <>
      <BackLink to={`/r/${name}`} label={name} />
      <PageHeader
        icon={<TagIcon />}
        title={<span><span className="font-normal text-muted-foreground">{name.slice(name.lastIndexOf("/") + 1)}{isTag ? ":" : "@"}</span>{isTag ? ref : shortDigest(ref)}</span>}
        badge={<span className="chip text-foreground">{m.artifact.label}</span>}
        actions={<>
          {!isArtifact && <Button variant="outline" asChild title="OCI image layout; load with docker load (Docker 25+) or skopeo"><a href={endpoints.exportUrl(name, ref)} download><DownloadIcon />Export .tar</a></Button>}
          {me?.scanner && actions.includes("scan") && <Button variant="outline" onClick={() => scan.mutate()} disabled={scan.isPending}><ScanSearchIcon />Scan</Button>}
          {me?.features.delete && actions.includes("delete") && (
            <Button variant="destructive" disabled={del.isPending}
              onClick={() => { if (isTag) setDeletingTag(true); else if (confirm(`Delete manifest ${shortDigest(ref)} and all tags pointing to it?`)) del.mutate() }}>
              <Trash2Icon />Delete {isTag ? "tag" : "manifest"}
            </Button>
          )}
          {deletingTag && <DeleteDialog repo={name} tags={[ref]} onClose={() => setDeletingTag(false)} onDeleted={() => { qc.invalidateQueries({ queryKey: ["tags", name] }); navigate(`/r/${name}`) }} />}
        </>}
      />
      {scan.error && <ErrorBox error={scan.error} />}
      {del.error && <ErrorBox error={del.error} />}

      <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
        <div className="flex min-w-0 flex-1 flex-col gap-6">
          {m.kind === "index" && platforms.length === 0 && <Panel><Empty>This index contains no platform images.</Empty></Panel>}
          {isArtifact && <ArtifactView name={name} m={m} />}
          {image && !isArtifact && (child.isLoading ? <Loading /> : <ImageView name={name} refName={ref} image={image} />)}
          {(m.artifact.kind === "image" || m.artifact.kind === "index" || m.attached.length > 0) && <SupplyChain name={name} reference={ref} attached={m.attached} />}
          {isTag && <TagHistoryPanel repo={name} tag={ref} />}
          {m.annotations && (
            <Panel icon={<StickyNoteIcon />} title="Annotations" padded>
              <KV items={Object.entries(m.annotations).map(([k, v]) => [k, <Mono>{v}</Mono>])} />
            </Panel>
          )}
        </div>

        <aside className="space-y-4 lg:w-96 lg:shrink-0">
          <Panel padded icon={<InfoIcon />} title="Details">
            <div className="space-y-4">
              {m.kind === "index" && platforms.length > 0 && (
                <LabeledSelect label="Platform" value={selected ?? ""} onChange={setPlatform} options={platforms.map((p) => [p.digest, p.platform ?? shortDigest(p.digest)] as [string, string])} className="w-full" />
              )}
              <DetailList>
                {isArtifact ? (
                  <>
                    <DetailRow label="Size">{formatBytes(m.total_size)}</DetailRow>
                    <DetailRow label="Files">{m.layers.length}</DetailRow>
                    <DetailRow label="Media type"><span className="truncate font-mono text-xs" title={m.artifact.media_type ?? m.config?.mediaType ?? m.media_type}>{m.artifact.media_type ?? m.config?.mediaType ?? m.media_type}</span></DetailRow>
                  </>
                ) : image && (
                  <>
                    {m.kind !== "index" && <DetailRow label="Platform">{image.image ? `${image.image.os}/${image.image.architecture}` : "—"}</DetailRow>}
                    <DetailRow label="Size">{formatBytes(image.total_size)}</DetailRow>
                    <DetailRow label="Built">{image.image?.created ? <span title={formatDate(image.image.created)}>{relativeTime(image.image.created)}</span> : "—"}</DetailRow>
                    <DetailRow label="Vulnerabilities"><SeverityBar scan={imageRow?.scan ?? image.scan} to={image.scan?.status === "done" ? `/r/${name}/s/${image.digest}` : undefined} /></DetailRow>
                  </>
                )}
                <DetailRow label={m.kind === "index" ? "Index digest" : "Digest"}><CopyInline value={m.digest} display={shortDigest(m.digest)} /></DetailRow>
                {isTag && tagInfo && (
                  <DetailRow label="Expires">
                    {tagInfo.expires_at ? <span title={formatDate(tagInfo.expires_at)}>{relativeTime(tagInfo.expires_at)}</span> : <span className="text-muted-foreground">Never</span>}
                    {actions.includes("push") && <button type="button" onClick={() => setExpiring(true)} className="text-xs text-muted-foreground hover:text-foreground hover:underline">{tagInfo.expires_at ? "Change" : "Set"}</button>}
                  </DetailRow>
                )}
                {m.kind === "index" && image && <DetailRow label="Image digest"><CopyInline value={image.digest} display={shortDigest(image.digest)} /></DetailRow>}
                {aliases.length > 0 && <DetailRow label="Also tagged"><span className="flex flex-wrap justify-end gap-1">{aliases.map((t) => <Link key={t} to={`/r/${name}/m/${encodeURIComponent(t)}`} className="chip hover:text-foreground">{t}</Link>)}</span></DetailRow>}
                {(m.attached_to || m.subject) && <DetailRow label="Attached to"><Link to={`/r/${name}/m/${m.attached_to ?? m.subject!.digest}`} className="font-mono text-xs hover:underline">{shortDigest(m.attached_to ?? m.subject!.digest)}</Link></DetailRow>}
              </DetailList>
            </div>
          </Panel>
          {expiring && <ExpirationDialog repo={name} tag={ref} current={tagInfo?.expires_at} onClose={() => setExpiring(false)} />}
          {!m.attached_to && m.artifact.kind !== "signature" && m.artifact.kind !== "attestation" && (
            <Panel padded icon={<TerminalIcon />} title={isArtifact ? "Use This Artifact" : "Use This Image"}>
              <UseSnippets name={name} reference={ref} kind={m.artifact.kind} compact />
            </Panel>
          )}
        </aside>
      </div>
    </>
  )
}

/** Non-container artifacts: Helm charts, WASM, SBOMs, signatures and generic OCI artifacts. */
function ArtifactView({ name, m }: { name: string; m: ManifestDetail }) {
  const chart = m.artifact.kind === "helm_chart" ? m.config_json : undefined
  return (
    <>
      {chart && (
        <Panel icon={<PackageIcon />} title="Chart" padded>
          <Facts columns={4} items={[
            { label: "Name", value: String(chart.name ?? "") },
            { label: "Version", value: String(chart.version ?? ""), mono: true },
            { label: "App version", value: chart.appVersion ? String(chart.appVersion) : undefined, mono: true },
            { label: "API version", value: chart.apiVersion ? String(chart.apiVersion) : undefined },
            { label: "Description", value: chart.description ? String(chart.description) : undefined },
            { label: "Type", value: chart.type ? String(chart.type) : undefined },
          ]} />
        </Panel>
      )}
      {(m.artifact.kind === "sbom" || m.artifact.kind === "attestation") && (
        <Panel icon={<ListIcon />} title={m.artifact.kind === "sbom" ? "Packages" : "Attestation contents"} padded>
          <SbomTable name={name} digest={m.digest} />
        </Panel>
      )}
      <Panel icon={<FileIcon />} title="Contents">
        <Table>
          <TableHeader><TableRow><TableHead className="pl-4">Media type</TableHead><TableHead>Digest</TableHead><TableHead className="pr-4 text-right">Size</TableHead></TableRow></TableHeader>
          <TableBody>
            {m.layers.map((l) => (
              <TableRow key={l.digest}>
                <TableCell className="pl-4 font-mono text-xs">{l.media_type}</TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">{shortDigest(l.digest)}</TableCell>
                <TableCell className="pr-4 text-right tabular-nums text-muted-foreground">{formatBytes(l.size)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </>
  )
}


/** Layer list on the left, files / vulnerabilities for the selected layer on the right. */
function ImageView({ name, refName, image }: { name: string; refName: string; image: ManifestDetail }) {
  const [sel, setSel] = useState(0)
  useEffect(() => { setSel(0) }, [image.digest])
  const layer: LayerInfo | undefined = image.layers[sel]
  const report = useQuery({ queryKey: ["scan", name, image.digest], queryFn: () => endpoints.scan(name, image.digest), enabled: image.scan?.status === "done", retry: false })
  const vulnsByLayer = useMemo(() => {
    const map = new Map<string, number>()
    for (const v of report.data?.vulnerabilities ?? []) if (v.layer) map.set(v.layer, (map.get(v.layer) ?? 0) + 1)
    return map
  }, [report.data])
  const total = image.layers.reduce((a, l) => a + l.size, 0) || 1
  return (
    <Tabs defaultValue="layers" className="gap-4">
      <TabsList>
        <TabsTrigger value="layers">Image layers</TabsTrigger>
        {image.image && <TabsTrigger value="config">Config</TabsTrigger>}
        <TabsTrigger value="raw">Raw manifest</TabsTrigger>
      </TabsList>
      <TabsContent value="layers">
        <div className="grid gap-5 2xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div className="space-y-4">
            <Panel icon={<LayersIcon />} title="Layers" actions={<span className="text-xs text-muted-foreground tabular-nums">{image.layers.length} · {formatBytes(image.total_size)} compressed</span>}>
              <div className="flex h-1 w-full gap-px overflow-hidden bg-muted">
                {image.layers.map((l, i) => <span key={l.digest + i} title={`${i + 1}: ${formatBytes(l.size)}`} className={i === sel ? "bg-primary" : "bg-muted-foreground/40"} style={{ width: `${(l.size / total) * 100}%` }} />)}
              </div>
              <ul className="divide-y">
                {image.layers.map((l, i) => {
                  const n = vulnsByLayer.get(l.digest) ?? 0
                  return (
                    <li key={l.digest + i}>
                      <button type="button" onClick={() => setSel(i)} className={`flex w-full items-center gap-3 px-3 py-2.5 text-left text-sm hover:bg-muted/40 ${i === sel ? "bg-primary/10" : ""}`}>
                        <span className="w-5 shrink-0 text-right text-xs tabular-nums text-muted-foreground">{i + 1}</span>
                        <span className="min-w-0 flex-1 truncate font-mono text-xs">{cleanCommand(l.created_by) || l.comment || "(no history)"}</span>
                        <span className="shrink-0 text-xs tabular-nums text-muted-foreground">{formatBytes(l.size)}</span>
                        {n > 0 && <span className="shrink-0 rounded-sm bg-red-600/20 px-1.5 text-[11px] font-semibold text-red-400">{n}</span>}
                      </button>
                    </li>
                  )
                })}
              </ul>
            </Panel>
            {image.history.length > 0 && (
              <Panel icon={<FileCodeIcon />} title="Metadata-only steps" actions={<span className="text-xs text-muted-foreground">No layer produced</span>}>
                <pre className="px-4 py-3 text-xs leading-relaxed whitespace-pre-wrap break-all">{image.history.map((h) => cleanCommand(h.created_by)).join("\n")}</pre>
              </Panel>
            )}
          </div>
          <div className="min-w-0">
            {layer ? <LayerDetail name={name} refName={refName} image={image} layer={layer} index={sel} report={report.data} /> : <Panel><Empty>No layers.</Empty></Panel>}
          </div>
        </div>
      </TabsContent>
      {image.image && <TabsContent value="config"><ConfigView m={image} /></TabsContent>}
      <TabsContent value="raw"><Panel icon={<BracesIcon />} title="Manifest"><pre className="p-4 text-xs overflow-auto">{JSON.stringify(image.raw, null, 2)}</pre></Panel></TabsContent>
    </Tabs>
  )
}

function LayerDetail({ name, image, layer, index, report }: { name: string; refName: string; image: ManifestDetail; layer: LayerInfo; index: number; report?: ScanReport }) {
  const files = useQuery({ queryKey: ["layer-files", name, image.digest, layer.digest], queryFn: () => endpoints.layerFiles(name, image.digest, layer.digest), staleTime: Infinity })
  const [filter, setFilter] = useState("")
  const vulns = (report?.vulnerabilities ?? []).filter((v) => v.layer === layer.digest)
  const entries = (files.data?.entries ?? []).filter((e) => !filter || e.path.toLowerCase().includes(filter.toLowerCase()))
  return (
    <Panel icon={<LayersIcon />} title={`Layer ${index + 1}`} actions={<span className="text-xs text-muted-foreground tabular-nums">{formatBytes(layer.size)} compressed</span>}>
      <div className="space-y-1 border-b px-4 py-3">
        <div className="break-all font-mono text-xs">{cleanCommand(layer.created_by) || layer.comment || "(no history)"}</div>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>Digest <CopyInline value={layer.digest} display={shortDigest(layer.digest)} /></span>
          {layer.diff_id && <span>Diff ID <CopyInline value={layer.diff_id} display={shortDigest(layer.diff_id)} /></span>}
        </div>
      </div>
      <Tabs defaultValue={vulns.length > 0 ? "vulns" : "files"} className="gap-0">
        <TabsList className="mx-0 px-2 pt-1">
          <TabsTrigger value="files">Files{files.data ? ` (${files.data.entries.length}${files.data.is_truncated ? "+" : ""})` : ""}</TabsTrigger>
          <TabsTrigger value="vulns">Vulnerabilities ({vulns.length})</TabsTrigger>
        </TabsList>
        <TabsContent value="files">
          <>
            <div className="border-b p-3"><SearchInput placeholder="Filter files..." value={filter} onChange={setFilter} className="sm:w-full" /></div>
            {files.isLoading && <div className="p-4"><Loading rows={3} /></div>}
            {files.error && <div className="p-3"><ErrorBox error={files.error} /></div>}
            {files.data && (
              <ScrollArea className="h-[480px]">
                <table className="w-full text-xs font-mono">
                  <tbody>
                    {entries.map((e, i) => (
                      <tr key={i} className="border-b border-border/50 last:border-0">
                        <td className="px-3 py-1 text-muted-foreground">{e.mode}</td>
                        <td className="px-2 py-1 text-right tabular-nums text-muted-foreground">{e.type === "file" ? formatBytes(e.size) : ""}</td>
                        <td className={`px-2 py-1 break-all ${e.is_whiteout ? "text-red-400" : e.type === "dir" ? "text-primary" : e.type === "symlink" ? "text-amber-300" : ""}`}>{e.path}{e.link_target ? ` → ${e.link_target}` : ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {files.data.entries.length === 0 && <Empty>Empty layer.</Empty>}
              </ScrollArea>
            )}
          </>
        </TabsContent>
        <TabsContent value="vulns">
          <>
            {!image.scan && <Empty>This image has not been scanned.</Empty>}
            {image.scan && image.scan.status !== "done" && <Empty>Scan {image.scan.status}...</Empty>}
            {image.scan?.status === "done" && vulns.length === 0 && <Empty>No vulnerabilities introduced by this layer.</Empty>}
            {vulns.length > 0 && (
              <Table>
                <TableHeader><TableRow><TableHead className="pl-3">CVE</TableHead><TableHead>Severity</TableHead><TableHead>Package</TableHead><TableHead>Fixed in</TableHead></TableRow></TableHeader>
                <TableBody>
                  {vulns.map((v, i) => (
                    <TableRow key={v.id + i}>
                      <TableCell className="pl-3">{v.url ? <a href={v.url} target="_blank" rel="noopener noreferrer" className="font-mono text-xs text-primary hover:underline">{v.id}</a> : <Mono>{v.id}</Mono>}</TableCell>
                      <TableCell><SeverityBadge severity={v.severity} /></TableCell>
                      <TableCell className="font-mono text-xs">{v.package}{v.installed_version && <span className="text-muted-foreground"> / {v.installed_version}</span>}</TableCell>
                      <TableCell className="font-mono text-xs">{v.fixed_version ?? <span className="text-muted-foreground">—</span>}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </>
        </TabsContent>
      </Tabs>
    </Panel>
  )
}

function ConfigView({ m }: { m: ManifestDetail }) {
  const c = m.image?.config
  if (!c) return <Panel><Empty>No container config.</Empty></Panel>
  return (
    <Panel padded>
      <Facts columns={2} items={[
        { label: "Entrypoint", value: c.Entrypoint && JSON.stringify(c.Entrypoint), mono: true },
        { label: "Cmd", value: c.Cmd && JSON.stringify(c.Cmd), mono: true },
        { label: "WorkingDir", value: c.WorkingDir, mono: true },
        { label: "User", value: c.User, mono: true },
        { label: "Ports", value: c.ExposedPorts && Object.keys(c.ExposedPorts).join(", "), mono: true },
        { label: "Volumes", value: c.Volumes && Object.keys(c.Volumes).join(", "), mono: true },
        { label: "Author", value: m.image?.author },
        { label: "Created", value: m.image?.created ? formatDate(m.image.created) : undefined },
      ]} />
      {(c.Env || c.Labels) && (
        <div className="mt-5 grid gap-5 sm:grid-cols-2">
          {c.Env && <div><div className="text-xs text-muted-foreground">Env</div><pre className="mt-1 whitespace-pre-wrap break-all text-xs leading-relaxed">{c.Env.join("\n")}</pre></div>}
          {c.Labels && <div><div className="text-xs text-muted-foreground">Labels</div><pre className="mt-1 whitespace-pre-wrap break-all text-xs leading-relaxed">{Object.entries(c.Labels).map(([k, v]) => `${k}=${v}`).join("\n")}</pre></div>}
        </div>
      )}
    </Panel>
  )
}
