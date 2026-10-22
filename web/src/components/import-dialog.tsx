import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useEffect, useState } from "react"
import { Link } from "react-router"
import { CheckCircle2Icon, CircleAlertIcon, DownloadIcon, FileArchiveIcon, GlobeIcon, Loader2Icon, UploadIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ErrorBox, Mono } from "@/components/ui-bits"
import { RegistrySelect } from "@/routes/remote"
import { endpoints, formatBytes } from "@/lib/api"
import { cn } from "@/lib/utils"

/** Import an image into `namespace/`: copied from another registry (a background job) or
 *  uploaded as an OCI layout archive. */
export function ImportDialog({ namespace, open, onOpenChange }: { namespace: string; open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient()
  const regs = useQuery({ queryKey: ["registries"], queryFn: endpoints.registries, enabled: open })
  const [mode, setMode] = useState<"registry" | "archive">("registry")
  const [registryId, setRegistryId] = useState<number | null>(null)
  const [source, setSource] = useState("")
  const [target, setTarget] = useState("")
  const [tag, setTag] = useState("")
  const [file, setFile] = useState<File | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)

  const registries = regs.data ?? []
  const rid = registryId ?? registries[0]?.id ?? null
  // "library/alpine:3.20" -> repository + reference
  const [srcRepo, srcRef] = (() => {
    const at = source.indexOf("@")
    if (at > 0) return [source.slice(0, at), source.slice(at + 1)]
    const colon = source.lastIndexOf(":")
    return colon > source.lastIndexOf("/") ? [source.slice(0, colon), source.slice(colon + 1)] : [source, "latest"]
  })()
  const defaultTarget = `${namespace}/${srcRepo.slice(srcRepo.lastIndexOf("/") + 1)}`
  const repo = (target || (mode === "registry" && srcRepo ? defaultTarget : "")).trim()
  const fullRepo = repo.includes("/") ? repo : `${namespace}/${repo}`

  const fromRegistry = useMutation({
    mutationFn: () => endpoints.importImage({ registry_id: rid!, source: srcRepo, reference: srcRef, target: fullRepo, tag: tag || undefined }),
    onSuccess: (r) => { setJobId(r.job); qc.invalidateQueries({ queryKey: ["jobs"] }) },
  })
  const upload = useMutation({
    mutationFn: () => endpoints.importArchive(fullRepo, file!, tag || undefined),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["repositories"] }),
  })
  const jobs = useQuery({
    queryKey: ["jobs"], queryFn: endpoints.jobs, enabled: !!jobId,
    refetchInterval: (q) => (q.state.data?.find((j) => j.id === jobId)?.status === "running" ? 1000 : false),
  })
  const job = jobs.data?.find((j) => j.id === jobId)
  useEffect(() => { if (job && job.status !== "running") qc.invalidateQueries({ queryKey: ["repositories"] }) }, [job?.status, qc]) // eslint-disable-line react-hooks/exhaustive-deps

  const reset = () => { setJobId(null); fromRegistry.reset(); upload.reset() }
  const close = (v: boolean) => { if (!v) { reset(); setSource(""); setTarget(""); setTag(""); setFile(null) } onOpenChange(v) }
  const done = (job && job.status === "done") || upload.isSuccess
  const busy = fromRegistry.isPending || upload.isPending || job?.status === "running"
  const canSubmit = mode === "registry" ? !!rid && !!srcRepo && !!repo : !!file && !!repo

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <form className="grid gap-5" onSubmit={(e) => { e.preventDefault(); reset(); (mode === "registry" ? fromRegistry : upload).mutate() }}>
          <DialogHeader>
            <DialogTitle>Import an image</DialogTitle>
            <DialogDescription>Copy an image into {namespace}/ without a docker push.</DialogDescription>
          </DialogHeader>
          <Tabs value={mode} onValueChange={(v) => { setMode(v as typeof mode); reset() }} className="gap-4">
            <TabsList>
              <TabsTrigger value="registry"><GlobeIcon className="size-4" />From a registry</TabsTrigger>
              <TabsTrigger value="archive"><FileArchiveIcon className="size-4" />Upload archive</TabsTrigger>
            </TabsList>
            <TabsContent value="registry" className="space-y-4">
              {regs.isSuccess && registries.length === 0 ? (
                <p className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">No registries are set up. An administrator can add one under <Link to="/admin/registries" className="text-foreground hover:underline" onClick={() => close(false)}>Administration → Registries</Link>.</p>
              ) : (
                <>
                  <div className="space-y-1.5"><Label htmlFor="imp-reg">Registry</Label><RegistrySelect id="imp-reg" registries={registries} value={rid} onChange={setRegistryId} /></div>
                  <div className="space-y-1.5">
                    <Label htmlFor="imp-src">Image</Label>
                    <Input id="imp-src" autoFocus value={source} onChange={(e) => setSource(e.target.value.trim())} placeholder="library/alpine:3.20" />
                    <p className="text-xs text-muted-foreground">Repository with a tag or <Mono>@digest</Mono>. Multi-platform images are copied whole.</p>
                  </div>
                </>
              )}
            </TabsContent>
            <TabsContent value="archive" className="space-y-4">
              <label className={cn("flex cursor-pointer flex-col items-center gap-2 rounded-lg border border-dashed px-4 py-6 text-center text-sm transition-colors hover:bg-accent/40", file && "border-solid")}>
                <UploadIcon className="size-5 text-muted-foreground" />
                {file ? <span><span className="font-medium">{file.name}</span> <span className="text-muted-foreground">· {formatBytes(file.size)}</span></span> : <span className="text-muted-foreground">Choose a <Mono>.tar</Mono> or <Mono>.tar.gz</Mono> OCI image layout</span>}
                <input type="file" accept=".tar,.tgz,.gz,application/x-tar,application/gzip" className="sr-only" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
              </label>
              <p className="text-xs text-muted-foreground">From <Mono>docker save</Mono> (Docker 25+), <Mono>skopeo copy ... oci-archive:</Mono> or an export from this registry.</p>
            </TabsContent>
          </Tabs>
          <div className="grid gap-4 sm:grid-cols-[1fr_9rem]">
            <div className="space-y-1.5">
              <Label htmlFor="imp-target">Into repository</Label>
              <Input id="imp-target" value={target} onChange={(e) => setTarget(e.target.value.toLowerCase())} placeholder={mode === "registry" && srcRepo ? defaultTarget : `${namespace}/name`} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="imp-tag">Tag</Label>
              <Input id="imp-tag" value={tag} onChange={(e) => setTag(e.target.value)} placeholder={mode === "registry" ? (srcRef.includes(":") ? "latest" : srcRef || "latest") : "from archive"} />
            </div>
          </div>

          {(fromRegistry.error || upload.error) && <ErrorBox error={fromRegistry.error ?? upload.error} />}
          {job?.status === "running" && <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2Icon className="size-4 animate-spin" />Copying {srcRepo}:{srcRef}... you can close this, it keeps going.</p>}
          {job?.status === "failed" && <p className="flex items-start gap-2 text-sm text-destructive"><CircleAlertIcon className="mt-0.5 size-4 shrink-0" />{job.message}</p>}
          {done && (
            <p className="flex items-center gap-2 text-sm text-emerald-500"><CheckCircle2Icon className="size-4" />
              <span>Imported {upload.data ? upload.data.tags.map((t) => `${fullRepo}:${t}`).join(", ") : job?.message}. <Link to={`/r/${fullRepo}`} className="text-foreground underline-offset-4 hover:underline" onClick={() => close(false)}>Open repository</Link></span>
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => close(false)}>{done ? "Close" : "Cancel"}</Button>
            <Button type="submit" disabled={!canSubmit || busy}>{busy ? <Loader2Icon className="animate-spin" /> : <DownloadIcon />}Import</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
