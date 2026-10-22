import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { useNavigate } from "react-router"
import { GlobeIcon, LockIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ErrorBox, Mono } from "@/components/ui-bits"
import { endpoints, type Visibility } from "@/lib/api"

/** OCI repository names: lowercase path components joined by `/`. */
const NAME_RE = /^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$/

/** Create an empty repository under `namespace/` and open it, to set up builds or settings
 *  before anything is pushed. */
export function NewRepositoryDialog({ namespace, open, onOpenChange }: { namespace: string; open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [name, setName] = useState(`${namespace}/`)
  const [description, setDescription] = useState("")
  const [visibility, setVisibility] = useState<Visibility>("private")
  const full = name.trim()
  const valid = NAME_RE.test(full) && full.length <= 255
  const create = useMutation({
    meta: { success: "Repository created" },
    mutationFn: () => endpoints.createRepository({ name: full, description: description.trim(), visibility }),
    onSuccess: (m) => { qc.invalidateQueries({ queryKey: ["repositories"] }); qc.invalidateQueries({ queryKey: ["org"] }); close(false); navigate(`/r/${m.name}`) },
  })
  function close(v: boolean) {
    if (!v) { setName(`${namespace}/`); setDescription(""); setVisibility("private"); create.reset() }
    onOpenChange(v)
  }
  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <form className="grid gap-5" onSubmit={(e) => { e.preventDefault(); if (valid) create.mutate() }}>
          <DialogHeader>
            <DialogTitle>New repository</DialogTitle>
            <DialogDescription>An empty repository: push to it, or set up a build from Git first.</DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="nr-name">Name</Label>
            <Input id="nr-name" className="font-mono" autoFocus value={name} onChange={(e) => setName(e.target.value.toLowerCase())} placeholder={`${namespace}/app`} />
            <p className="text-xs text-muted-foreground">
              {full && !valid && full !== `${namespace}/`
                ? "Lowercase letters, digits and . _ -, in path components separated by /."
                : <>Images are addressed as <Mono className="text-foreground">{location.host}/{valid ? full : `${namespace}/<name>`}</Mono>.</>}
            </p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="nr-desc">Description <span className="font-normal text-muted-foreground">(optional)</span></Label>
            <Input id="nr-desc" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={200} placeholder="What it holds" />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            {(["private", "public"] as const).map((v) => (
              <label key={v} className={`flex cursor-pointer items-start gap-3 rounded-lg p-3 ring-1 transition-colors ${visibility === v ? "bg-foreground/5 ring-foreground/30" : "ring-border hover:bg-foreground/[0.03]"}`}>
                <input type="radio" name="nr-visibility" className="mt-1 size-4 accent-foreground" checked={visibility === v} onChange={() => setVisibility(v)} />
                <span>
                  <span className="flex items-center gap-1.5 text-sm font-medium">{v === "public" ? <GlobeIcon className="size-4" /> : <LockIcon className="size-4" />}{v === "public" ? "Public" : "Private"}</span>
                  <span className="block text-sm text-muted-foreground">{v === "public" ? "Anyone can pull." : "Only people with access can pull."}</span>
                </span>
              </label>
            ))}
          </div>
          {create.error && <ErrorBox error={create.error} />}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => close(false)}>Cancel</Button>
            <Button type="submit" disabled={!valid || create.isPending}>{create.isPending ? "Creating..." : "Create repository"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
