import { useMutation } from "@tanstack/react-query"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ErrorBox, Mono } from "@/components/ui-bits"

const VALID = /^[a-z0-9][a-z0-9._-]*$/

/** Rename a namespace (organization or user). Explains what moves and asks for confirmation. */
export function RenameNamespace({ current, what, onRename, onDone }: { current: string; what: "organization" | "account"; onRename: (next: string) => Promise<unknown>; onDone: (next: string) => void }) {
  const [next, setNext] = useState(current)
  const [confirming, setConfirming] = useState(false)
  const [typed, setTyped] = useState("")
  const rename = useMutation({ meta: { success: "Renamed" }, mutationFn: () => onRename(next.trim()), onSuccess: () => { setConfirming(false); onDone(next.trim()) } })
  const value = next.trim()
  const valid = VALID.test(value)
  const changed = value !== current
  return (
    <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); if (valid && changed) { setTyped(""); setConfirming(true) } }}>
      <div className="flex flex-col gap-2 sm:flex-row">
        <div className="relative sm:flex-1">
          <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 font-mono text-sm text-muted-foreground">{location.host}/</span>
          <Input className="font-mono" style={{ paddingLeft: `calc(${location.host.length + 1}ch + 0.75rem + 1px)` }} value={next}
            aria-invalid={!!value && !valid} onChange={(e) => setNext(e.target.value.toLowerCase())} />
        </div>
        <Button type="submit" variant="outline" disabled={!valid || !changed}>Rename</Button>
      </div>
      <p className="text-xs text-muted-foreground">{value && !valid ? "Lowercase letters, digits, . _ and -, starting with a letter or digit." : <>Images are addressed as <Mono className="text-foreground">{location.host}/{value || current}/&lt;image&gt;</Mono>.</>}</p>
      <Dialog open={confirming} onOpenChange={(v) => { setConfirming(v); if (!v) rename.reset() }}>
        <DialogContent className="sm:max-w-lg">
          <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (typed === value) rename.mutate() }}>
            <DialogHeader>
              <DialogTitle>Rename {current} to {value}?</DialogTitle>
              <DialogDescription>Every repository moves from <Mono className="text-foreground">{current}/</Mono> to <Mono className="text-foreground">{value}/</Mono>, along with {what === "organization" ? "its robots" : "your robots"}, permissions, stars and settings.</DialogDescription>
            </DialogHeader>
            <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
              <li><Mono className="text-foreground">docker pull {location.host}/{current}/...</Mono> stops working. Update deployments, CI and image references.</li>
              <li>Robot usernames change to <Mono className="text-foreground">{value}+...</Mono>; their credentials keep working with the new name.</li>
              {what === "account" && <li>You sign in with the new username from now on.</li>}
            </ul>
            <div className="space-y-2">
              <Label htmlFor="rename-confirm">Type <Mono className="text-foreground">{value}</Mono> to confirm</Label>
              <Input id="rename-confirm" className="font-mono" autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} />
            </div>
            {rename.error && <ErrorBox error={rename.error} />}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setConfirming(false)}>Cancel</Button>
              <Button type="submit" variant="destructive" disabled={typed !== value || rename.isPending}>{rename.isPending ? "Renaming..." : "Rename"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </form>
  )
}
