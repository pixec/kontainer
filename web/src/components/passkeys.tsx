import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { Trash2Icon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Empty, Panel } from "@/components/page"
import { ErrorBox } from "@/components/ui-bits"
import { endpoints, type PasskeyInfo } from "@/lib/api"
import { formatDate, relativeTime } from "@/lib/time"
import { passkeysSupported, registerPasskey } from "@/lib/webauthn"

/** Settings > Security > Passkeys: add one on this device (with a name), list them, remove them. */
export function PasskeysSection({ available }: { available: boolean }) {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ["passkeys"], queryFn: endpoints.passkeys })
  const [name, setName] = useState("")
  const [removing, setRemoving] = useState<PasskeyInfo | null>(null)
  const add = useMutation({
    meta: { success: "Passkey added" },
    mutationFn: () => registerPasskey(name.trim()),
    onSuccess: () => { setName(""); qc.invalidateQueries({ queryKey: ["passkeys"] }) },
  })
  const remove = useMutation({
    meta: { success: "Passkey removed" },
    mutationFn: (id: number) => endpoints.deletePasskey(id),
    onSuccess: () => { setRemoving(null); qc.invalidateQueries({ queryKey: ["passkeys"] }) },
  })
  const supported = passkeysSupported()
  // Closing the browser's dialog is a choice, not an error.
  const addError = add.error instanceof DOMException && add.error.name === "NotAllowedError" ? null : add.error
  return (
    <Panel title="Passkeys" description="Sign in with your device's screen lock or a security key instead of a password. A passkey is both factors, so no one-time code is asked.">
      <div className="space-y-4 p-4">
        {!available && <p className="text-sm text-muted-foreground">Passkeys are unavailable on this registry: its public URL must name it by domain.</p>}
        {available && !supported && <p className="text-sm text-muted-foreground">This browser does not support passkeys.</p>}
        {available && supported && (
          <form className="flex max-w-md items-end gap-2" onSubmit={(e) => { e.preventDefault(); if (name.trim()) add.mutate() }}>
            <div className="flex-1 space-y-2">
              <Label htmlFor="passkey-name">Name</Label>
              <Input id="passkey-name" placeholder="Work laptop" maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <Button type="submit" disabled={!name.trim() || add.isPending}>{add.isPending ? "Waiting for your device..." : "Add a passkey"}</Button>
          </form>
        )}
        {addError && <ErrorBox error={addError} />}
        {list.error && <ErrorBox error={list.error} />}
      </div>
      {list.data && list.data.length === 0 && <Empty>No passkeys yet.</Empty>}
      {list.data && list.data.length > 0 && (
        <Table>
          <TableHeader><TableRow><TableHead className="pl-4">Name</TableHead><TableHead>Added</TableHead><TableHead>Last used</TableHead><TableHead className="pr-4" /></TableRow></TableHeader>
          <TableBody>
            {list.data.map((k) => (
              <TableRow key={k.id}>
                <TableCell className="pl-4 font-medium">{k.name}</TableCell>
                <TableCell className="text-muted-foreground"><span title={formatDate(k.created_at)}>{relativeTime(k.created_at)}</span></TableCell>
                <TableCell className="text-muted-foreground">{k.last_used_at ? <span title={formatDate(k.last_used_at)}>{relativeTime(k.last_used_at)}</span> : "Never"}</TableCell>
                <TableCell className="pr-4 text-right">
                  {removing?.id === k.id ? (
                    <span className="inline-flex items-center gap-2">
                      <Button size="sm" variant="destructive" disabled={remove.isPending} onClick={() => remove.mutate(k.id)}>Remove</Button>
                      <Button size="sm" variant="ghost" onClick={() => setRemoving(null)}>Cancel</Button>
                    </span>
                  ) : (
                    <Button size="icon-sm" variant="ghost" aria-label={`Remove ${k.name}`} onClick={() => setRemoving(k)}><Trash2Icon /></Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {remove.error && <div className="p-4"><ErrorBox error={remove.error} /></div>}
    </Panel>
  )
}
