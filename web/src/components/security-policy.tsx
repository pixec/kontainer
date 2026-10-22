import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { PlusIcon, Trash2Icon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { LabeledSelect } from "@/components/page"
import { ErrorBox, Loading, Mono } from "@/components/ui-bits"
import { endpoints, type BlockSeverity, type SecurityPolicyInput } from "@/lib/api"
import { daysFromNow, formatDate, relativeTime, within } from "@/lib/time"

const SEVERITY: Record<string, string> = { critical: "Critical", high: "High or worse", medium: "Medium or worse", low: "Low or worse" }

/** A namespace's pull policy: what it refuses to serve. */
export function SecurityPolicyForm({ namespace }: { namespace: string }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ["security-policy", namespace], queryFn: () => endpoints.securityPolicy(namespace) })
  if (q.isLoading) return <Loading rows={3} />
  if (q.error) return <ErrorBox error={q.error} />
  const v = q.data!
  return <PolicyEditor key={v.policy?.updated_at ?? "new"} namespace={namespace} view={v} onSaved={() => qc.invalidateQueries({ queryKey: ["security-policy", namespace] })} />
}

function PolicyEditor({ namespace, view, onSaved }: { namespace: string; view: Awaited<ReturnType<typeof endpoints.securityPolicy>>; onSaved: () => void }) {
  const p = view.policy
  const [form, setForm] = useState<SecurityPolicyInput>({
    block_severity: p?.block_severity ?? null, is_block_unscanned: p?.is_block_unscanned ?? false,
    is_require_signature: p?.is_require_signature ?? false, signing_keys: p?.signing_keys ?? [],
  })
  const [keys, setKeys] = useState((p?.signing_keys ?? []).join("\n\n"))
  const save = useMutation({
    meta: { success: "Pull policy saved" },
    // Keys are PEM blocks; split on the END line so they can be pasted back to back.
    mutationFn: () => endpoints.setSecurityPolicy(namespace, { ...form, signing_keys: keys.split(/(?<=-----END PUBLIC KEY-----)/).map((k) => k.trim()).filter(Boolean) }),
    onSuccess: onSaved,
  })
  const registry = view.registry_block_severity
  const severityOptions: [string, string][] = [
    ["", registry ? `Registry default (${SEVERITY[registry] ?? registry})` : "Registry default (off)"],
    ["none", "Off"],
    ...Object.entries(SEVERITY),
  ]
  return (
    <form className="grid gap-5" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
      <div className="space-y-1.5">
        <Label>Block pulls of images with vulnerabilities</Label>
        <LabeledSelect label="Block" value={form.block_severity ?? ""} onChange={(s) => setForm({ ...form, block_severity: (s || null) as BlockSeverity | null })} options={severityOptions} className="w-full sm:w-80" />
        <p className="text-xs text-muted-foreground">Based on each image's latest scan. Allowlisted CVEs below don't count.{!view.scanner && " No scanner is configured on this registry, so nothing is scanned yet."}</p>
      </div>
      <label className="flex items-start gap-3">
        <Switch className="mt-0.5" checked={form.is_block_unscanned} onCheckedChange={(is_block_unscanned) => setForm({ ...form, is_block_unscanned })} />
        <span className="text-sm"><span className="font-medium">Block images that haven't been scanned</span><span className="block text-xs text-muted-foreground">Including ones still being scanned or whose scan failed.</span></span>
      </label>
      <label className="flex items-start gap-3">
        <Switch className="mt-0.5" checked={form.is_require_signature} onCheckedChange={(is_require_signature) => setForm({ ...form, is_require_signature })} />
        <span className="text-sm"><span className="font-medium">Require a cosign signature</span><span className="block text-xs text-muted-foreground">Images pulled by tag must be signed. The images inside a signed multi-platform index count as signed.</span></span>
      </label>
      {form.is_require_signature && (
        <div className="space-y-1.5">
          <Label htmlFor="sig-keys">Trusted public keys <span className="font-normal text-muted-foreground">(optional)</span></Label>
          <Textarea id="sig-keys" rows={5} className="font-mono text-xs" value={keys} onChange={(e) => setKeys(e.target.value)} placeholder={"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"} />
          <p className="text-xs text-muted-foreground">Paste <Mono>cosign.pub</Mono> files, one after another. Empty: any cosign signature is accepted.</p>
        </div>
      )}
      {save.error && <ErrorBox error={save.error} />}
      <div className="flex items-center gap-3">
        <Button type="submit" disabled={save.isPending}>Save policy</Button>
        {p && <span className="text-xs text-muted-foreground">Last changed by {p.updated_by} {relativeTime(p.updated_at)}</span>}
      </div>
    </form>
  )
}

const EXPIRY: [string, string][] = [["", "Never"], ["30", "30 days"], ["90", "90 days"], ["180", "180 days"]]

/** CVEs that don't count towards blocking: a namespace's, or the registry's (`namespace` null). */
export function CveAllowlist({ namespace, canEdit = true }: { namespace: string | null; canEdit?: boolean }) {
  const qc = useQueryClient()
  const key = ["cve-allowlist", namespace]
  const q = useQuery({ queryKey: key, queryFn: () => endpoints.cveAllowlist(namespace) })
  const registry = useQuery({ queryKey: ["cve-allowlist", null], queryFn: () => endpoints.cveAllowlist(null), enabled: namespace !== null })
  const [cve, setCve] = useState("")
  const [reason, setReason] = useState("")
  const [days, setDays] = useState("")
  const add = useMutation({
    meta: { success: "Added to the allowlist" },
    mutationFn: () => endpoints.allowCve(namespace, { cve: cve.trim(), reason: reason.trim(), expires_at: days ? daysFromNow(Number(days)) : null }),
    onSuccess: () => { setCve(""); setReason(""); qc.invalidateQueries({ queryKey: key }) },
  })
  const remove = useMutation({ meta: { success: "Removed from the allowlist" }, mutationFn: (id: number) => endpoints.disallowCve(namespace, id), onSuccess: () => qc.invalidateQueries({ queryKey: key }) })
  const rows = q.data ?? []
  return (
    <div className="space-y-3">
      {q.error && <ErrorBox error={q.error} />}
      {rows.length > 0 && (
        <ul className="divide-y rounded-lg border">
          {rows.map((r) => {
            const expired = !!r.expires_at && within(r.expires_at, 0)
            return (
              <li key={r.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                <Mono className={expired ? "text-muted-foreground line-through" : "text-foreground"}>{r.cve}</Mono>
                <span className="min-w-0 flex-1 truncate text-muted-foreground" title={r.reason}>{r.reason || "No reason given"}</span>
                <span className="text-xs text-muted-foreground" title={r.expires_at ? formatDate(r.expires_at) : undefined}>{r.expires_at ? (expired ? "expired" : `until ${relativeTime(r.expires_at)}`) : "no expiry"} · {r.created_by}</span>
                {canEdit && <Button size="icon-sm" variant="ghost" aria-label={`Remove ${r.cve}`} disabled={remove.isPending} onClick={() => remove.mutate(r.id)}><Trash2Icon /></Button>}
              </li>
            )
          })}
        </ul>
      )}
      {q.data && rows.length === 0 && <p className="text-sm text-muted-foreground">No allowlisted vulnerabilities{namespace ? " in this namespace" : ""}.</p>}
      {canEdit && (
        <form className="grid gap-2 sm:grid-cols-[11rem_1fr_9rem_auto]" onSubmit={(e) => { e.preventDefault(); if (cve.trim()) add.mutate() }}>
          <Input aria-label="CVE" className="font-mono text-xs" value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2024-1234" />
          <Input aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why it's acceptable" maxLength={500} />
          <LabeledSelect label="Expires" value={days} onChange={setDays} options={EXPIRY} className="w-full" />
          <Button type="submit" variant="outline" disabled={!cve.trim() || add.isPending}><PlusIcon />Allow</Button>
        </form>
      )}
      {add.error && <ErrorBox error={add.error} />}
      {namespace !== null && (registry.data?.length ?? 0) > 0 && (
        <p className="text-xs text-muted-foreground">Also allowed registry-wide: {registry.data!.map((r) => r.cve).join(", ")}</p>
      )}
    </div>
  )
}
