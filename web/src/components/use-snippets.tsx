import { useState } from "react"
import { CheckIcon, CopyIcon } from "lucide-react"
import type { ArtifactKind } from "@/lib/api"
import { useSession } from "@/lib/session"
import { cn } from "@/lib/utils"
import { LabeledSelect } from "@/components/page"

/** A copyable, multi-line command or config snippet. */
export function CodeBlock({ code, className, wrap }: { code: string; className?: string; wrap?: boolean }) {
  const [done, setDone] = useState(false)
  const copy = () => navigator.clipboard.writeText(code).then(() => { setDone(true); setTimeout(() => setDone(false), 1500) }).catch(() => {})
  return (
    <div className={cn("group relative rounded-lg border bg-canvas-subtle", className)}>
      <pre className={cn("overflow-x-auto p-4 pr-12 font-mono text-[13px] leading-6 text-foreground", wrap && "whitespace-pre-wrap [overflow-wrap:anywhere]")}><code>{code}</code></pre>
      <button type="button" onClick={copy} title="Copy" aria-label="Copy"
        className="absolute right-2 top-2 rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground">
        {done ? <CheckIcon className="size-4 text-success" /> : <CopyIcon className="size-4" />}
      </button>
    </div>
  )
}

type Snippet = { id: string; label: string; code: string; note?: string }

/** Ready-to-paste commands for one artifact, adapted to what it is. */
/** `compact` (narrow sidebars): a client dropdown instead of a tab row, and wrapped commands. */
export function UseSnippets({ name, reference, kind, className, compact }: { name: string; reference: string; kind: ArtifactKind; className?: string; compact?: boolean }) {
  const { me } = useSession()
  const host = location.host
  const isDigest = reference.includes(":")
  const ref = `${host}/${name}${isDigest ? "@" : ":"}${reference}`
  const user = me?.username ?? "<username>"
  const short = name.slice(name.lastIndexOf("/") + 1)
  const secret = `${host.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}-pull`
  const isImage = kind === "image" || kind === "index"

  const snippets: Snippet[] = []
  if (kind === "helm_chart") {
    snippets.push({
      id: "helm", label: "Helm",
      code: `helm registry login ${host} --username ${user}\nhelm pull oci://${host}/${name} --version ${reference}\nhelm install ${short} oci://${host}/${name} --version ${reference}`,
    })
  }
  if (isImage) {
    snippets.push(
      { id: "docker", label: "Docker", code: `docker login ${host} --username ${user}\ndocker pull ${ref}` },
      { id: "podman", label: "Podman", code: `podman login ${host} --username ${user}\npodman pull ${ref}` },
    )
  }
  snippets.push({ id: "oras", label: "ORAS", code: `oras login ${host} --username ${user}\noras pull ${ref}${isImage ? "" : " --output ./" + short}` })
  if (isImage) {
    snippets.push(
      {
        id: "k8s", label: "Kubernetes",
        note: "Use an access token or robot credential as the password. The pull secret lets the cluster pull private images.",
        code: `kubectl create secret docker-registry ${secret} \\\n  --docker-server=${host} \\\n  --docker-username=${user} \\\n  --docker-password=<token>\n\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: ${short}\nspec:\n  imagePullSecrets:\n    - name: ${secret}\n  containers:\n    - name: ${short}\n      image: ${ref}`,
      },
      {
        id: "gha", label: "GitHub Actions",
        note: "Store a robot account's credential as the REGISTRY_TOKEN secret.",
        code: `- uses: docker/login-action@v3\n  with:\n    registry: ${host}\n    username: \${{ vars.REGISTRY_USERNAME }}\n    password: \${{ secrets.REGISTRY_TOKEN }}\n\n- uses: docker/build-push-action@v6\n  with:\n    push: true\n    tags: ${host}/${name}:\${{ github.sha }}`,
      },
      {
        id: "gitlab", label: "GitLab CI",
        note: "Set REGISTRY_USERNAME and REGISTRY_TOKEN as masked CI/CD variables.",
        code: `build:\n  image: docker:27\n  services: [docker:27-dind]\n  script:\n    - echo "$REGISTRY_TOKEN" | docker login ${host} -u "$REGISTRY_USERNAME" --password-stdin\n    - docker build -t ${host}/${name}:$CI_COMMIT_SHORT_SHA .\n    - docker push ${host}/${name}:$CI_COMMIT_SHORT_SHA`,
      },
    )
  }
  const [active, setActive] = useState(snippets[0].id)
  const current = snippets.find((s) => s.id === active) ?? snippets[0]

  return (
    <div className={cn("space-y-3", className)}>
      {compact ? (
        <LabeledSelect label="Client" value={current.id} onChange={setActive} options={snippets.map((x) => [x.id, x.label] as [string, string])} className="w-full" />
      ) : <div className="-mx-1 flex gap-1 overflow-x-auto px-1">
        {snippets.map((s) => (
          <button key={s.id} type="button" onClick={() => setActive(s.id)} aria-pressed={current.id === s.id}
            className={cn("shrink-0 rounded-md px-2.5 py-1 text-sm transition-colors", current.id === s.id ? "bg-secondary font-medium text-foreground" : "text-muted-foreground hover:bg-accent hover:text-foreground")}>
            {s.label}
          </button>
        ))}
      </div>}
      <CodeBlock code={current.code} wrap={compact} />
      {current.note && <p className="text-xs text-muted-foreground">{current.note}</p>}
    </div>
  )
}
