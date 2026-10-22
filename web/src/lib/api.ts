export type Action = "pull" | "push" | "delete" | "delete_repository" | "scan" | "logs" | "metadata" | "visibility" | "permissions" | "state" | "builds" | "mirror" | "admin"
export type Severity = "critical" | "high" | "medium" | "low" | "negligible" | "unknown"
export type ScanStatus = "pending" | "running" | "done" | "failed"

export type Global = "users:read" | "users:write" | "roles:write" | "gc" | "logs:all" | "catalog" | "orgs:create" | "system"
export type Visibility = "public" | "private"
export interface Me {
  username: string | null
  user_id: number | null
  is_robot: boolean
  is_admin: boolean
  method: "anonymous" | "session" | "bearer" | "password" | "access_token"
  is_mfa_enabled: boolean
  is_managed: boolean
  builds: boolean
  email: string | null
  display_name: string | null
  avatar_url: string | null
  roles: string[]
  globals: Global[]
  auth_mode: "none" | "basic" | "token"
  oidc: string | null
  /** Passkey sign-in is available (the public URL names the registry by domain). */
  passkeys: boolean
  features: { delete: boolean; catalog: boolean; cross_repo_mount: boolean; referrers: boolean }
  scanner: string | null
}
export interface PasskeyInfo { id: number; user_id: number; name: string; sign_count: number; created_at: string; last_used_at: string | null }
/** A WebAuthn ceremony from the server: its id, and the options for `navigator.credentials`. */
export interface PasskeyCeremony { challenge_id: string; options: { publicKey: Record<string, unknown>; mediation?: string | null } }
export interface TagDeletePreview { tag: string; digest: string; other_tags: string[]; index_parents: string[]; referrers: number; is_immutable: boolean }
export interface SyncedTags { id: number; name: string; tags: string[] }
export interface RepoDeletePreview { tags: number; manifests: number; manifest_bytes: number; blob_bytes: number; bytes: number; immutable_tags: string[]; replication: SyncedTags[]; mirrors: SyncedTags[] }
export type DeleteTargets = { repository: true } | { tags: string[] }
export interface DeletePlan { id: string; repository: string; targets: DeleteTargets; expires_at: string; preview: RepoDeletePreview | { tags: TagDeletePreview[] } }
/** The most tags one deletion plan (and one bulk selection) covers. */
export const MAX_BULK_TAGS = 100
export interface Organization { id: number; name: string; display_name: string | null; description: string; created_at: string }
export interface OrgSummary extends Organization { teams: number; is_admin: boolean; is_member: boolean; is_joined?: boolean; sso: string | null }
export interface TeamSync { team_id: number; source: "ldap" | "oidc" | "org-oidc"; group_name: string; created_at: string }
export interface OrgSsoProvider { org_id: number; issuer: string; client_id: string; display_name: string; groups_claim: string | null; updated_at: string }
export interface OrgSsoInfo { provider: OrgSsoProvider | null; callback_url: string; login_url: string; sync_sources: { id: TeamSync["source"]; label: string }[] }
/** Repository access. */
/** Repository access: a preset, or a custom comma list of actions such as `pull,metadata`. */
export type Preset = "read" | "write" | "admin"
export type Level = Preset | (string & {})
export const PRESETS: Record<Preset, Action[]> = { read: ["pull"], write: ["pull", "push", "delete", "scan"], admin: ["admin"] }
export const isPreset = (l: Level): l is Preset => l in PRESETS
export const levelActions = (l: Level): Action[] => (isPreset(l) ? PRESETS[l] : (l.split(",").filter(Boolean) as Action[]))
/** Repository settings actions: any of them opens the Settings tab. */
export const SETTINGS_ACTIONS: Action[] = ["metadata", "visibility", "state", "builds", "mirror", "delete_repository"]
export type TeamRole = "member" | "creator" | "admin"
export interface RepoLevel { repository: string; level: Level }
export interface Team { id: number; org_id: number; name: string; description: string; role: TeamRole; base_permission: Level | null; created_at: string; members: { id: number; username: string; is_robot: boolean }[]; repositories: RepoLevel[]; sync: TeamSync | null }
export type Robot = UserInfo & { repositories: RepoLevel[]; expires_at: string | null; last_used_at: string | null }
export interface RobotUpdate { description?: string; is_disabled?: boolean }
export interface OrgDetail extends Organization { is_admin: boolean; teams: Team[]; robots: Robot[]; repositories: string[]; time_machine_secs: number | null; default_time_machine_secs: number }
export interface TagEvent { id: number; repository: string; tag: string; action: "push" | "move" | "delete" | "restore" | "expire" | "sync" | "import" | "retention" | "cache"; digest: string | null; previous: string | null; actor: string; at: string; is_restorable: boolean }
export interface FederationRule { id?: number; issuer: string; subject: string; audience: string | null }
export interface BuildTrigger { id: number; repository: string; name: string; git_url: string; git_username: string | null; has_token: boolean; branches: string[]; dockerfile: string; context: string; tags: string[]; is_enabled: boolean; created_by: string; created_at: string; webhook_url: string | null
  /** Checks Git this often (seconds); null waits for push webhooks. */
  poll_secs: number | null
  /** Where each matching branch or tag was last seen (by webhook or poll): ref → commit. */
  seen_refs: Record<string, string>; checked_at: string | null; check_error: string | null
  last_build: { id: number; status: BuildStatus; git_ref: string; commit_sha: string | null; created_at: string } | null }
export type BuildStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled"
/** One piece of a build's log, as the log stream sends it. */
export interface BuildLogChunk { seq: number; data: string }

export interface Build { id: number; trigger_id: number | null; repository: string; git_url: string; git_ref: string; commit_sha: string | null; tags: string[]; digest: string | null; status: BuildStatus; message: string | null; actor: string; created_at: string; started_at: string | null; finished_at: string | null; agent: string | null; log?: string
  /** Who started it, for display: the account behind `actor` when there is one. */
  actor_user?: { name: string; display_name: string | null; avatar_url: string | null; via_webhook: boolean; via_poll?: boolean }
  /** Queued builds: older queued builds, and the namespace's running builds against its limit. */
  queue?: { ahead: number; namespace: string; namespace_running: number; namespace_limit: number | null } | null }
export type RunnerStatus = "online" | "offline" | "never"
export interface Runner {
  id: number; name: string
  /** Self-hosted: the user or organization it belongs to. Null: shared. */
  namespace: string | null
  is_all_namespaces: boolean; is_enabled: boolean; is_from_config: boolean; created_by: string; created_at: string
  status: RunnerStatus; last_seen_at: string | null; hostname: string | null; version: string | null; executor: string | null; concurrency: number | null; running: number | null
  /** Shared runners serving chosen namespaces (administrators only). */
  namespaces: string[] | null
}
export interface RunnerInput { name: string; namespace?: string; all_namespaces?: boolean; namespaces?: string[]; is_enabled?: boolean }
export type RunnerWithToken = Runner & { token: string; server_url: string }
export interface TriggerInput { name: string; git_url: string; git_username?: string; git_token?: string; branches: string[]; dockerfile?: string; context?: string; tags: string[]; is_enabled: boolean; poll_secs: number | null }
export interface TagHistory { time_machine_secs: number; events: TagEvent[] }
export type RepoStateKind = "normal" | "read_only" | "mirror"
export interface RepoState { repository: string; state: RepoStateKind; reason: string | null; set_by: string; set_at: string }
export interface RepoGrant { kind: "user" | "robot" | "team"; name: string; display_name: string | null; is_robot: boolean; level: Level }
export interface RepoPermissions { org: string | null; grants: RepoGrant[]; inherited: { source: string; team: string; level: Level }[] }
export interface RepoOrigin {
  kind: "cache" | "mirror" | "import"; registry: string | null; registry_url: string | null; source: string
  via: "registry" | "archive" | null; at: string | null; status: "ok" | "error" | null; message: string | null; actor: string | null; mirror_id: number | null
}
export interface RepoMeta { name: string; description: string; readme: string; visibility: Visibility; topics: string[]; created_at: string | null; updated_at: string | null; actions: Action[]; stars: number; is_starred: boolean; origin: RepoOrigin | null; owner: RepoOwner | null; state: RepoState | null
  /** A runner serves this repository's namespace, so it can be built from Git. */
  builds: boolean }
export interface RepoOwner { kind: "user" | "org"; name: string; display_name: string | null; avatar_url: string | null }
export interface SearchHit { name: string; description: string; visibility: Visibility; tags: number; score: number }
export interface RepoUsage { name: string; namespace: string; tags: number; manifests: number; bytes: number; unique_bytes: number; untagged_bytes: number }
export interface NamespaceUsage { namespace: string; repositories: number; bytes: number; unique_bytes: number; quota: number | null }
export interface UsageReport {
  computed_at: string; physical_bytes: number; blobs: number; logical_bytes: number; dedup_savings: number
  unreferenced_bytes: number; untagged_bytes: number; repositories: RepoUsage[]; namespaces: NamespaceUsage[]
  shared_layers: { digest: string; size: number; repositories: string[] }[]
}
export interface TaskRun { id: number; kind: "gc" | "scan_all"; trigger: "schedule" | "manual"; actor: string; status: "running" | "succeeded" | "failed"; summary: string | null; started_at: string; finished_at: string | null }
export interface TaskRuns { interval: string | null; runs: TaskRun[] }
export type BlockSeverity = "none" | "critical" | "high" | "medium" | "low" | "negligible" | "unknown"
export interface SecurityPolicy { namespace: string; block_severity: BlockSeverity | null; is_block_unscanned: boolean; is_require_signature: boolean; signing_keys: string[]; updated_by: string; updated_at: string }
export interface SecurityPolicyView { policy: SecurityPolicy | null; registry_block_severity: Severity | null; scanner: boolean }
export interface SecurityPolicyInput { block_severity: BlockSeverity | null; is_block_unscanned: boolean; is_require_signature: boolean; signing_keys: string[] }
export interface AllowedCve { id: number; namespace: string | null; cve: string; reason: string; expires_at: string | null; created_by: string; created_at: string }
export type ReplicationTrigger = "push" | "schedule" | "manual"
export interface ReplicationRule {
  id: number; name: string; registry_id: number; repositories: string[]; tags: string[]; destination: string; trigger: ReplicationTrigger
  interval_secs: number | null; is_replicate_deletes: boolean; is_enabled: boolean
  last_run_at: string | null; last_status: "succeeded" | "failed" | null; last_message: string | null; created_by: string; created_at: string
}
export type ReplicationInput = Pick<ReplicationRule, "name" | "registry_id" | "repositories" | "tags" | "destination" | "trigger" | "interval_secs" | "is_replicate_deletes" | "is_enabled">
export type QuotaSource = "namespace" | "default" | "none"
export type WebhookFormat = "default" | "cloudevents" | "slack"
export interface Webhook {
  id: number; namespace: string; name: string; url: string; format: WebhookFormat; events: string[]; repositories: string[]
  is_verify_tls: boolean; is_enabled: boolean; has_secret: boolean; has_auth_header: boolean; created_by: string; created_at: string
  last_delivery: { status: DeliveryStatus; event: string; response_code: number | null; at: string } | null
}
export interface WebhookInput { name: string; url: string; format: WebhookFormat; events: string[]; repositories: string[]; secret?: string; auth_header?: string; is_verify_tls: boolean; is_enabled: boolean }
export type DeliveryStatus = "pending" | "succeeded" | "failed"
export interface WebhookDelivery { id: number; webhook_id: number; event: string; payload: string; status: DeliveryStatus; attempts: number; response_code: number | null; response_body: string | null; error: string | null; duration_ms: number | null; created_at: string; delivered_at: string | null }
export interface NamespaceStorage { namespace: string; bytes: number; unique_bytes: number; quota: number | null; quota_source: QuotaSource; default_quota: number | null; repositories: RepoUsage[]; computed_at: string }
export interface RetentionPolicy {
  id: number; namespace: string; repositories: string; keep_last: number | null; max_age_days: number | null
  protect: string[]; is_enabled: boolean; created_at: string; last_run_at: string | null; last_deleted: number | null
}
export type RetentionInput = Pick<RetentionPolicy, "repositories" | "keep_last" | "max_age_days" | "protect" | "is_enabled">
export interface RetentionOutcome { policy: number; repositories: number; kept_protected: number; deletions: { repository: string; tag: string; digest: string; pushed_at: string | null; reason: string }[] }
export interface UpstreamRegistry { id: number; name: string; url: string; username: string | null; is_insecure: boolean; created_at: string }
export interface RegistryInput { name: string; url: string; username?: string; password?: string; is_insecure: boolean }
export interface ProxyCache { namespace: string; registry_id: number; ttl_secs: number; is_public: boolean; created_at: string }
export interface Mirror {
  id: number; registry_id: number; source: string; target: string; tags: string[]; interval_secs: number; is_enabled: boolean
  created_at: string; last_sync_at: string | null; last_status: "ok" | "error" | null; last_message: string | null
}
export type MirrorInput = Pick<Mirror, "registry_id" | "source" | "target" | "tags" | "interval_secs" | "is_enabled">
export interface Job { id: string; kind: string; title: string; actor: string; status: "running" | "done" | "failed" | "cancelled"; message: string | null; started_at: string; finished_at: string | null; instance: string; is_cancel_requested: boolean }
export interface HealthCheck { name: string; group: string; status: "ok" | "warn" | "error"; message: string; latency_ms?: number }
export interface HealthReport { status: "ok" | "warn" | "error"; version: string; uptime_seconds: number; checked_at: string; checks: HealthCheck[] }
export interface About {
  name: string; version: string; description: string; commit: string | null; built_at: string | null; rustc: string | null
  license: string; license_text: string; homepage: string | null; repository: string | null
  runtime: { os: string; arch: string; uptime_seconds: number; storage: string; auth: string; scanner: string | null; metrics: "on" | "off" | "no token" }
}
export interface StarState { stars: number; is_starred: boolean }
export interface StarredRepo { name: string; description: string; visibility: Visibility; tags: number; stars: number; updated_at: string | null }
export interface Profile { display_name: string | null; company: string | null; location: string | null; website: string | null; gravatar_email: string | null }
export interface ExploreEntry { name: string; description: string; topics: string[]; tags: number; updated_at: string; created_at: string; org: string | null; stars: number; latest: { tag: string | null; pushed_at: string | null; platforms: string[] } }
export interface Rule { repositories: string[]; actions: Action[] }
export interface Role { name: string; description: string; rules: Rule[]; global: Global[]; is_managed: boolean }
export interface UserInfo {
  id: number; username: string; email: string | null; display_name: string | null; is_robot: boolean
  owner_id: number | null; owner: string | null; is_disabled: boolean; is_managed: boolean; is_mfa_enabled: boolean
  created_at: string; last_login_at: string | null; roles: string[]; identities: string[]
}
export interface AccessTokenInfo {
  id: number; name: string; hint: string; created_at: string; expires_at: string | null; last_used_at: string | null; scopes: Rule[] | null
}
export interface SessionInfo { id: string; created_at: string; expires_at: string; user_agent: string | null; ip: string | null; is_current: boolean }
export interface Permissions { actions: { name: Action; description: string }[]; global: { name: Global; description: string }[] }
export interface RepoSummary { name: string; tags: number; actions: Action[]; visibility: Visibility; description: string; topics: string[]; updated_at: string | null; stars: number; is_starred: boolean; origin: RepoOrigin | null }
export interface ScanBrief { status: ScanStatus; total: number; summary: Partial<Record<Severity, number>>; max_severity: Severity | null }
export interface PlatformRow { digest: string; platform?: string; size: number; scan?: ScanBrief }
export type ArtifactKind = "image" | "index" | "helm_chart" | "wasm" | "sbom" | "signature" | "attestation" | "artifact"
export interface ArtifactInfo { kind: ArtifactKind; label: string; media_type: string | null }
export interface Attached extends ArtifactInfo { digest: string; tag?: string; size: number; annotations?: Record<string, string> }
export interface TagInfo { tag: string; digest: string; media_type: string; size: number; kind: "image" | "index"; pushed_at?: string; expires_at?: string; scan?: ScanBrief; platforms: PlatformRow[]; artifact: ArtifactInfo; attached_to?: string }
export interface SbomPackage { name: string; version: string | null; type: string | null; purl: string | null; licenses: string[] }
export interface SbomView { document: string; media_type: string; sbom: { format: string; spec_version: string | null; created: string | null; tools: string[]; packages: SbomPackage[] } }
export interface SignatureCheck { signature: string; status: "verified" | "invalid" | "mismatch" | "keyless" | "malformed"; detail: string }
export interface VerifyResult { digest: string; verified: boolean; signatures: SignatureCheck[] }
export interface CompareSide { reference: string; digest: string; platform: string | null; created: string | null; size: number; layers: number }
export interface CompareResult {
  a: CompareSide; b: CompareSide; size_delta: number; shared_bytes: number
  layers: { status: "shared" | "changed" | "added" | "removed" | "moved"; digest: string; size: number; created_by: string | null; previous_size?: number; previous_digest?: string }[]
  changes: { field: string; before: string | null; after: string | null }[]
}
export interface Descriptor {
  mediaType: string; digest: string; size: number; artifactType?: string
  platform?: { architecture: string; os: string; variant?: string }
  annotations?: Record<string, string>
}
export interface LayerInfo {
  digest: string; media_type: string; size: number
  created_by?: string; created?: string; comment?: string; diff_id?: string; urls?: string[]
}
export interface HistoryEntry { created?: string; created_by?: string; comment?: string; empty_layer: boolean }
export interface ImageConfig {
  architecture?: string; os?: string; created?: string; author?: string
  config?: {
    Env?: string[]; Cmd?: string[]; Entrypoint?: string[]; WorkingDir?: string; User?: string
    Labels?: Record<string, string>; ExposedPorts?: Record<string, unknown>; Volumes?: Record<string, unknown>
  }
  history: HistoryEntry[]
}
export interface ManifestDetail {
  repository: string; reference: string; digest: string; media_type: string; size: number
  kind: "image" | "index"; artifact_type?: string; annotations?: Record<string, string>
  subject?: Descriptor; tags: string[]; config?: Descriptor; image?: ImageConfig
  layers: LayerInfo[]; total_size: number; history: HistoryEntry[]
  manifests: Descriptor[]; platforms: PlatformRow[]; referrers: Descriptor[]; scan?: ScanBrief; raw: unknown
  artifact: ArtifactInfo; attached: Attached[]; config_json?: Record<string, unknown>; attached_to?: string
}
export interface Vulnerability {
  id: string; severity: Severity; package: string; installed_version?: string; fixed_version?: string
  title?: string; url?: string; layer?: string; target?: string
}
export interface ScanReport {
  status: ScanStatus; scanner: string; scanner_version?: string; digest: string; repository: string
  started_at?: string; finished_at?: string; error?: string
  summary: Partial<Record<Severity, number>>; total: number; vulnerabilities: Vulnerability[]
  /** Findings this namespace's pull policy ignores (CVE allowlists). */
  allowlisted?: string[]
}
export interface LayerEntry {
  path: string; type: string; size: number; mode: string; link_target?: string; mtime?: number; is_whiteout?: boolean
}
export interface LayerListing {
  digest: string; media_type: string; compression: string; entries: LayerEntry[]; is_truncated: boolean; total_uncompressed: number
}
export interface GcReport {
  is_dry_run: boolean; repositories: number; manifests_kept: number; manifests_removed: string[]
  links_removed: string[]; blobs_removed: string[]; scans_removed: string[]; bytes_freed: number; skipped_recent: number
}
export interface AuditEntry {
  id: string; timestamp: string; action: string; actor: string; is_robot: boolean
  repository?: string; reference?: string; digest?: string; detail?: string; org?: string
}

/** Error body of every endpoint outside `/v2/`. */
export interface ApiErrorBody { code: string; message: string; details: Record<string, unknown> }

export class ApiError extends Error {
  status: number
  /** `BAD_REQUEST`, `NOT_FOUND`, `CONFLICT`, `DENIED`, ... */
  code?: string
  details: Record<string, unknown>
  body: unknown
  constructor(status: number, message: string, body?: unknown) {
    super(message)
    this.status = status
    this.body = body
    const b = body as Partial<ApiErrorBody> | undefined
    this.code = b?.code
    this.details = b?.details ?? {}
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json")
  const res = await fetch(path, { ...init, headers, credentials: "same-origin" })
  if (!res.ok) {
    let message = res.statusText
    let body: unknown
    try { body = await res.json(); const b = body as Partial<ApiErrorBody> & { errors?: { message?: string }[] }; message = b?.message ?? b?.errors?.[0]?.message ?? message } catch { /* ignore */ }
    throw new ApiError(res.status, message, body)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}
const post = <T,>(path: string, body?: unknown, method = "POST") => api<T>(path, { method, body: body === undefined ? undefined : JSON.stringify(body) })

const enc = (s: string) => s.split("/").map(encodeURIComponent).join("/")

export const endpoints = {
  me: () => api<Me>("/api/v1/me"),
  repositories: () => api<RepoSummary[]>("/api/v1/repositories"),
  /** One repository's listing entry; one created empty has `tags: 0`. */
  repository: (name: string) => api<RepoSummary>(`/api/v1/repositories/${enc(name)}`),
  /** Create an empty repository (to set up builds, permissions or a README before a push). */
  createRepository: (r: { name: string; description?: string; visibility?: Visibility; topics?: string[] }) => post<RepoMeta>("/api/v1/repositories", r),
  tags: (repo: string) => api<TagInfo[]>(`/api/v1/repositories/${enc(repo)}/tags`),
  manifest: (repo: string, ref: string) => api<ManifestDetail>(`/api/v1/repositories/${enc(repo)}/manifests/${encodeURIComponent(ref)}`),
  sbom: (repo: string, ref: string) => api<SbomView>(`/api/v1/repositories/${enc(repo)}/manifests/${encodeURIComponent(ref)}/sbom`),
  verify: (repo: string, ref: string, public_key: string) => post<VerifyResult>(`/api/v1/repositories/${enc(repo)}/manifests/${encodeURIComponent(ref)}/verify`, { public_key }),
  compare: (repo: string, a: string, b: string, platform?: string) =>
    api<CompareResult>(`/api/v1/repositories/${enc(repo)}/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}${platform ? `&platform=${encodeURIComponent(platform)}` : ""}`),
  scan: (repo: string, ref: string) => api<ScanReport>(`/api/v1/repositories/${enc(repo)}/manifests/${encodeURIComponent(ref)}/scan`),
  triggerScan: (repo: string, ref: string) => api<{ queued: string[] }>(`/api/v1/repositories/${enc(repo)}/manifests/${encodeURIComponent(ref)}/scan`, { method: "POST" }),
  layerFiles: (repo: string, ref: string, layer: string, limit = 3000) =>
    api<LayerListing>(`/api/v1/repositories/${enc(repo)}/manifests/${encodeURIComponent(ref)}/layers/${layer}/files?limit=${limit}`),
  deleteManifest: (repo: string, ref: string) => api<void>(`/v2/${enc(repo)}/manifests/${encodeURIComponent(ref)}`, { method: "DELETE" }),
  tagDeletePreview: (repo: string, tag: string) => api<TagDeletePreview>(`/api/v1/repositories/${enc(repo)}/tags/${encodeURIComponent(tag)}/delete-preview`),
  repoDeletePreview: (repo: string) => api<RepoDeletePreview>(`/api/v1/repositories/${enc(repo)}/delete-preview`),
  /** Deleting a repository, or several tags, is a plan executed with the repository name typed back. */
  deletePlan: (repo: string, targets: DeleteTargets) => post<DeletePlan>(`/api/v1/repositories/${enc(repo)}/delete-plan`, targets),
  executeDeletePlan: (id: string, confirm: string) => post<{ id: string; deleted: { repository?: string; tags?: string[] } }>(`/api/v1/delete-plans/${encodeURIComponent(id)}/execute`, { confirm }),
  gc: (dryRun: boolean, deleteUntagged: boolean) => api<GcReport>(`/api/v1/gc?dry_run=${dryRun}&delete_untagged=${deleteUntagged}`, { method: "POST" }),
  logs: (f: { repository?: string; q?: string; namespace?: string; limit?: number } = {}) => {
    const p = new URLSearchParams({ limit: String(f.limit ?? 200) })
    for (const k of ["repository", "q", "namespace"] as const) if (f[k]) p.set(k, f[k]!)
    return api<AuditEntry[]>(`/api/v1/logs?${p}`)
  },
  // accounts
  login: (username: string, password: string, otp?: string, recovery_code?: string) => post<{ ok: boolean }>("/api/v1/auth/login", { username, password, otp, recovery_code }),
  logout: () => post<void>("/api/v1/auth/logout"),
  changePassword: (current_password: string, new_password: string) => post<void>("/api/v1/auth/password", { current_password, new_password }),
  passkeys: () => api<PasskeyInfo[]>("/api/v1/auth/passkeys"),
  deletePasskey: (id: number) => post<void>(`/api/v1/auth/passkeys/${id}`, undefined, "DELETE"),
  passkeyRegisterStart: (name: string) => post<PasskeyCeremony>("/api/v1/auth/passkeys/register/start", { name }),
  passkeyRegisterFinish: (challenge_id: string, credential: unknown) => post<PasskeyInfo>("/api/v1/auth/passkeys/register/finish", { challenge_id, credential }),
  passkeyLoginStart: (username?: string) => post<PasskeyCeremony>("/api/v1/auth/passkeys/login/start", { username: username || undefined }),
  passkeyLoginFinish: (challenge_id: string, credential: unknown) => post<{ ok: boolean; username: string }>("/api/v1/auth/passkeys/login/finish", { challenge_id, credential }),
  mfaSetup: () => post<{ secret: string; otpauth_url: string; qr_svg: string }>("/api/v1/auth/mfa/setup"),
  mfaEnable: (code: string) => post<{ recovery_codes: string[] }>("/api/v1/auth/mfa/enable", { code }),
  mfaDisable: (code: string, password?: string) => post<void>("/api/v1/auth/mfa/disable", { code, password }),
  mfaRecoveryCodes: (code: string) => post<{ recovery_codes: string[] }>("/api/v1/auth/mfa/recovery-codes", { code }),
  tokens: () => api<AccessTokenInfo[]>("/api/v1/auth/tokens"),
  createToken: (name: string, expires_in_days?: number) => post<{ token: string; id: number }>("/api/v1/auth/tokens", { name, expires_in_days }),
  deleteToken: (id: number) => post<void>(`/api/v1/auth/tokens/${id}`, undefined, "DELETE"),
  sessions: () => api<SessionInfo[]>("/api/v1/auth/sessions"),
  deleteSession: (id: string) => post<void>(`/api/v1/auth/sessions/${id}`, undefined, "DELETE"),
  robots: () => api<Robot[]>("/api/v1/auth/robots"),
  createRobot: (name: string, description?: string, expires_in_days?: number) => post<{ id: number; username: string; token: string }>("/api/v1/auth/robots", { name, description, expires_in_days }),
  updateRobot: (id: number, u: RobotUpdate) => post<Robot>(`/api/v1/auth/robots/${id}`, u, "PATCH"),
  deleteRobot: (id: number) => post<void>(`/api/v1/auth/robots/${id}`, undefined, "DELETE"),
  robotFederation: (id: number) => api<FederationRule[]>(`/api/v1/robots/${id}/federation`),
  setRobotFederation: (id: number, rules: FederationRule[]) => post<FederationRule[]>(`/api/v1/robots/${id}/federation`, { rules }, "PUT"),
  rotateRobot: (id: number) => post<{ username: string; token: string }>(`/api/v1/auth/robots/${id}/rotate`),
  // admin
  permissions: () => api<Permissions>("/api/v1/permissions"),
  roles: () => api<Role[]>("/api/v1/roles"),
  createRole: (r: Omit<Role, "is_managed">) => post<Role>("/api/v1/roles", r),
  updateRole: (name: string, r: Omit<Role, "is_managed" | "name">) => post<Role>(`/api/v1/roles/${encodeURIComponent(name)}`, r, "PUT"),
  deleteRole: (name: string) => post<void>(`/api/v1/roles/${encodeURIComponent(name)}`, undefined, "DELETE"),
  users: () => api<UserInfo[]>("/api/v1/users"),
  createUser: (u: { username: string; password?: string; email?: string; display_name?: string; roles: string[]; is_robot: boolean }) => post<UserInfo & { token?: string }>("/api/v1/users", u),
  updateUser: (id: number, u: { email?: string; display_name?: string; is_disabled?: boolean; roles?: string[] }) => post<UserInfo>(`/api/v1/users/${id}`, u, "PATCH"),
  // organizations
  orgs: () => api<OrgSummary[]>("/api/v1/orgs"),
  orgSso: (org: string) => api<OrgSsoInfo>(`/api/v1/orgs/${encodeURIComponent(org)}/sso`),
  setOrgSso: (org: string, s: { issuer: string; client_id: string; client_secret?: string; display_name?: string; groups_claim?: string }) => post<OrgSsoInfo>(`/api/v1/orgs/${encodeURIComponent(org)}/sso`, s, "PUT"),
  deleteOrgSso: (org: string) => post<void>(`/api/v1/orgs/${encodeURIComponent(org)}/sso`, undefined, "DELETE"),
  setTeamSync: (org: string, team: string, source: string, group: string) => post<void>(`/api/v1/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(team)}/sync`, { source, group }, "PUT"),
  clearTeamSync: (org: string, team: string) => post<void>(`/api/v1/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(team)}/sync`, undefined, "DELETE"),
  org: (name: string) => api<OrgDetail>(`/api/v1/orgs/${encodeURIComponent(name)}`),
  createOrg: (name: string, display_name?: string, description?: string) => post<Organization>("/api/v1/orgs", { name, display_name, description }),
  changeUsername: (username: string) => post<{ username: string }>("/api/v1/auth/username", { username }),
  buildTriggers: (repo: string) => api<BuildTrigger[]>(`/api/v1/build-triggers?repository=${encodeURIComponent(repo)}`),
  createBuildTrigger: (repo: string, t: TriggerInput) => post<BuildTrigger & { secret: string }>("/api/v1/build-triggers", { repository: repo, ...t }),
  updateBuildTrigger: (id: number, t: TriggerInput) => post<BuildTrigger>(`/api/v1/build-triggers/${id}`, t, "PUT"),
  deleteBuildTrigger: (id: number) => post<void>(`/api/v1/build-triggers/${id}`, undefined, "DELETE"),
  rotateBuildSecret: (id: number) => post<{ secret: string; webhook_url: string }>(`/api/v1/build-triggers/${id}/secret`),
  checkBuildTrigger: (id: number) => post<BuildTrigger & { queued: number[] }>(`/api/v1/build-triggers/${id}/check`),
  runners: () => api<Runner[]>("/api/v1/runners"),
  namespaceRunners: (ns: string) => api<{ runners: Runner[]; self_hosted: boolean }>(`/api/v1/namespaces/${encodeURIComponent(ns)}/runners`),
  createRunner: (i: RunnerInput) => post<RunnerWithToken>("/api/v1/runners", i),
  updateRunner: (id: number, i: RunnerInput) => post<Runner>(`/api/v1/runners/${id}`, i, "PUT"),
  rotateRunnerToken: (id: number) => post<RunnerWithToken>(`/api/v1/runners/${id}/token`),
  deleteRunner: (id: number) => post<void>(`/api/v1/runners/${id}`, undefined, "DELETE"),
  runBuild: (id: number, ref?: string, tags?: string[]) => post<{ build: number; superseded: number[] }>(`/api/v1/build-triggers/${id}/run`, { ref, tags }),
  builds: (repo: string) => api<Build[]>(`/api/v1/builds?repository=${encodeURIComponent(repo)}`),
  /** `withLog: false` leaves the log out, for a build whose log is followed on its stream. */
  build: (id: number, withLog = true) => api<Build>(`/api/v1/builds/${id}${withLog ? "" : "?log=false"}`),
  /** Server-sent events: `{seq, data}` per log chunk (event id = seq), then `done` with `{status, message}`. */
  buildLogStream: (id: number) => `/api/v1/builds/${id}/log/stream`,
  cancelBuild: (id: number) => post<void>(`/api/v1/builds/${id}/cancel`),
  tagHistory: (repo: string, tag?: string) => api<TagHistory>(`/api/v1/repositories/${enc(repo)}/history${tag ? `?tag=${encodeURIComponent(tag)}` : ""}`),
  restoreTag: (repo: string, tag: string, digest: string) => post<void>(`/api/v1/repositories/${enc(repo)}/tags/${encodeURIComponent(tag)}/restore`, { digest }),
  setTagExpiration: (repo: string, tag: string, expires_at: string | null) => post<{ expires_at: string | null }>(`/api/v1/repositories/${enc(repo)}/tags/${encodeURIComponent(tag)}/expiration`, { expires_at }, "PUT"),
  setRepoState: (repo: string, state: RepoStateKind, reason?: string) => post<void>(`/api/v1/repositories/${enc(repo)}/state`, { state, reason }, "PUT"),
  updateOrg: (name: string, u: { name?: string; display_name?: string; description?: string; time_machine_secs?: number | null }) => post<Organization>(`/api/v1/orgs/${encodeURIComponent(name)}`, u, "PATCH"),
  deleteOrg: (name: string) => post<void>(`/api/v1/orgs/${encodeURIComponent(name)}`, undefined, "DELETE"),
  createTeam: (org: string, t: { name: string; description: string; role: TeamRole; base_permission: Level | null }) => post<Team>(`/api/v1/orgs/${encodeURIComponent(org)}/teams`, t),
  updateTeam: (org: string, team: string, t: { description: string; role: TeamRole; base_permission: Level | null }) => post<Team>(`/api/v1/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(team)}`, t, "PUT"),
  repoPermissions: (name: string) => api<RepoPermissions>(`/api/v1/repository-permissions/${enc(name)}`),
  setRepoPermission: (name: string, kind: "user" | "team", subject: string, level: Level | null) => post<RepoPermissions>(`/api/v1/repository-permissions/${enc(name)}`, { kind, name: subject, level }, "PUT"),
  deleteTeam: (org: string, team: string) => post<void>(`/api/v1/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(team)}`, undefined, "DELETE"),
  addMember: (org: string, team: string, username: string) => post<void>(`/api/v1/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(team)}/members`, { username }),
  removeMember: (org: string, team: string, username: string) => post<void>(`/api/v1/orgs/${encodeURIComponent(org)}/teams/${encodeURIComponent(team)}/members/${encodeURIComponent(username)}`, undefined, "DELETE"),
  createOrgRobot: (org: string, name: string, teams: string[], description?: string, expires_in_days?: number) => post<{ id: number; username: string; token: string }>(`/api/v1/orgs/${encodeURIComponent(org)}/robots`, { name, teams, description, expires_in_days }),
  updateOrgRobot: (org: string, id: number, u: RobotUpdate) => post<Robot>(`/api/v1/orgs/${encodeURIComponent(org)}/robots/${id}`, u, "PATCH"),
  deleteOrgRobot: (org: string, id: number) => post<void>(`/api/v1/orgs/${encodeURIComponent(org)}/robots/${id}`, undefined, "DELETE"),
  rotateOrgRobot: (org: string, id: number) => post<{ username: string; token: string }>(`/api/v1/orgs/${encodeURIComponent(org)}/robots/${id}/rotate`),
  // repository catalogue
  explore: (q?: string, topic?: string) => api<{ repositories: ExploreEntry[]; topics: string[] }>(`/api/v1/explore?q=${encodeURIComponent(q ?? "")}&topic=${encodeURIComponent(topic ?? "")}`),
  profile: () => api<Profile>("/api/v1/auth/profile"),
  updateProfile: (p: Profile) => post<Profile>("/api/v1/auth/profile", p, "PUT"),
  stars: () => api<StarredRepo[]>("/api/v1/stars"),
  setStar: (name: string, starred: boolean) => api<StarState>(`/api/v1/stars/${enc(name)}`, { method: starred ? "PUT" : "DELETE" }),
  search: (q: string, limit = 8) => api<SearchHit[]>(`/api/v1/search?q=${encodeURIComponent(q)}&limit=${limit}`),
  storageReport: (refresh = false) => api<UsageReport>(`/api/v1/storage${refresh ? "?refresh=1" : ""}`),
  namespaceStorage: (ns: string, refresh = false) => api<NamespaceStorage>(`/api/v1/namespaces/${encodeURIComponent(ns)}/storage${refresh ? "?refresh=1" : ""}`),
  webhookEvents: () => api<{ events: string[]; formats: WebhookFormat[] }>("/api/v1/webhook-events"),
  webhooks: (ns: string) => api<Webhook[]>(`/api/v1/namespaces/${encodeURIComponent(ns)}/webhooks`),
  createWebhook: (ns: string, w: WebhookInput) => post<Webhook>(`/api/v1/namespaces/${encodeURIComponent(ns)}/webhooks`, w),
  updateWebhook: (ns: string, id: number, w: WebhookInput) => post<Webhook>(`/api/v1/namespaces/${encodeURIComponent(ns)}/webhooks/${id}`, w, "PUT"),
  deleteWebhook: (ns: string, id: number) => post<void>(`/api/v1/namespaces/${encodeURIComponent(ns)}/webhooks/${id}`, undefined, "DELETE"),
  testWebhook: (ns: string, id: number) => post<WebhookDelivery>(`/api/v1/namespaces/${encodeURIComponent(ns)}/webhooks/${id}/test`),
  webhookDeliveries: (ns: string, id: number) => api<WebhookDelivery[]>(`/api/v1/namespaces/${encodeURIComponent(ns)}/webhooks/${id}/deliveries`),
  redeliverWebhook: (ns: string, id: number, delivery: number) => post<WebhookDelivery>(`/api/v1/namespaces/${encodeURIComponent(ns)}/webhooks/${id}/deliveries/${delivery}/redeliver`),
  taskRuns: (kind: "gc" | "scan_all") => api<TaskRuns>(`/api/v1/maintenance/${kind}/runs`),
  scanAll: (missingOnly: boolean) => post<{ images: number; queued: number; current: number }>(`/api/v1/scans/all${missingOnly ? "?missing_only=true" : ""}`),
  securityPolicy: (ns: string) => api<SecurityPolicyView>(`/api/v1/namespaces/${encodeURIComponent(ns)}/security`),
  setSecurityPolicy: (ns: string, p: SecurityPolicyInput) => post<SecurityPolicyView>(`/api/v1/namespaces/${encodeURIComponent(ns)}/security`, p, "PUT"),
  cveAllowlist: (ns: string | null) => api<AllowedCve[]>(ns ? `/api/v1/namespaces/${encodeURIComponent(ns)}/cve-allowlist` : "/api/v1/cve-allowlist"),
  allowCve: (ns: string | null, e: { cve: string; reason: string; expires_at: string | null }) => post<AllowedCve>(ns ? `/api/v1/namespaces/${encodeURIComponent(ns)}/cve-allowlist` : "/api/v1/cve-allowlist", e),
  disallowCve: (ns: string | null, id: number) => post<void>(ns ? `/api/v1/namespaces/${encodeURIComponent(ns)}/cve-allowlist/${id}` : `/api/v1/cve-allowlist/${id}`, undefined, "DELETE"),
  replicationRules: () => api<ReplicationRule[]>("/api/v1/replication-rules"),
  createReplicationRule: (r: ReplicationInput) => post<ReplicationRule>("/api/v1/replication-rules", r),
  updateReplicationRule: (id: number, r: ReplicationInput) => post<ReplicationRule>(`/api/v1/replication-rules/${id}`, r, "PUT"),
  deleteReplicationRule: (id: number) => post<void>(`/api/v1/replication-rules/${id}`, undefined, "DELETE"),
  runReplicationRule: (id: number) => post<void>(`/api/v1/replication-rules/${id}/run`),
  replicationRuns: (id: number) => api<TaskRun[]>(`/api/v1/replication-rules/${id}/runs`),
  setQuota: (ns: string, max_bytes: number | null) => post<unknown>(`/api/v1/namespaces/${encodeURIComponent(ns)}/quota`, { max_bytes }, "PUT"),
  retention: (ns: string) => api<RetentionPolicy[]>(`/api/v1/namespaces/${encodeURIComponent(ns)}/retention`),
  createRetention: (ns: string, p: RetentionInput) => post<RetentionPolicy>(`/api/v1/namespaces/${encodeURIComponent(ns)}/retention`, p),
  updateRetention: (ns: string, id: number, p: RetentionInput) => post<RetentionPolicy>(`/api/v1/namespaces/${encodeURIComponent(ns)}/retention/${id}`, p, "PUT"),
  deleteRetention: (ns: string, id: number) => post<void>(`/api/v1/namespaces/${encodeURIComponent(ns)}/retention/${id}`, undefined, "DELETE"),
  previewRetention: (ns: string, id: number) => post<RetentionOutcome>(`/api/v1/namespaces/${encodeURIComponent(ns)}/retention/${id}/preview`),
  runRetention: (ns: string, id: number) => post<RetentionOutcome>(`/api/v1/namespaces/${encodeURIComponent(ns)}/retention/${id}/run`),
  registries: () => api<UpstreamRegistry[]>("/api/v1/registries"),
  createRegistry: (r: RegistryInput) => post<UpstreamRegistry>("/api/v1/registries", r),
  updateRegistry: (id: number, r: RegistryInput) => post<UpstreamRegistry>(`/api/v1/registries/${id}`, r, "PUT"),
  deleteRegistry: (id: number) => post<void>(`/api/v1/registries/${id}`, undefined, "DELETE"),
  testRegistry: (id: number, repository?: string) => post<{ ok: boolean; message: string; latency_ms?: number; tags?: string[] }>(`/api/v1/registries/${id}/test`, { repository }),
  proxyCaches: () => api<ProxyCache[]>("/api/v1/proxy-caches"),
  createProxyCache: (p: { namespace: string; registry_id: number; ttl_secs: number; is_public: boolean }) => post<ProxyCache>("/api/v1/proxy-caches", p),
  deleteProxyCache: (ns: string) => post<void>(`/api/v1/proxy-caches/${encodeURIComponent(ns)}`, undefined, "DELETE"),
  mirrors: () => api<Mirror[]>("/api/v1/mirrors"),
  createMirror: (m: MirrorInput) => post<Mirror>("/api/v1/mirrors", m),
  updateMirror: (id: number, m: MirrorInput) => post<Mirror>(`/api/v1/mirrors/${id}`, m, "PUT"),
  deleteMirror: (id: number) => post<void>(`/api/v1/mirrors/${id}`, undefined, "DELETE"),
  syncMirror: (id: number) => post<{ job: string }>(`/api/v1/mirrors/${id}/sync`),
  importImage: (b: { registry_id: number; source: string; reference: string; target: string; tag?: string }) => post<{ job: string }>("/api/v1/import", b),
  importArchive: (target: string, file: File, tag?: string) =>
    api<{ tags: string[]; manifests: number; blobs: number }>(`/api/v1/import/archive/${enc(target)}?${new URLSearchParams({ filename: file.name, ...(tag ? { tag } : {}) })}`, { method: "POST", body: file, headers: { "content-type": "application/x-tar" } }),
  jobs: () => api<Job[]>("/api/v1/jobs"),
  health: () => api<HealthReport>("/api/v1/health"),
  directory: (kind: "user" | "robot" | "team", q: string, namespace?: string) =>
    api<DirectoryEntry[]>(`/api/v1/directory?${new URLSearchParams({ kind, q, ...(namespace ? { namespace } : {}) })}`),
  storageLocations: () => api<StorageLocations>("/api/v1/admin/storage"),
  syncReplicas: () => api<{ job: string }>("/api/v1/admin/storage/sync", { method: "POST" }),
  about: () => api<About>("/api/v1/about"),
  exportUrl: (repo: string, ref: string) => `/api/v1/repositories/${enc(repo)}/manifests/${encodeURIComponent(ref)}/export`,
  repoMeta: (name: string) => api<RepoMeta>(`/api/v1/repository-meta/${enc(name)}`),
  updateRepoMeta: (name: string, u: { description?: string; readme?: string; visibility?: Visibility; topics?: string[] }) => post<RepoMeta>(`/api/v1/repository-meta/${enc(name)}`, u, "PATCH"),
  deleteUser: (id: number) => post<void>(`/api/v1/users/${id}`, undefined, "DELETE"),
  resetPassword: (id: number, password: string) => post<void>(`/api/v1/users/${id}/password`, { password }),
  resetMfa: (id: number) => post<void>(`/api/v1/users/${id}/mfa`, undefined, "DELETE"),
  revokeSessions: (id: number) => post<void>(`/api/v1/users/${id}/sessions`, undefined, "DELETE"),
}

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "negligible", "unknown"]

export function formatBytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"]
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${i ? v.toFixed(1) : v} ${units[i]}`
}
export const shortDigest = (d?: string) => (d ?? "").replace(/^sha\d+:/, "").slice(0, 12)
export function cleanCommand(s?: string): string {
  return (s ?? "")
    .replace(/^\/bin\/sh -c #\(nop\)\s*/, "")
    .replace(/^\/bin\/sh -c /, "RUN ")
    .replace(/\s*# buildkit$/, "")
}


export interface LocationStats { copied: number; copied_bytes: number; failed: number; last_error: string | null; last_error_at: string | null }
export interface StorageLocation {
  name: string
  /** `unknown`: no longer configured, but the database still records blobs there. */
  driver: "filesystem" | "s3" | "gcs" | "azure" | "memory" | "unknown"
  redirect: boolean
  regions: string[]
  /** This instance's preferred location (where it writes). */
  preferred: boolean
  configured: boolean
  blobs: number
  bytes: number
  /** Copies to here waiting or in progress, and given up on. */
  pending: number
  failed: number
  last_error: string | null
  last_error_at: string | null
  /** Copies this instance made to here since it started. */
  stats: LocationStats
}
export interface StorageLocations {
  primary: StorageLocation
  replicas: StorageLocation[]
  locations: StorageLocation[]
  unknown_locations: string[]
  region_header: string | null
  redirect_ttl_secs: number
  replication_interval_secs: number
  pending: number
  failed: number
  syncing: boolean
}

/** Someone who can be granted access: a person, robot or team. */
export interface DirectoryEntry { name: string; display_name: string | null; avatar_url: string | null }
