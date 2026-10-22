{{/* Shared with the kontainer-runner chart: keep the two in step. */}}
{{/* A map as a TOML inline table: { "a" = "b" }. */}}
{{- define "runner.tomlTable" -}}
{{- $parts := list }}
{{- range $k, $v := . }}
{{- $parts = append $parts (printf "%s = %s" (quote $k) (quote $v)) }}
{{- end }}
{{- printf "{ %s }" (join ", " $parts) }}
{{- end }}

{{/*
The runner's container. Context: dict with
  root      the chart's context
  server    the registry URL
  secret    the Secret with the token (key `token`)
  runnerName  optional: the name shown on builds (defaults to the pod's)
  values    the runner settings (concurrency, builds, extraEnv, resources, securityContext)
*/}}
{{- define "runner.container" -}}
{{- $v := .values -}}
{{- $b := $v.builds -}}
- name: runner
  image: {{ .image }}
  imagePullPolicy: {{ .pullPolicy }}
  args: [runner]
  env:
    - name: KONTAINER_SERVER
      value: {{ .server | quote }}
    - name: KONTAINER_RUNNER_TOKEN
      valueFrom: { secretKeyRef: { name: {{ .secret }}, key: token } }
    {{- with .runnerName }}
    - name: KONTAINER_RUNNER_NAME
      value: {{ . | quote }}
    {{- end }}
    - name: KONTAINER_RUNNER__EXECUTOR
      value: kubernetes
    - name: KONTAINER_RUNNER__CONCURRENCY
      value: {{ $v.concurrency | quote }}
    - name: KONTAINER_RUNNER__KUBERNETES__NAMESPACE
      value: {{ .buildsNamespace | quote }}
    - name: KONTAINER_RUNNER__KUBERNETES__IMAGE
      value: {{ .image | quote }}
    - name: KONTAINER_RUNNER__KUBERNETES__CPU
      value: {{ $b.cpu | quote }}
    - name: KONTAINER_RUNNER__KUBERNETES__MEMORY
      value: {{ $b.memory | quote }}
    - name: KONTAINER_RUNNER__KUBERNETES__EPHEMERAL_STORAGE
      value: {{ $b.ephemeralStorage | quote }}
    {{- with $b.nodeSelector }}
    - name: KONTAINER_RUNNER__KUBERNETES__NODE_SELECTOR
      value: {{ include "runner.tomlTable" . | quote }}
    {{- end }}
    {{- with $b.tolerations }}
    {{- $items := list }}
    {{- range . }}{{ $items = append $items (include "runner.tomlTable" .) }}{{ end }}
    - name: KONTAINER_RUNNER__KUBERNETES__TOLERATIONS
      value: {{ printf "[%s]" (join ", " $items) | quote }}
    {{- end }}
    {{- with .imagePullSecrets }}
    {{- $names := list }}
    {{- range . }}{{ $names = append $names (quote .name) }}{{ end }}
    - name: KONTAINER_RUNNER__KUBERNETES__IMAGE_PULL_SECRETS
      value: {{ printf "[%s]" (join ", " $names) | quote }}
    {{- end }}
    {{- with $v.extraEnv }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  securityContext:
    {{- toYaml $v.securityContext | nindent 4 }}
  {{- with $v.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}

{{/* The Role (and namespace and NetworkPolicy) build Jobs need. Context: dict root, name, namespace, serviceAccount, values, registrySelector. */}}
{{- define "runner.rbac" -}}
{{- $b := .values.builds -}}
{{- if $b.createNamespace }}
apiVersion: v1
kind: Namespace
metadata:
  name: {{ .namespace }}
  labels:
    # Rootless BuildKit needs the unconfined seccomp and AppArmor profiles.
    pod-security.kubernetes.io/enforce: privileged
---
{{- end }}
# The runner creates a Job per build, and deletes it when done. Each build's token is in a
# Secret owned by its Job.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .name }}
  namespace: {{ .namespace }}
rules:
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "delete"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create", "delete"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["create", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ .name }}
  namespace: {{ .namespace }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ .name }}
subjects:
  - kind: ServiceAccount
    name: {{ .serviceAccount }}
    namespace: {{ .root.Release.Namespace }}
{{- if $b.networkPolicy }}
---
# Build pods may reach the registry and the internet (Git hosts, base images), nothing else in
# the cluster.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ .name }}
  namespace: {{ .namespace }}
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: kontainer-build
  policyTypes: ["Egress"]
  egress:
    {{- with .registrySelector }}
    - to:
        {{- toYaml . | nindent 8 }}
    {{- end }}
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    - ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
{{- end }}
{{- end }}
