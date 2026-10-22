{{- define "kontainer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kontainer.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "kontainer.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "kontainer.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "kontainer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kontainer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kontainer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kontainer.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "kontainer.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/* The URL the registry is reached at. */}}
{{- define "kontainer.publicUrl" -}}
{{- if .Values.publicUrl }}
{{- .Values.publicUrl | trimSuffix "/" }}
{{- else if .Values.ingress.enabled }}
{{- printf "%s://%s" (ternary "https" "http" .Values.ingress.tls.enabled) .Values.ingress.host }}
{{- end }}
{{- end }}

{{/* In-cluster URL, for build pods. */}}
{{- define "kontainer.internalUrl" -}}
{{- printf "http://%s.%s.svc:%v" (include "kontainer.fullname" .) .Release.Namespace .Values.service.port }}
{{- end }}

{{- define "kontainer.adminSecret" -}}
{{- default (printf "%s-admin" (include "kontainer.fullname" .)) .Values.admin.existingSecret }}
{{- end }}

{{- define "kontainer.metricsSecret" -}}
{{- default (printf "%s-metrics" (include "kontainer.fullname" .)) .Values.metrics.existingSecret }}
{{- end }}

{{- define "kontainer.buildsNamespace" -}}
{{- default .Release.Namespace .Values.runner.builds.namespace }}
{{- end }}

{{/* A value kept from the existing Secret, else `fallback`: generated passwords survive upgrades. */}}
{{- define "kontainer.keep" -}}
{{- $secret := lookup "v1" "Secret" .namespace .name }}
{{- if and $secret (index $secret.data .key) }}
{{- index $secret.data .key | b64dec }}
{{- else }}
{{- .fallback }}
{{- end }}
{{- end }}

{{/* `KONTAINER__...` settings derived from the values. */}}
{{- define "kontainer.env" -}}
{{- $v := .Values -}}
- name: KONTAINER_CONFIG
  value: /etc/kontainer/config.toml
- name: KONTAINER__SERVER__BIND
  value: "0.0.0.0:5000"
{{- if ne $v.storage.driver "locations" }}
- name: KONTAINER_STORAGE_ROOT
  value: /var/lib/registry
{{- end }}
- name: KONTAINER_UPLOAD_DIR
  value: /var/lib/registry/_uploads
- name: KONTAINER_DATABASE_URL
  valueFrom: { secretKeyRef: { name: {{ include "kontainer.databaseSecret" . }}, key: url } }
- name: KONTAINER__AUTH__DATABASE_POOL
  value: {{ .Values.database.pool | quote }}
{{- with include "kontainer.publicUrl" . }}
- name: KONTAINER_PUBLIC_URL
  value: {{ . | quote }}
{{- end }}
- name: KONTAINER_ADMIN_USERNAME
  valueFrom: { secretKeyRef: { name: {{ include "kontainer.adminSecret" . }}, key: username } }
- name: KONTAINER_ADMIN_PASSWORD
  valueFrom: { secretKeyRef: { name: {{ include "kontainer.adminSecret" . }}, key: password } }
- name: KONTAINER_METRICS_TOKEN
  valueFrom: { secretKeyRef: { name: {{ include "kontainer.metricsSecret" . }}, key: token } }
{{- /* storage */}}
- name: KONTAINER_STORAGE_LOCATION
  value: {{ $v.storage.location | quote }}
{{- /* With storage.driver "locations", the buckets come from [[storage.locations]] in `config`. */}}
{{- if ne $v.storage.driver "locations" }}
- name: KONTAINER__STORAGE__DRIVER
  value: {{ $v.storage.driver | quote }}
{{- with $v.storage.prefix }}
- name: KONTAINER__STORAGE__PREFIX
  value: {{ . | quote }}
{{- end }}
{{- if ne $v.storage.driver "filesystem" }}
- name: KONTAINER__STORAGE__REDIRECT
  value: {{ $v.storage.redirect | quote }}
{{- end }}
{{- if eq $v.storage.driver "s3" }}
{{- $s3 := $v.storage.s3 }}
- name: KONTAINER__STORAGE__S3__BUCKET
  value: {{ required "storage.s3.bucket is required" $s3.bucket | quote }}
{{- with $s3.region }}
- name: KONTAINER__STORAGE__S3__REGION
  value: {{ . | quote }}
{{- end }}
{{- with $s3.endpoint }}
- name: KONTAINER__STORAGE__S3__ENDPOINT
  value: {{ . | quote }}
{{- end }}
- name: KONTAINER__STORAGE__S3__VIRTUAL_HOSTED_STYLE
  value: {{ $s3.virtualHostedStyle | quote }}
- name: KONTAINER__STORAGE__S3__ALLOW_HTTP
  value: {{ $s3.allowHttp | quote }}
{{- with $s3.existingSecret }}
- name: AWS_ACCESS_KEY_ID
  valueFrom: { secretKeyRef: { name: {{ . }}, key: {{ $s3.accessKeyIdKey }} } }
- name: AWS_SECRET_ACCESS_KEY
  valueFrom: { secretKeyRef: { name: {{ . }}, key: {{ $s3.secretAccessKeyKey }} } }
{{- end }}
{{- else if eq $v.storage.driver "gcs" }}
- name: KONTAINER__STORAGE__GCS__BUCKET
  value: {{ required "storage.gcs.bucket is required" $v.storage.gcs.bucket | quote }}
{{- if $v.storage.gcs.existingSecret }}
- name: KONTAINER__STORAGE__GCS__SERVICE_ACCOUNT_PATH
  value: /var/run/secrets/kontainer/gcs/{{ $v.storage.gcs.key }}
{{- end }}
{{- else if eq $v.storage.driver "azure" }}
{{- $az := $v.storage.azure }}
- name: KONTAINER__STORAGE__AZURE__CONTAINER
  value: {{ required "storage.azure.container is required" $az.container | quote }}
{{- with $az.account }}
- name: KONTAINER__STORAGE__AZURE__ACCOUNT
  value: {{ . | quote }}
{{- end }}
{{- with $az.existingSecret }}
- name: AZURE_STORAGE_ACCOUNT_KEY
  valueFrom: { secretKeyRef: { name: {{ . }}, key: {{ $az.accessKeyKey }} } }
{{- end }}
{{- end }}
{{- end }}
{{- /* scanner */}}
{{- if ne $v.scanner.kind "none" }}
- name: KONTAINER__SCANNER__KIND
  value: {{ $v.scanner.kind | quote }}
- name: KONTAINER__SCANNER__SCAN_ON_PUSH
  value: {{ $v.scanner.scanOnPush | quote }}
- name: KONTAINER__SCANNER__REGISTRY_HOST
  value: "127.0.0.1:5000"
- name: KONTAINER__SCANNER__INSECURE
  value: "true"
- name: KONTAINER__SCANNER__ENV__TRIVY_CACHE_DIR
  value: /var/lib/registry/_cache/trivy
- name: KONTAINER__SCANNER__ENV__GRYPE_DB_CACHE_DIR
  value: /var/lib/registry/_cache/grype
{{- with $v.scanner.blockPullAt }}
- name: KONTAINER__SCANNER__BLOCK_PULL_AT
  value: {{ . | quote }}
{{- end }}
# The scanner pulls images as the administrator.
- name: KONTAINER__SCANNER__USERNAME
  valueFrom: { secretKeyRef: { name: {{ include "kontainer.adminSecret" . }}, key: username } }
- name: KONTAINER_SCANNER_PASSWORD
  valueFrom: { secretKeyRef: { name: {{ include "kontainer.adminSecret" . }}, key: password } }
{{- end }}
{{- /* builds */}}
- name: KONTAINER__BUILDS__ENABLED
  value: {{ $v.builds.enabled | quote }}
- name: KONTAINER__BUILDS__SELF_HOSTED_RUNNERS
  value: {{ $v.builds.selfHostedRunners | quote }}
- name: KONTAINER__BUILDS__MAX_PER_NAMESPACE
  value: {{ $v.builds.maxPerNamespace | quote }}
- name: KONTAINER__BUILDS__TIMEOUT
  value: {{ $v.builds.timeout | quote }}
{{- if $v.runner.enabled }}
# Registers the shared runner below as `default`, serving every namespace.
- name: KONTAINER_RUNNER_TOKEN
  valueFrom: { secretKeyRef: { name: {{ include "kontainer.fullname" . }}-runner, key: token } }
{{- end }}
{{- end }}

{{/* The Secret holding the PostgreSQL URL: the user's, or one made from `database.url`. */}}
{{- define "kontainer.databaseSecret" -}}
{{- if .Values.database.existingSecret -}}
{{ .Values.database.existingSecret }}
{{- else -}}
{{ required "set database.url (postgres://user:password@host:5432/dbname) or database.existingSecret" .Values.database.url | trunc 0 }}{{ include "kontainer.fullname" . }}-database
{{- end -}}
{{- end }}

{{/* The data volume is a PersistentVolumeClaim only for a single pod; several pods each get an emptyDir. */}}
{{- define "kontainer.usesPvc" -}}
{{- if and .Values.persistence.enabled (le (int .Values.replicaCount) 1) }}true{{- end -}}
{{- end }}
