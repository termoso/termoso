{{- define "termoso.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "termoso.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "termoso.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "termoso.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/name: {{ include "termoso.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "termoso.selectorLabels" -}}
app.kubernetes.io/name: {{ include "termoso.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "termoso.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "termoso.secretName" -}}
{{- default (printf "%s-env" (include "termoso.fullname" .)) .Values.existingSecret -}}
{{- end -}}

{{- define "termoso.databaseUrl" -}}
{{- if .Values.bundled.postgres.enabled -}}
{{- printf "postgres://termoso:%s@%s-postgres:5432/termoso" .Values.bundled.postgres.password (include "termoso.fullname" .) -}}
{{- else -}}
{{- .Values.database.url -}}
{{- end -}}
{{- end -}}

{{- define "termoso.redisUrl" -}}
{{- if .Values.bundled.redis.enabled -}}
{{- printf "redis://%s-redis:6379" (include "termoso.fullname" .) -}}
{{- else -}}
{{- .Values.redis.url -}}
{{- end -}}
{{- end -}}
