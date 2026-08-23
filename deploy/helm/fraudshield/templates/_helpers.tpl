{{- define "fraudshield.name" -}}
fraudshield
{{- end }}

{{- define "fraudshield.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "fraudshield.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "fraudshield.labels" -}}
app.kubernetes.io/name: {{ include "fraudshield.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end }}

{{- define "fraudshield.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fraudshield.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "fraudshield.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "fraudshield.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end }}

{{- define "fraudshield.image" -}}
{{- if .Values.image.digest -}}
{{ printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else -}}
{{ printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end -}}
{{- end }}

{{- define "fraudshield.frontendImage" -}}
{{- if .Values.frontend.image.digest -}}
{{ printf "%s@%s" .Values.frontend.image.repository .Values.frontend.image.digest }}
{{- else -}}
{{ printf "%s:%s" .Values.frontend.image.repository (default .Chart.AppVersion .Values.frontend.image.tag) }}
{{- end -}}
{{- end }}
