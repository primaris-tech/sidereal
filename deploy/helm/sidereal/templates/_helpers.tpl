{{/*
Chart name.
*/}}
{{- define "sidereal.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name.
*/}}
{{- define "sidereal.fullname" -}}
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

{{/*
Common labels.
*/}}
{{- define "sidereal.labels" -}}
app.kubernetes.io/name: {{ include "sidereal.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "sidereal.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sidereal.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Controller image with tag defaulting to appVersion.
*/}}
{{- define "sidereal.controllerImage" -}}
{{ .Values.controller.image.repository }}:{{ .Values.controller.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Go probe image with tag defaulting to appVersion.
*/}}
{{- define "sidereal.goProbeImage" -}}
{{ .Values.probe.goImage.repository }}:{{ .Values.probe.goImage.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Detection probe image with tag defaulting to appVersion.
*/}}
{{- define "sidereal.detectionProbeImage" -}}
{{ .Values.probe.detectionImage.repository }}:{{ .Values.probe.detectionImage.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Bootstrap probe image with tag defaulting to appVersion.
*/}}
{{- define "sidereal.bootstrapImage" -}}
{{ .Values.probe.bootstrapImage.repository }}:{{ .Values.probe.bootstrapImage.tag | default .Chart.AppVersion }}
{{- end }}
