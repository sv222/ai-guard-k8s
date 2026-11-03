{{- define "vllm.labels" -}}
app: {{ .Release.Name }}-vllm
{{- end }}
