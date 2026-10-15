{{- define "bulwark.fullname" -}}
bulwark
{{- end -}}

{{- define "bulwark.labels" -}}
app.kubernetes.io/part-of: bulwark
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "bulwark.selectorLabels" -}}
app.kubernetes.io/part-of: bulwark
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
The non-sensitive half of the shared app env (docker-compose.yml's x-app-env anchor). Sensitive
values live in templates/secret.yaml instead and are referenced via secretKeyRef, not inlined here.
*/}}
{{- define "bulwark.workdirClaimName" -}}
{{- if .Values.workdir.existingClaim -}}
{{ .Values.workdir.existingClaim }}
{{- else -}}
{{ include "bulwark.fullname" . }}-workdir
{{- end -}}
{{- end -}}

{{/*
Kubernetes Deployments have no native equivalent of docker-compose.yml's own
`depends_on: condition: service_healthy` -- without this, api/worker/beat start racing their own
Redis/object-store/OpenBao calls before those pods are actually ready to accept connections (found
live: the API crash-looped on a real EndpointConnectionError to the object store on first install).
This waits on plain TCP connectivity, the same minimal check migrate-job.yaml's own
wait-for-postgres initContainer uses.
*/}}
{{- define "bulwark.waitForDepsInitContainers" -}}
- name: wait-for-redis
  image: busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
  command: ['sh', '-c', 'until nc -z {{ include "bulwark.fullname" . }}-redis 6379; do echo waiting for redis; sleep 2; done']
- name: wait-for-objectstore
  image: busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
  command: ['sh', '-c', 'until nc -z {{ include "bulwark.fullname" . }}-objectstore 9000; do echo waiting for objectstore; sleep 2; done']
- name: wait-for-openbao
  image: busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
  command: ['sh', '-c', 'until nc -z {{ include "bulwark.fullname" . }}-openbao 8200; do echo waiting for openbao; sleep 2; done']
{{- end -}}

{{- define "bulwark.sharedEnv" -}}
- name: BULWARK_REDIS_URL
  value: "redis://{{ include "bulwark.fullname" . }}-redis:6379/0"
- name: BULWARK_S3_ENDPOINT
  value: "http://{{ include "bulwark.fullname" . }}-objectstore:9000"
- name: BULWARK_OPENBAO_ADDR
  value: "http://{{ include "bulwark.fullname" . }}-openbao:8200"
- name: BULWARK_LOG_FORMAT
  value: "json"
- name: BULWARK_WORKDIR
  value: "/workdir"
{{- /* Email for notifications (Week 66, plan §49): no host, no email. */}}
- name: BULWARK_SMTP_HOST
  value: {{ .Values.smtp.host | default "" | quote }}
- name: BULWARK_SMTP_PORT
  value: {{ .Values.smtp.port | default 587 | quote }}
- name: BULWARK_SMTP_FROM
  value: {{ .Values.smtp.from | default "bulwark@localhost" | quote }}
- name: BULWARK_SMTP_USERNAME
  value: {{ .Values.smtp.username | default "" | quote }}
- name: BULWARK_SMTP_PASSWORD
  valueFrom:
    secretKeyRef: { name: {{ include "bulwark.fullname" . }}-secrets, key: smtp-password }
- name: BULWARK_SMTP_TLS
  value: {{ .Values.smtp.tls | default "starttls" | quote }}
- name: BULWARK_PUBLIC_URL
  value: {{ .Values.smtp.publicUrl | default "" | quote }}
- name: BULWARK_API_PUBLIC_URL
  value: {{ .Values.smtp.apiPublicUrl | default "" | quote }}
{{- end -}}
