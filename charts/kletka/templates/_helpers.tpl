{{- define "kletka.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- default .Chart.Name .Values.nameOverride | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "kletka.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kletka.labels" -}}
helm.sh/chart: {{ include "kletka.chart" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: kletka
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "kletka.image" -}}
{{- $tag := .image.tag | default .root.Chart.AppVersion -}}
{{- $ref := printf "%s:%s" .image.repository $tag -}}
{{- if .image.digest -}}
{{- $ref = printf "%s@%s" $ref .image.digest -}}
{{- end -}}
{{- $ref -}}
{{- end -}}

{{- define "kletka.imagePullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{- define "kletka.keepAnnotations" -}}
{{- if .Values.keepPersistentResources }}
helm.sh/resource-policy: keep
argocd.argoproj.io/sync-options: Prune=false,Delete=false
{{- end }}
{{- end -}}

{{- define "kletka.apiName" -}}{{ include "kletka.fullname" . }}-api{{- end -}}
{{- define "kletka.apiSecretName" -}}
{{- .Values.api.secret.existingSecret | default (printf "%s-secret" (include "kletka.apiName" .)) -}}
{{- end -}}
{{- define "kletka.vmServiceAccount" -}}{{ include "kletka.fullname" . }}-vm{{- end -}}
{{- define "kletka.registryName" -}}{{ include "kletka.fullname" . }}-registry{{- end -}}
{{- define "kletka.builderName" -}}{{ include "kletka.fullname" . }}-image-builder{{- end -}}
{{- define "kletka.devicePluginName" -}}{{ include "kletka.fullname" . }}-device-plugin{{- end -}}
{{- define "kletka.guestImagesConfigMap" -}}{{ include "kletka.fullname" . }}-guest-images{{- end -}}

{{- define "kletka.vmNodeSelector" -}}
{{- $pairs := list -}}
{{- range $k, $v := .Values.vms.nodeSelector -}}
{{- $pairs = append $pairs (printf "%s=%s" $k $v) -}}
{{- end -}}
{{- join "," $pairs -}}
{{- end -}}

{{- define "kletka.pairs" -}}
{{- $pairs := list -}}
{{- range $k, $v := . -}}
{{- $pairs = append $pairs (printf "%s=%v" $k $v) -}}
{{- end -}}
{{- join "," $pairs -}}
{{- end -}}

{{- define "kletka.registryServiceHost" -}}
{{- printf "%s.%s.svc.cluster.local:%v" (include "kletka.registryName" .) .Release.Namespace .Values.registry.port -}}
{{- end -}}

{{- define "kletka.builderPushRegistry" -}}
{{- if .Values.imageBuilder.registry.push -}}
{{- .Values.imageBuilder.registry.push -}}
{{- else if .Values.registry.enabled -}}
{{- include "kletka.registryServiceHost" . -}}
{{- else -}}
{{- fail "imageBuilder.registry.push is required when registry.enabled=false" -}}
{{- end -}}
{{- end -}}

{{- define "kletka.builderPullRegistry" -}}
{{- if .Values.imageBuilder.registry.pull -}}
{{- .Values.imageBuilder.registry.pull -}}
{{- else if .Values.imageBuilder.registry.push -}}
{{- .Values.imageBuilder.registry.push -}}
{{- else if .Values.registry.nodeProxy.enabled -}}
{{- printf "localhost:%v" .Values.registry.nodeProxy.port -}}
{{- else -}}
{{- fail "imageBuilder.registry.pull is required when the registry node proxy is disabled (nodes cannot resolve cluster DNS)" -}}
{{- end -}}
{{- end -}}

{{- define "kletka.builderRetention" -}}
{{- if and .Values.registry.enabled (not .Values.imageBuilder.registry.push) -}}
{{- .Values.registry.retention.keepVersions -}}
{{- else -}}
0
{{- end -}}
{{- end -}}

{{- define "kletka.registryConfig" -}}
version: 0.1
log:
  level: info
storage:
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: true
http:
  addr: ":{{ .Values.registry.port }}"
{{- end -}}

{{- define "kletka.builderTlsVerify" -}}
{{- if .Values.imageBuilder.registry.push -}}
{{- .Values.imageBuilder.registry.tlsVerify -}}
{{- else -}}
false
{{- end -}}
{{- end -}}

{{- define "kletka.guestImageDefinitions" -}}
{{- $defs := list -}}
{{- range $name, $def := .Values.guestImages -}}
{{- if and (kindIs "map" $def) (ne (toString (dig "enabled" true $def)) "false") -}}
{{- if not (regexMatch "^[a-z0-9][a-z0-9._-]*$" $name) -}}
{{- fail (printf "guestImages.%s: names must be lowercase letters, digits, '.', '-', '_'" $name) -}}
{{- end -}}
{{- $entry := dict "name" $name -}}
{{- with $def.size }}{{ $_ := set $entry "size" (toString .) }}{{ end -}}
{{- if hasKey $def "update" }}{{ $_ := set $entry "update" $def.update }}{{ end -}}
{{- with $def.dockerfile }}{{ $_ := set $entry "dockerfile" . }}{{ end -}}
{{- with $def.files }}{{ $_ := set $entry "files" . }}{{ end -}}
{{- $defs = append $defs $entry -}}
{{- end -}}
{{- end -}}
{{- if and .Values.imageBuilder.enabled (not $defs) -}}
{{- fail "guestImages: at least one image must be enabled while imageBuilder.enabled=true" -}}
{{- end -}}
{{- toPrettyJson $defs -}}
{{- end -}}

{{- define "kletka.nodeProxyConf" -}}
worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 1024; }
stream {
  server {
    listen 127.0.0.1:{{ .Values.registry.nodeProxy.port }};
    proxy_pass {{ include "kletka.registryServiceHost" . }};
    proxy_connect_timeout 10s;
    proxy_timeout 10m;
  }
}
{{- end -}}

{{- define "kletka.checkGcWindow" -}}
{{- if and .Values.registry.enabled .Values.registry.garbageCollect.enabled .Values.imageBuilder.enabled -}}
{{- $fields := splitList " " (.Values.imageBuilder.schedule | trim) -}}
{{- if and (ge (len $fields) 2) (regexMatch "^[0-9]+$" (index $fields 0)) (regexMatch "^[0-9]+$" (index $fields 1)) -}}
{{- $start := add (mul (atoi (index $fields 1)) 60) (atoi (index $fields 0)) -}}
{{- $end := add $start (div (add .Values.imageBuilder.activeDeadlineSeconds 59) 60) -}}
{{- $gc := mul (int .Values.registry.garbageCollect.hourUTC) 60 -}}
{{- range $day := list 0 1440 -}}
{{- $from := add $gc $day -}}
{{- $to := add $from 59 -}}
{{- if and (le $from $end) (ge $to $start) -}}
{{- fail (printf "registry.garbageCollect.hourUTC=%v overlaps the image builder window (%s + %vs); pick another hour" $.Values.registry.garbageCollect.hourUTC $.Values.imageBuilder.schedule $.Values.imageBuilder.activeDeadlineSeconds) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
