FROM grafana/grafana:12.1.1@sha256:a1701c2180249361737a99a01bc770db39381640e4d631825d38ff4535efa47d
COPY --chown=472:0 --chmod=0755 monitoring/grafana/provisioning/ /etc/grafana/provisioning/
COPY --chown=472:0 --chmod=0755 monitoring/grafana/dashboards/ /etc/grafana/dashboards/
