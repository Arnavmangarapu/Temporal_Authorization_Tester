FROM prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996
COPY --chmod=0644 monitoring/prometheus.yml /etc/prometheus/prometheus.yml
