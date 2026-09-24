#!/bin/bash
# -----------------------------------------------------------------------
# MAAS Grafana Setup
# Install Grafana, provision the MAAS dashboard, and start metrics cron.
# Run on the monitoring host (Debian/Ubuntu).
# -----------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRAFANA_DASHBOARDS_DIR="/var/lib/grafana/dashboards/maas"
GRAFANA_PROVISIONING="/etc/grafana/provisioning"
METRICS_DATA_DIR="/var/lib/grafana/data/maas"
METRICS_SCRIPT="/opt/maas/metrics-collector.py"
JENKINS_URL="${JENKINS_URL:-http://10.5.99.3:8080}"

echo "[*] MAAS Grafana Setup"
echo "    Jenkins URL: ${JENKINS_URL}"

# -----------------------------------------------------------------------
# 1. Install Grafana (if not already installed)
# -----------------------------------------------------------------------
if ! command -v grafana-server &>/dev/null; then
    echo "[*] Installing Grafana OSS..."
    apt-get install -y apt-transport-https software-properties-common wget
    mkdir -p /etc/apt/keyrings/
    wget -q -O - https://apt.grafana.com/gpg.key \
        | gpg --dearmor > /etc/apt/keyrings/grafana.gpg
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
        > /etc/apt/sources.list.d/grafana.list
    apt-get update
    apt-get install -y grafana
    echo "[+] Grafana installed"
else
    echo "[+] Grafana already installed"
fi

# -----------------------------------------------------------------------
# 2. Install required Grafana plugins
# -----------------------------------------------------------------------
echo "[*] Installing Grafana plugins..."
grafana-cli plugins install marcusolsson-json-datasource 2>/dev/null || true
grafana-cli plugins install yesoreyeram-infinity-datasource 2>/dev/null || true
echo "[+] Plugins installed"

# -----------------------------------------------------------------------
# 3. Deploy provisioning configs
# -----------------------------------------------------------------------
echo "[*] Deploying provisioning configurations..."

mkdir -p "${GRAFANA_PROVISIONING}/datasources"
mkdir -p "${GRAFANA_PROVISIONING}/dashboards"
mkdir -p "${GRAFANA_DASHBOARDS_DIR}"
mkdir -p "${METRICS_DATA_DIR}"

cp "${SCRIPT_DIR}/provisioning/datasources/maas.yml" \
    "${GRAFANA_PROVISIONING}/datasources/maas.yml"
cp "${SCRIPT_DIR}/provisioning/dashboards/maas.yml" \
    "${GRAFANA_PROVISIONING}/dashboards/maas.yml"

echo "[+] Provisioning configs deployed"

# -----------------------------------------------------------------------
# 4. Deploy dashboard JSON
# -----------------------------------------------------------------------
echo "[*] Deploying dashboard..."
cp "${SCRIPT_DIR}/dashboard.json" "${GRAFANA_DASHBOARDS_DIR}/dashboard.json"
echo "[+] Dashboard deployed"

# -----------------------------------------------------------------------
# 5. Deploy metrics collector
# -----------------------------------------------------------------------
echo "[*] Deploying metrics collector..."
mkdir -p /opt/maas
cp "${SCRIPT_DIR}/metrics-collector.py" "${METRICS_SCRIPT}"
chmod +x "${METRICS_SCRIPT}"

# Install Python dependencies
pip3 install --quiet requests 2>/dev/null || true

echo "[+] Metrics collector deployed"

# -----------------------------------------------------------------------
# 6. Initial metrics collection
# -----------------------------------------------------------------------
echo "[*] Running initial metrics collection..."
python3 "${METRICS_SCRIPT}" \
    --jenkins-url "${JENKINS_URL}" \
    --output-dir "${METRICS_DATA_DIR}" || {
    echo "[!] Initial collection failed (Jenkins may not be reachable yet)"
    # Write empty metrics so Grafana does not error
    echo '{"collected_at":"","jenkins":{"builds":[],"summary":{"total":0,"success":0,"failure":0,"unstable":0,"aborted":0},"builds_per_day":{},"duration_by_profile":{},"queue_depth":0},"litterbox":{"scans":[],"detection_rate_over_time":[],"engine_payload_matrix":{},"profile_detection_rates":{},"detection_by_obfuscation":{}},"shelf_life":{"entries":[],"avg_by_profile":{},"trend":[],"first_detection_engines":{}},"infrastructure":{"runners":[],"cache_usage":{},"disk_usage":{}}}' \
        > "${METRICS_DATA_DIR}/metrics.json"
}

# -----------------------------------------------------------------------
# 7. Set up cron job (every 5 minutes)
# -----------------------------------------------------------------------
echo "[*] Setting up cron job..."
CRON_ENTRY="*/5 * * * * python3 ${METRICS_SCRIPT} --jenkins-url ${JENKINS_URL} --output-dir ${METRICS_DATA_DIR} 2>&1 | logger -t maas-metrics"

# Add to root crontab if not already present
(crontab -l 2>/dev/null | grep -v "maas-metrics" ; echo "${CRON_ENTRY}") \
    | crontab -
echo "[+] Cron job installed (every 5 minutes)"

# -----------------------------------------------------------------------
# 8. Fix permissions and restart Grafana
# -----------------------------------------------------------------------
echo "[*] Fixing permissions..."
chown -R grafana:grafana "${GRAFANA_DASHBOARDS_DIR}"
chown -R grafana:grafana "${METRICS_DATA_DIR}"
chown -R grafana:grafana "${GRAFANA_PROVISIONING}/datasources/maas.yml"
chown -R grafana:grafana "${GRAFANA_PROVISIONING}/dashboards/maas.yml"

echo "[*] Restarting Grafana..."
systemctl daemon-reload
systemctl enable grafana-server
systemctl restart grafana-server

echo ""
echo "============================================"
echo " MAAS Grafana Setup Complete"
echo "============================================"
echo ""
echo "  Dashboard:  http://$(hostname -I | awk '{print $1}'):3000"
echo "  Default login: admin / admin"
echo ""
echo "  Metrics cron: every 5 minutes"
echo "  Metrics file: ${METRICS_DATA_DIR}/metrics.json"
echo "  Dashboard UID: maas-overview"
echo ""
echo "  Jenkins:    ${JENKINS_URL}"
echo ""
