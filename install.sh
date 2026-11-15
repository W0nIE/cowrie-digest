#!/usr/bin/env bash
# cowrie-digest installer — deploys the module to /opt/cowrie/ops/01-digest
# Idempotent: safe to run multiple times (re-deploys code, keeps config).
set -euo pipefail

MODULE_DIR="/opt/cowrie/ops/01-digest"
CRON_FILE="/etc/cron.d/cowrie-digest"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> cowrie-digest installer"

# --- preflight checks -------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root (or via sudo)" >&2
    exit 1
fi
if ! command -v python3 >/dev/null; then
    echo "ERROR: python3 not found — install it first (apt install python3)" >&2
    exit 1
fi
if [[ ! -f /opt/cowrie/var/log/cowrie/cowrie.json ]]; then
    echo "WARNING: /opt/cowrie/var/log/cowrie/cowrie.json not found."
    echo "         Is Cowrie deployed at /opt/cowrie? Continuing anyway."
fi

# --- deploy files -----------------------------------------------------------
echo "==> installing files to ${MODULE_DIR}"
mkdir -p "${MODULE_DIR}/state" "${MODULE_DIR}/log"
install -m 0755 "${SRC_DIR}/digest.py" "${MODULE_DIR}/digest.py"

if [[ ! -f "${MODULE_DIR}/config.env" ]]; then
    install -m 0600 "${SRC_DIR}/config.env.example" "${MODULE_DIR}/config.env"
    echo "==> created ${MODULE_DIR}/config.env from example — EDIT IT before alerts will work"
else
    echo "==> keeping existing config.env"
fi

# --- cron -------------------------------------------------------------------
echo "==> installing cron to ${CRON_FILE}"
cat > "${CRON_FILE}" <<'EOF'
# cowrie-digest: daily 24h report at 09:00 + instant alerts every 5 min
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

0 9 * * *   root  /opt/cowrie/ops/01-digest/digest.py --digest >> /opt/cowrie/ops/01-digest/log/digest.log 2>&1
*/5 * * * * root  /opt/cowrie/ops/01-digest/digest.py --alerts >> /opt/cowrie/ops/01-digest/log/alerts.log 2>&1
EOF
chmod 0644 "${CRON_FILE}"

echo ""
echo "==> DONE. Next steps:"
echo "    1. Edit ${MODULE_DIR}/config.env  (choose channel, set topic/token)"
echo "    2. Test:  ${MODULE_DIR}/digest.py --print"
echo "    3. Send a test report: ${MODULE_DIR}/digest.py --digest"
