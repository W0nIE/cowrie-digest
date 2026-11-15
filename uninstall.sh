#!/usr/bin/env bash
# cowrie-digest uninstaller — removes the module cleanly.
set -euo pipefail

MODULE_DIR="/opt/cowrie/ops/01-digest"
CRON_FILE="/etc/cron.d/cowrie-digest"

# Defense in depth: never rm -rf an unexpected path.
if [[ "${MODULE_DIR}" != "/opt/cowrie/ops/01-digest" ]]; then
    echo "ERROR: unsafe module dir '${MODULE_DIR}', aborting" >&2
    exit 1
fi

echo "==> removing cron ${CRON_FILE}"
rm -f "${CRON_FILE}"

if [[ -d "${MODULE_DIR}" ]]; then
    echo "==> removing ${MODULE_DIR} (including config.env and state)"
    rm -rf "${MODULE_DIR}"
fi

echo "==> cowrie-digest removed. No other modules or Cowrie itself were touched."
