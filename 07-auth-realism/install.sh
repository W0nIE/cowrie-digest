#!/usr/bin/env bash
# Module 07 installer — realistic Cowrie auth (Weak-Enterprise userdb)
# Idempotent: backups are timestamped; re-runs are safe.
set -euo pipefail

MODULE_DIR="/opt/cowrie/ops/07-auth-realism"
COWRIE_ETC="/opt/cowrie/etc"
COWRIE_CFG="${COWRIE_ETC}/cowrie.cfg"
USERDB="${COWRIE_ETC}/userdb.txt"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> module 07: realistic Cowrie auth"

# --- preflight ---------------------------------------------------------------
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root" >&2; exit 1; }
[[ -f "${USERDB}" ]] || { echo "ERROR: ${USERDB} not found" >&2; exit 1; }
podman ps --format '{{.Names}}' | grep -qx cowrie || { echo "ERROR: cowrie container not running" >&2; exit 1; }
if [[ ! -f "${SRC_DIR}/userdb.txt" ]]; then
    echo "ERROR: ${SRC_DIR}/userdb.txt missing." >&2
    echo "       cp userdb.txt.example userdb.txt and CUSTOMIZE the passwords first." >&2
    exit 1
fi
command -v sshpass >/dev/null || { echo "==> installing sshpass (needed for E2E tests)"; apt-get install -y -qq sshpass >/dev/null; }

# --- backup ------------------------------------------------------------------
mkdir -p "${MODULE_DIR}/backups" "${MODULE_DIR}/log"
TS="$(date +%Y%m%d-%H%M%S)"
cp -a "${USERDB}" "${MODULE_DIR}/backups/userdb.txt.${TS}"
echo "==> backup: ${MODULE_DIR}/backups/userdb.txt.${TS}"

# --- deploy module files -----------------------------------------------------
deploy_file() {  # src dst mode — skip when src and dst are the same file
    local src="$1" dst="$2" mode="$3"
    if [[ "${src}" -ef "${dst}" ]]; then
        chmod "${mode}" "${dst}"
    else
        install -m "${mode}" "${src}" "${dst}"
    fi
}
deploy_file "${SRC_DIR}/test.sh" "${MODULE_DIR}/test.sh" 0755
deploy_file "${SRC_DIR}/uninstall.sh" "${MODULE_DIR}/uninstall.sh" 0755
deploy_file "${SRC_DIR}/add_admin_user.py" "${MODULE_DIR}/add_admin_user.py" 0755
install -m 0640 -o root -g 999 "${SRC_DIR}/userdb.txt" "${USERDB}"
echo "==> deployed userdb.txt (root:999 0640)"

# --- explicit auth_class -----------------------------------------------------
if grep -qE '^\s*auth_class' "${COWRIE_CFG}"; then
    sed -i 's/^\s*auth_class.*/auth_class = UserDB/' "${COWRIE_CFG}"
else
    sed -i '/^\[honeypot\]/a auth_class = UserDB' "${COWRIE_CFG}"
fi
echo "==> cowrie.cfg: auth_class = UserDB (explicit)"

# --- persona consistency: admin user in fs.pickle ----------------------------
python3 "${MODULE_DIR}/add_admin_user.py"

# --- restart -----------------------------------------------------------------
systemctl restart cowrie.service
for i in $(seq 1 15); do
    if podman logs cowrie 2>&1 | tail -20 | grep -q "Ready to accept SSH connections"; then
        echo "==> cowrie restarted and accepting connections"
        break
    fi
    sleep 1
done

echo ""
echo "==> DONE. Verify with: ${MODULE_DIR}/test.sh"
