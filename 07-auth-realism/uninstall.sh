#!/usr/bin/env bash
# Module 07 uninstaller — restores the pre-module userdb and pickle.
set -euo pipefail

MODULE_DIR="/opt/cowrie/ops/07-auth-realism"
COWRIE_ETC="/opt/cowrie/etc"
USERDB="${COWRIE_ETC}/userdb.txt"

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root" >&2; exit 1; }

LATEST="$(ls -1t "${MODULE_DIR}"/backups/userdb.txt.* 2>/dev/null | head -1 || true)"
if [[ -z "${LATEST}" ]]; then
    echo "ERROR: no backup found in ${MODULE_DIR}/backups" >&2
    exit 1
fi
install -m 0640 -o root -g 999 "${LATEST}" "${USERDB}"
echo "==> restored userdb from ${LATEST}"

# Revert pickle to pre-admin state if that backup exists
if [[ -f /opt/cowrie/data/fs.pickle.pre07 ]]; then
    cp -a /opt/cowrie/data/fs.pickle.pre07 /opt/cowrie/data/fs.pickle
    chown 999:999 /opt/cowrie/data/fs.pickle
    echo "==> restored fs.pickle from fs.pickle.pre07 (admin persona removed)"
fi

systemctl restart cowrie.service
echo "==> cowrie restarted with previous auth config"
